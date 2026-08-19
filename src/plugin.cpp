#include "bsi_plugin.h"
#include "disasm.h"
#include "format.h"
#include "imgui.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <vector>
#include <string>
#include <algorithm>
#include <ctype.h>
#include <mutex>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <math.h>

static const char kId[] = "com.bsi.lydis";
static const char kName[] = "Lydis";
static const char kVersion[] = "0.1.0";
static const char kModule[] = "lydis";
static const char kCfgMaxInsn[] = "max_insn";
static const char kCfgShowBytes[] = "show_bytes";
static const char kCfgShowAddr[] = "show_addr";
static const char kCfgShowXrefs[] = "show_xrefs";
static const char kCfgShowStr[] = "show_strings";

enum
{
    kOriginEntry = 0,
    kOriginHex = 1,
    kToolEntry = 0,
    kToolHex = 1
};

enum
{
    kLyXrefCall = 1,
    kLyXrefJmp = 2,
    kLyXrefCondJmp = 3
};

enum
{
    kLyIrOther = 0,
    kLyIrAssign = 1,
    kLyIrCall = 2,
    kLyIrJump = 3,
    kLyIrCondJump = 4,
    kLyIrRet = 5
};

struct LyXref
{
    uint64_t from_va;
    uint64_t to_va;
    uint32_t kind;
};

struct LyBlock
{
    int start_insn;
    int end_insn;
    std::vector<int> succ;
};

struct LyIrInst
{
    uint64_t va;
    uint32_t kind;
    uint64_t target_va;
    char op[16];
    char dst[64];
    char src[96];
};

enum
{
    kLyTypeUnknown = 0,
    kLyTypeI8 = 1,
    kLyTypeI16 = 2,
    kLyTypeI32 = 3,
    kLyTypeI64 = 4
};

struct LyStackSlot
{
    int32_t offset;
    uint32_t type_kind;
};

enum
{
    kLyDecTextCap = 192
};

struct LyDecLine
{
    uint32_t insn_idx; // maps back to fn.insns index (and thus listing row)
    char text[kLyDecTextCap];
};

struct LyFunction
{
    uint64_t start_va;
    uint64_t end_va;
    int start_idx;
    int end_idx;
    char name[64];
    int analyzed;
    std::vector<LyLine> insns;
    std::vector<LyBlock> blocks;
    std::vector<LyXref> xrefs;
    std::vector<LyIrInst> ir;
    std::vector<LyStackSlot> stack_slots;
    std::vector<LyDecLine> dec_lines;
};

static const BsiHost* g_host;
static std::vector<LyLine> g_insns;
static std::vector<LyLine> g_lines;
static std::vector<LyFunction> g_funcs;
static char g_status[192];
static char g_search[96];
static int g_origin = kOriginEntry;
static int g_sel = -1;
static int g_func_sel = 0;
static int g_dec_sel = -1;
static int g_dec_sel_end = -1;
static bool g_dirty = true;
static bool g_scroll_listing = false;
static uint32_t g_pushed_hex_off = 0xFFFFFFFFu;
static std::vector<LyRow> g_rows;
static std::mutex g_mu;
static std::thread g_worker;
static std::atomic<int> g_busy{0};
static std::atomic<int> g_cancel{0};
static std::atomic<int> g_stage{0};
static std::atomic<float> g_frac{-1.f};
static char g_stage_text[128];
static std::vector<uint64_t> g_nav;
static int g_nav_i = -1;
static bool g_nav_lock = false;
static char g_goto[40];
static double g_flash_until = 0.0;
static int g_xref_sel = -1;
static uint64_t g_seen_epoch = 0;

static void Logf(int sev, const char* fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (g_host && g_host->log)
        g_host->log(g_host->ctx, sev, kModule, buf);
}

static int ClampInsn(int n)
{
    if (n < kLyInsnMin)
        return kLyInsnMin;
    if (n > kLyInsnMax)
        return kLyInsnMax;
    return n;
}

static int CfgMaxInsn()
{
    if (!g_host || !g_host->setting_get_int)
        return kLyInsnDefault;
    return ClampInsn(g_host->setting_get_int(g_host->ctx, kCfgMaxInsn, kLyInsnDefault));
}

static void CfgSetMaxInsn(int n)
{
    if (g_host && g_host->setting_set_int)
        g_host->setting_set_int(g_host->ctx, kCfgMaxInsn, ClampInsn(n));
}

static int CfgShowBytes()
{
    if (!g_host || !g_host->setting_get_bool)
        return 1;
    return g_host->setting_get_bool(g_host->ctx, kCfgShowBytes, 1);
}

static void CfgSetShowBytes(int on)
{
    if (g_host && g_host->setting_set_bool)
        g_host->setting_set_bool(g_host->ctx, kCfgShowBytes, on ? 1 : 0);
}

static int CfgShowAddr()
{
    if (!g_host || !g_host->setting_get_bool)
        return 1;
    return g_host->setting_get_bool(g_host->ctx, kCfgShowAddr, 1);
}

static int CfgShowXrefs()
{
    if (!g_host || !g_host->setting_get_bool)
        return 1;
    return g_host->setting_get_bool(g_host->ctx, kCfgShowXrefs, 1);
}

static int CfgShowStr()
{
    if (!g_host || !g_host->setting_get_bool)
        return 1;
    return g_host->setting_get_bool(g_host->ctx, kCfgShowStr, 1);
}

static const char* Tr(const char* key, const char* lit)
{
    if (g_host && g_host->i18n_get)
    {
        const char* s = g_host->i18n_get(g_host->ctx, key);
        if (s && s[0] && strcmp(s, key) != 0)
            return s;
    }
    return lit;
}

static void ReportProgress(const char* stage, float frac)
{
    g_stage_text[0] = 0;
    if (stage)
        snprintf(g_stage_text, sizeof(g_stage_text), "%s", stage);
    g_frac.store(frac);
    if (g_host && BSI_HOST_HAS(g_host, progress_set) && g_host->progress_set)
        g_host->progress_set(g_host->ctx, kId, "Disassembly", stage, frac);
}

static int WantCancel()
{
    if (g_cancel.load())
        return 1;
    if (g_host && BSI_HOST_HAS(g_host, progress_want_cancel) && g_host->progress_want_cancel)
        return g_host->progress_want_cancel(g_host->ctx, kId);
    return 0;
}

static void StopWorker()
{
    g_cancel.store(1);
    if (g_worker.joinable() && std::this_thread::get_id() != g_worker.get_id())
        g_worker.join();
    g_busy.store(0);
}

static void ClearListing()
{
    StopWorker();
    std::lock_guard<std::mutex> lock(g_mu);
    g_insns.clear();
    g_lines.clear();
    g_funcs.clear();
    g_rows.clear();
    g_nav.clear();
    g_nav_i = -1;
    g_func_sel = 0;
    g_sel = -1;
    g_dec_sel = -1;
    g_dec_sel_end = -1;
    g_status[0] = 0;
    g_search[0] = 0;
    g_dirty = true;
    g_scroll_listing = false;
    g_pushed_hex_off = 0xFFFFFFFFu;
    g_seen_epoch = 0;
    g_cancel.store(0);
}

static int InsnIndexByVa(const std::vector<LyLine>& insns, uint64_t va)
{
    for (int i = 0; i < (int)insns.size(); i++)
        if (insns[(size_t)i].va == va)
            return i;
    return -1;
}

// Forward declarations: helpers used by multiple view renderers.
static int SplitTwoOperands(const char* ops, char* left, int left_cap, char* right, int right_cap);
static int32_t ParseStackOffset(const char* op);
static void GotoInsn(int i);
static void GotoVa(uint64_t va);
static void SelectFunction(int fi);
static void EnsureAnalyzed(int fi);

static uint32_t CodeCol(uint32_t tok)
{
    if (g_host && BSI_HOST_HAS(g_host, theme_code_color) && g_host->theme_code_color)
        return g_host->theme_code_color(g_host->ctx, tok);
    return 0xFFFFFFFFu;
}

static void PushMonoFont()
{
    if (!g_host || !BSI_HOST_HAS(g_host, theme_font_mono) || !g_host->theme_font_mono)
        return;
    ImFont* font = (ImFont*)g_host->theme_font_mono(g_host->ctx);
    if (font)
        ImGui::PushFont(font);
}

static void PopMonoFont()
{
    if (!g_host || !BSI_HOST_HAS(g_host, theme_font_mono) || !g_host->theme_font_mono)
        return;
    if (g_host->theme_font_mono(g_host->ctx))
        ImGui::PopFont();
}

static int FuncIndexByVa(uint64_t va)
{
    for (int i = 0; i < (int)g_funcs.size(); i++)
    {
        if (va >= g_funcs[(size_t)i].start_va && va < g_funcs[(size_t)i].end_va)
            return i;
    }
    return -1;
}

static int FuncStartIndex(uint64_t va)
{
    for (int i = 0; i < (int)g_funcs.size(); i++)
    {
        if (g_funcs[(size_t)i].start_va == va)
            return i;
    }
    return -1;
}

static const char* FuncNameAt(uint64_t va)
{
    int i = FuncStartIndex(va);
    if (i >= 0)
        return g_funcs[(size_t)i].name;
    return nullptr;
}

static void TryReadString(const uint8_t* image, size_t image_n, uint64_t va, uint64_t base,
    char* out, int cap)
{
    out[0] = 0;
    if (!g_host || !g_host->rva_to_off || va < base)
        return;
    uint32_t off = 0;
    if (!g_host->rva_to_off(g_host->ctx, (uint32_t)(va - base), &off))
        return;
    if ((size_t)off >= image_n)
        return;
    int n = 0;
    while (n < cap - 1 && (size_t)off + (size_t)n < image_n)
    {
        uint8_t c = image[off + n];
        if (c < 32 || c > 126)
            break;
        n++;
        if (n >= 48)
            break;
    }
    if (n < 3)
        return;
    out[0] = '"';
    int o = 1;
    int vis = n > 32 ? 32 : n;
    memcpy(out + o, image + off, (size_t)vis);
    o += vis;
    if (n > 32 && o < cap - 2)
        out[o++] = '.';
    if (o < cap - 2)
        out[o++] = '"';
    out[o] = 0;
}

static void BuildDocument(const uint8_t* image, size_t image_n, uint64_t base)
{
    g_rows.clear();
    std::unordered_map<uint64_t, uint16_t> xref;
    std::unordered_set<uint64_t> labels;
    for (const LyLine& l : g_insns)
    {
        if (!l.target_va)
            continue;
        if (l.flow == kLyFlowCall || l.flow == kLyFlowJmp || l.flow == kLyFlowCondJmp)
        {
            xref[l.target_va]++;
            if (l.flow != kLyFlowCall)
                labels.insert(l.target_va);
        }
    }

    for (int i = 0; i < (int)g_insns.size(); i++)
    {
        const LyLine& l = g_insns[(size_t)i];
        int fi = FuncStartIndex(l.va);
        if (fi >= 0)
        {
            LyRow h{};
            h.kind = kLyRowHeader;
            h.insn_idx = i;
            h.func_idx = fi;
            h.va = l.va;
            h.file_off = l.file_off;
            h.size = l.size;
            h.xref_n = xref[l.va];
            snprintf(h.mnemonic, sizeof(h.mnemonic), "%s", g_funcs[(size_t)fi].name);
            if (h.xref_n)
                snprintf(h.comment, sizeof(h.comment), "Xrefs: %u", (unsigned)h.xref_n);
            h.ops[0].kind = kLyTokFn;
            snprintf(h.ops[0].text, sizeof(h.ops[0].text), "%s", h.mnemonic);
            h.op_n = 1;
            g_rows.push_back(h);
        }
        else if (labels.count(l.va))
        {
            LyRow lb{};
            lb.kind = kLyRowLabel;
            lb.insn_idx = i;
            lb.func_idx = FuncIndexByVa(l.va);
            lb.va = l.va;
            LyMakeLabel(l.va, lb.mnemonic, (int)sizeof(lb.mnemonic));
            lb.ops[0].kind = kLyTokLabel;
            snprintf(lb.ops[0].text, sizeof(lb.ops[0].text), "%s:", lb.mnemonic);
            lb.op_n = 1;
            g_rows.push_back(lb);
        }

        LyRow r{};
        r.kind = kLyRowInsn;
        r.insn_idx = i;
        r.func_idx = FuncIndexByVa(l.va);
        r.va = l.va;
        r.file_off = l.file_off;
        r.size = l.size;
        r.flow = l.flow;
        r.target_va = l.target_va;
        r.bytes_n = l.bytes_n;
        memcpy(r.bytes, l.bytes, r.bytes_n);
        r.xref_n = xref[l.va];
        snprintf(r.mnemonic, sizeof(r.mnemonic), "%s", l.mnemonic);

        char ops[kLyOperandsCap];
        snprintf(ops, sizeof(ops), "%s", l.operands);
        const char* tname = l.target_va ? FuncNameAt(l.target_va) : nullptr;
        char loc[40];
        loc[0] = 0;
        if (!tname && l.target_va && labels.count(l.target_va))
        {
            LyMakeLabel(l.target_va, loc, (int)sizeof(loc));
            tname = loc;
        }
        if (tname && (l.flow == kLyFlowCall || l.flow == kLyFlowJmp || l.flow == kLyFlowCondJmp))
            snprintf(ops, sizeof(ops), "%s", tname);
        r.op_n = (uint8_t)LyTokenizeOperands(ops, r.ops, 14);
        if (tname && l.flow == kLyFlowCall)
        {
            for (uint8_t t = 0; t < r.op_n; t++)
                if (r.ops[t].kind == kLyTokFn || r.ops[t].kind == kLyTokSym)
                    r.ops[t].kind = kLyTokFn;
        }
        if (tname && (l.flow == kLyFlowJmp || l.flow == kLyFlowCondJmp))
        {
            for (uint8_t t = 0; t < r.op_n; t++)
                if (r.ops[t].kind == kLyTokLabel || r.ops[t].kind == kLyTokSym || r.ops[t].kind == kLyTokImm)
                    r.ops[t].kind = kLyTokBranch;
        }

        if (CfgShowStr() && l.mem_va && image)
        {
            char str[64];
            TryReadString(image, image_n, l.mem_va, base, str, (int)sizeof(str));
            if (str[0])
                snprintf(r.comment, sizeof(r.comment), "%s", str);
        }
        if (!r.comment[0] && CfgShowXrefs() && r.xref_n && fi < 0)
            snprintf(r.comment, sizeof(r.comment), "Xrefs: %u", (unsigned)r.xref_n);
        g_rows.push_back(r);
    }
}

static void PushNav(uint64_t va)
{
    if (g_nav_lock)
        return;
    if (g_nav_i >= 0 && g_nav_i < (int)g_nav.size() && g_nav[(size_t)g_nav_i] == va)
        return;
    if (g_nav_i + 1 < (int)g_nav.size())
        g_nav.resize((size_t)g_nav_i + 1);
    g_nav.push_back(va);
    g_nav_i = (int)g_nav.size() - 1;
}

static void GotoFirstInsnUsingStackOffset(int32_t stack_off)
{
    for (int i = 0; i < (int)g_lines.size(); i++)
    {
        const LyLine& l = g_lines[(size_t)i];
        char a[64];
        char b[96];
        a[0] = 0;
        b[0] = 0;
        if (SplitTwoOperands(l.operands, a, (int)sizeof(a), b, (int)sizeof(b)))
        {
            int32_t oa = ParseStackOffset(a);
            if (oa == stack_off)
            {
                GotoVa(l.va);
                return;
            }
            int32_t ob = ParseStackOffset(b);
            if (ob == stack_off)
            {
                GotoVa(l.va);
                return;
            }
        }
        else
        {
            int32_t o = ParseStackOffset(l.operands);
            if (o == stack_off)
            {
                GotoVa(l.va);
                return;
            }
        }
    }
}

static void BuildCfgAndXrefs(LyFunction& fn)
{
    fn.blocks.clear();
    fn.xrefs.clear();

    const int n = (int)fn.insns.size();
    if (n <= 0)
        return;

    // Xrefs: for now keep it code -> code based on direct targets.
    for (int i = 0; i < n; i++)
    {
        const LyLine& l = fn.insns[(size_t)i];
        if (!l.target_va)
            continue;
        if (l.flow == kLyFlowCall)
            fn.xrefs.push_back(LyXref{l.va, l.target_va, kLyXrefCall});
        else if (l.flow == kLyFlowJmp)
            fn.xrefs.push_back(LyXref{l.va, l.target_va, kLyXrefJmp});
        else if (l.flow == kLyFlowCondJmp)
            fn.xrefs.push_back(LyXref{l.va, l.target_va, kLyXrefCondJmp});
    }

    std::vector<int> leaders;
    leaders.push_back(0);

    for (int i = 0; i < n; i++)
    {
        const LyLine& l = fn.insns[(size_t)i];

        if ((l.flow == kLyFlowJmp || l.flow == kLyFlowCondJmp) && l.target_va)
        {
            int tidx = InsnIndexByVa(fn.insns, l.target_va);
            if (tidx >= 0)
                leaders.push_back(tidx);
        }
        if (l.flow == kLyFlowCondJmp)
        {
            // Fallthrough after conditional jump starts a new block.
            if (i + 1 < n)
                leaders.push_back(i + 1);
        }
    }

    std::sort(leaders.begin(), leaders.end());
    leaders.erase(std::unique(leaders.begin(), leaders.end()), leaders.end());

    // Blocks in sorted leader order.
    fn.blocks.reserve(leaders.size());
    for (int bi = 0; bi < (int)leaders.size(); bi++)
    {
        int start = leaders[(size_t)bi];
        int end = (bi + 1 < (int)leaders.size()) ? leaders[(size_t)(bi + 1)] - 1 : (n - 1);
        LyBlock b{};
        b.start_insn = start;
        b.end_insn = end;
        fn.blocks.push_back(std::move(b));
    }

    // Instruction -> block mapping.
    std::vector<int> inst_to_block((size_t)n, -1);
    for (int bi = 0; bi < (int)fn.blocks.size(); bi++)
    {
        const LyBlock& b = fn.blocks[(size_t)bi];
        for (int i = b.start_insn; i <= b.end_insn; i++)
            inst_to_block[(size_t)i] = bi;
    }

    // Successor edges.
    for (int bi = 0; bi < (int)fn.blocks.size(); bi++)
    {
        LyBlock& b = fn.blocks[(size_t)bi];
        const LyLine& term = fn.insns[(size_t)b.end_insn];

        if (term.flow == kLyFlowRet)
        {
            continue;
        }
        else if (term.flow == kLyFlowJmp || term.flow == kLyFlowCondJmp)
        {
            if (term.target_va)
            {
                int tidx = InsnIndexByVa(fn.insns, term.target_va);
                if (tidx >= 0)
                    b.succ.push_back(inst_to_block[(size_t)tidx]);
            }
            if (term.flow == kLyFlowCondJmp && b.end_insn + 1 < n)
                b.succ.push_back(inst_to_block[(size_t)(b.end_insn + 1)]);
        }
        else
        {
            // Default: fallthrough.
            if (b.end_insn + 1 < n)
                b.succ.push_back(inst_to_block[(size_t)(b.end_insn + 1)]);
        }

        // De-dup successors (can happen on self-edges).
        std::sort(b.succ.begin(), b.succ.end());
        b.succ.erase(std::unique(b.succ.begin(), b.succ.end()), b.succ.end());
    }
}

static int MnStarts(const char* mn, const char* pref)
{
    if (!mn || !pref)
        return 0;
    for (; *pref; pref++, mn++)
    {
        char a = *mn;
        char b = *pref;
        if (!a)
            return 0;
        if (tolower((unsigned char)a) != tolower((unsigned char)b))
            return 0;
    }
    return 1;
}

static void TrimInPlace(char* s)
{
    if (!s)
        return;

    char* start = s;
    while (*start == ' ' || *start == '\t')
        start++;

    char* end = start + strlen(start);
    while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
        end--;
    *end = 0;

    if (start != s)
        memmove(s, start, strlen(start) + 1);
}

static int SplitTwoOperands(const char* ops, char* left, int left_cap, char* right, int right_cap)
{
    if (!left || !right || left_cap <= 1 || right_cap <= 1)
        return 0;
    if (!ops)
        return 0;

    left[0] = 0;
    right[0] = 0;

    const char* comma = strchr(ops, ',');
    if (!comma)
        return 0;

    size_t l_n = (size_t)(comma - ops);
    if (l_n >= (size_t)left_cap)
        l_n = (size_t)left_cap - 1;
    memcpy(left, ops, l_n);
    left[l_n] = 0;
    snprintf(right, (size_t)right_cap, "%s", comma + 1);

    TrimInPlace(left);
    TrimInPlace(right);
    return 1;
}

static int32_t ParseStackOffset(const char* op)
{
    if (!op)
        return 0x80000000u;
    // Very conservative: only recognize patterns like [rbp-0x10] or [rsp+0x8].
    if (strstr(op, "rbp") == nullptr && strstr(op, "rsp") == nullptr)
        return 0x80000000u;

    const char* p = op;
    while (*p)
    {
        if (*p == '+' || *p == '-')
        {
            int sign = (*p == '-') ? -1 : 1;
            p++;
            // Skip optional "0x".
            if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
                p += 2;
            uint64_t v = 0;
            int any = 0;
            while (*p && isxdigit((unsigned char)*p))
            {
                any = 1;
                char c = *p++;
                v <<= 4;
                if (c >= '0' && c <= '9')
                    v |= (uint64_t)(c - '0');
                else if (c >= 'a' && c <= 'f')
                    v |= (uint64_t)(10 + (c - 'a'));
                else if (c >= 'A' && c <= 'F')
                    v |= (uint64_t)(10 + (c - 'A'));
            }
            if (any)
                return (int32_t)(sign * (int64_t)v);
        }
        p++;
    }
    return 0x80000000u;
}

static uint32_t ParseStackTypeFromOperand(const char* op)
{
    if (!op)
        return kLyTypeUnknown;
    // Very conservative: use operand-size hints when present.
    if (strstr(op, "qword ptr") || strstr(op, "qword"))
        return kLyTypeI64;
    if (strstr(op, "dword ptr") || strstr(op, "dword"))
        return kLyTypeI32;
    if (strstr(op, "word ptr") || strstr(op, "word"))
        return kLyTypeI16;
    if (strstr(op, "byte ptr") || strstr(op, "byte"))
        return kLyTypeI8;
    return kLyTypeUnknown;
}

static int ParseHexU64FromText(const char* s, uint64_t* out)
{
    if (!s || !out)
        return 0;
    *out = 0;

    // 0x... case.
    for (const char* p = s; *p; p++)
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            p += 2;
            uint64_t v = 0;
            int any = 0;
            while (*p && isxdigit((unsigned char)*p))
            {
                any = 1;
                char c = *p++;
                v <<= 4;
                if (c >= '0' && c <= '9')
                    v |= (uint64_t)(c - '0');
                else if (c >= 'a' && c <= 'f')
                    v |= (uint64_t)(10 + (c - 'a'));
                else if (c >= 'A' && c <= 'F')
                    v |= (uint64_t)(10 + (c - 'A'));
            }
            if (any)
            {
                *out = v;
                return 1;
            }
        }
    }

    // ...h suffix case.
    for (const char* p = s; *p; p++)
    {
        if (!isxdigit((unsigned char)*p))
            continue;
        uint64_t v = 0;
        int any = 0;
        const char* start = p;
        while (*p && isxdigit((unsigned char)*p))
        {
            any = 1;
            char c = *p++;
            v <<= 4;
            if (c >= '0' && c <= '9')
                v |= (uint64_t)(c - '0');
            else if (c >= 'a' && c <= 'f')
                v |= (uint64_t)(10 + (c - 'a'));
            else if (c >= 'A' && c <= 'F')
                v |= (uint64_t)(10 + (c - 'A'));
        }
        if (any && (*p == 'h' || *p == 'H'))
        {
            *out = v;
            return 1;
        }
        p = start;
    }

    return 0;
}

static int IsLikelyRegisterToken(const char* s)
{
    if (!s || !s[0])
        return 0;
    if (strchr(s, '[') || strchr(s, ']'))
        return 0;
    if (strstr(s, "ptr"))
        return 0;
    if (strchr(s, ' ') || strchr(s, '\t'))
        return 0;
    return 1;
}

static void BuildIrAndAnalysis(LyFunction& fn)
{
    fn.ir.clear();
    fn.stack_slots.clear();

    const int n = (int)fn.insns.size();
    for (int i = 0; i < n; i++)
    {
        const LyLine& l = fn.insns[(size_t)i];
        LyIrInst ir{};
        ir.va = l.va;
        ir.kind = kLyIrOther;
        ir.target_va = l.target_va;
        snprintf(ir.op, sizeof(ir.op), "%s", l.mnemonic);
        ir.dst[0] = 0;
        ir.src[0] = 0;

        if (l.flow == kLyFlowCall)
        {
            ir.kind = kLyIrCall;
        }
        else if (l.flow == kLyFlowJmp)
        {
            ir.kind = kLyIrJump;
        }
        else if (l.flow == kLyFlowCondJmp)
        {
            ir.kind = kLyIrCondJump;
        }
        else if (l.flow == kLyFlowRet)
        {
            ir.kind = kLyIrRet;
        }
        else
        {
            // Conservative lifting: only treat a subset of instruction shapes as assigns.
            if (MnStarts(l.mnemonic, "mov") || MnStarts(l.mnemonic, "lea") || MnStarts(l.mnemonic, "add") ||
                MnStarts(l.mnemonic, "sub") || MnStarts(l.mnemonic, "xor") || MnStarts(l.mnemonic, "or") ||
                MnStarts(l.mnemonic, "and") || MnStarts(l.mnemonic, "cmp"))
            {
                ir.kind = kLyIrAssign;
                snprintf(ir.op, sizeof(ir.op), "%s", l.mnemonic);
                char a[64];
                char b[96];
                if (SplitTwoOperands(l.operands, a, (int)sizeof(a), b, (int)sizeof(b)))
                {
                    snprintf(ir.dst, sizeof(ir.dst), "%s", a);
                    snprintf(ir.src, sizeof(ir.src), "%s", b);
                }
                else
                {
                    snprintf(ir.dst, sizeof(ir.dst), "%s", l.operands);
                }

                int32_t off = ParseStackOffset(a);
                if (off != (int32_t)0x80000000u)
                    fn.stack_slots.push_back(LyStackSlot{off, ParseStackTypeFromOperand(a)});
                off = ParseStackOffset(b);
                if (off != (int32_t)0x80000000u)
                    fn.stack_slots.push_back(LyStackSlot{off, ParseStackTypeFromOperand(b)});
            }
            else
            {
                snprintf(ir.op, sizeof(ir.op), "%s", l.mnemonic);
            }
        }

        fn.ir.push_back(ir);
    }

    // Very small data-flow pass: constant-propagate simple "mov reg, imm".
    // This is intentionally conservative and only handles direct hex immediates.
    struct LyConst { char name[64]; uint64_t value; };
    std::vector<LyConst> consts;
    for (LyIrInst& ir : fn.ir)
    {
        if (ir.kind == kLyIrAssign && MnStarts(ir.op, "mov") && IsLikelyRegisterToken(ir.dst))
        {
            uint64_t v = 0;
            if (ParseHexU64FromText(ir.src, &v))
            {
                int found = 0;
                for (LyConst& c : consts)
                {
                    if (strcmp(c.name, ir.dst) == 0)
                    {
                        c.value = v;
                        found = 1;
                        break;
                    }
                }
                if (!found)
                {
                    LyConst c{};
                    snprintf(c.name, sizeof(c.name), "%s", ir.dst);
                    c.value = v;
                    consts.push_back(c);
                }
            }
            else
            {
                // Invalidate destination constant if RHS isn't a direct number.
                consts.erase(
                    std::remove_if(consts.begin(), consts.end(),
                        [&](const LyConst& c) { return strcmp(c.name, ir.dst) == 0; }),
                    consts.end());
            }
        }
        else if (IsLikelyRegisterToken(ir.src))
        {
            for (const LyConst& c : consts)
            {
                if (strcmp(c.name, ir.src) == 0)
                {
                    snprintf(ir.src, sizeof(ir.src), "0x%llX", (unsigned long long)c.value);
                    break;
                }
            }
        }
    }

    // Dedup stack slots by offset (keep the first observed type hint).
    std::sort(fn.stack_slots.begin(), fn.stack_slots.end(),
        [](const LyStackSlot& a, const LyStackSlot& b) { return a.offset < b.offset; });
    fn.stack_slots.erase(std::unique(fn.stack_slots.begin(), fn.stack_slots.end(),
        [](const LyStackSlot& a, const LyStackSlot& b) { return a.offset == b.offset; }),
        fn.stack_slots.end());
}

static void BuildDecompilerDoc(LyFunction& fn)
{
    fn.dec_lines.clear();

    const int n = (int)fn.insns.size();
    if (n <= 0 || (int)fn.ir.size() != n)
        return;

    std::vector<int> is_block_start((size_t)n, 0);
    for (const LyBlock& b : fn.blocks)
    {
        if (b.start_insn >= 0 && b.start_insn < n)
            is_block_start[(size_t)b.start_insn] = 1;
    }

    for (int i = 0; i < n; i++)
    {
        if (is_block_start[(size_t)i])
        {
            LyDecLine lab{};
            lab.insn_idx = (uint32_t)i;
            snprintf(lab.text, sizeof(lab.text), "L_%llX:",
                (unsigned long long)fn.insns[(size_t)i].va);
            fn.dec_lines.push_back(lab);
        }

        const LyIrInst& ir = fn.ir[(size_t)i];
        LyDecLine dl{};
        dl.insn_idx = (uint32_t)i;

        if (ir.kind == kLyIrAssign)
        {
            if (ir.dst[0] && ir.src[0])
                snprintf(dl.text, sizeof(dl.text), "%s = %s;", ir.dst, ir.src);
            else if (ir.dst[0])
                snprintf(dl.text, sizeof(dl.text), "%s = <expr>;", ir.dst);
            else
                snprintf(dl.text, sizeof(dl.text), "/* %s */", ir.op);
        }
        else if (ir.kind == kLyIrCall)
        {
            if (ir.target_va)
                snprintf(dl.text, sizeof(dl.text), "call 0x%llX;", (unsigned long long)ir.target_va);
            else
                snprintf(dl.text, sizeof(dl.text), "call;");
        }
        else if (ir.kind == kLyIrJump)
        {
            if (ir.target_va)
                snprintf(dl.text, sizeof(dl.text), "goto 0x%llX;", (unsigned long long)ir.target_va);
            else
                snprintf(dl.text, sizeof(dl.text), "goto;");
        }
        else if (ir.kind == kLyIrCondJump)
        {
            if (ir.target_va)
                snprintf(dl.text, sizeof(dl.text), "if (%s) goto 0x%llX;", ir.op, (unsigned long long)ir.target_va);
            else
                snprintf(dl.text, sizeof(dl.text), "if (%s) goto;", ir.op);
        }
        else if (ir.kind == kLyIrRet)
        {
            snprintf(dl.text, sizeof(dl.text), "return;");
        }
        else
        {
            if (ir.op[0])
                snprintf(dl.text, sizeof(dl.text), "/* %s */", ir.op);
            else
                snprintf(dl.text, sizeof(dl.text), "/* <ir> */");
        }

        fn.dec_lines.push_back(dl);
    }
}

static int HostReady()
{
    return g_host && g_host->job_ready && g_host->job_ready(g_host->ctx);
}

static int Rebuild()
{
    g_insns.clear();
    g_lines.clear();
    g_funcs.clear();
    g_sel = -1;
    g_func_sel = 0;
    g_dec_sel = -1;
    g_dec_sel_end = -1;
    g_status[0] = 0;
    g_dirty = false;
    g_rows.clear();
    ReportProgress(Tr("lydis.stage.exec", "Finding executable code..."), -1.f);
    if (!HostReady())
    {
        snprintf(g_status, sizeof(g_status), "No open PE");
        return 0;
    }
    if (!BSI_HOST_HAS(g_host, hex_cursor) || !g_host->image || !g_host->pe_machine)
    {
        snprintf(g_status, sizeof(g_status), "Host is missing PE/hex queries");
        Logf(BsiSevError, "%s", g_status);
        return 0;
    }

    uint16_t machine = g_host->pe_machine(g_host->ctx);
    if (!LyMachineOk(machine))
    {
        snprintf(g_status, sizeof(g_status), "Unsupported architecture 0x%04X (x86/x64 only)", machine);
        return 0;
    }

    size_t image_n = 0;
    const uint8_t* image = g_host->image(g_host->ctx, &image_n);
    if (!image || !image_n)
    {
        snprintf(g_status, sizeof(g_status), "Host image is empty");
        return 0;
    }

    uint64_t base = g_host->image_base ? g_host->image_base(g_host->ctx) : 0;
    uint32_t entry_rva = g_host->entry_rva ? g_host->entry_rva(g_host->ctx) : 0;
    const uint64_t entry_va = base + entry_rva;
    const int show_bytes = CfgShowBytes();
    const int insn_cap = CfgMaxInsn();
    const uint32_t kScnMemExecute = 0x20000000u;
    const uint32_t kScnCntCode = 0x00000020u;
    const int kMaxFuncs = 16384;

    if (g_host->section_count && g_host->section_at)
    {
        int sc = g_host->section_count(g_host->ctx);
        for (int si = 0; si < sc && (int)g_insns.size() < insn_cap; si++)
        {
            char sname[16];
            uint32_t vaddr = 0, vsize = 0, rawptr = 0, rawsize = 0, chars = 0;
            sname[0] = 0;
            if (!g_host->section_at(g_host->ctx, si, sname, (int)sizeof(sname),
                    &vaddr, &vsize, &rawptr, &rawsize, &chars))
                continue;
            if ((chars & kScnMemExecute) == 0 && (chars & kScnCntCode) == 0)
                continue;
            uint32_t n = rawsize;
            if (vsize && vsize < n)
                n = vsize;
            if (!n)
                continue;
            uint32_t off = rawptr;
            uint64_t va = base + vaddr;
            uint32_t end = rawptr + n;
            if ((size_t)end > image_n)
                end = (uint32_t)image_n;
            ReportProgress(Tr("lydis.stage.decode", "Decoding instructions..."),
                insn_cap > 0 ? (float)g_insns.size() / (float)insn_cap : -1.f);
            while (off < end && (int)g_insns.size() < insn_cap)
            {
                if (WantCancel())
                    break;
                LyLine line{};
                if (!LyDecodeOne(image, image_n, off, va, machine, show_bytes, &line))
                {
                    LyFillDataByte(image, off, va, show_bytes, &line);
                }
                if (line.size == 0)
                    break;
                if (off + line.size > end)
                    break;
                g_insns.push_back(line);
                off += line.size;
                va += line.size;
            }
        }
    }

    if (g_insns.empty())
    {
        uint32_t file_off = 0;
        uint32_t rva = entry_rva;
        if (g_origin == kOriginHex)
        {
            uint32_t sel_n = 0;
            if (!g_host->hex_cursor(g_host->ctx, &file_off, &sel_n))
            {
                snprintf(g_status, sizeof(g_status), "No hex cursor");
                return 0;
            }
            if (g_host->off_to_rva)
                g_host->off_to_rva(g_host->ctx, file_off, &rva);
        }
        else if (!g_host->rva_to_off || !g_host->rva_to_off(g_host->ctx, rva, &file_off))
        {
            snprintf(g_status, sizeof(g_status), "Entry RVA 0x%X has no file offset", rva);
            return 0;
        }
        g_insns.resize((size_t)insn_cap);
        char err[160];
        int n = LyDisasm(image, image_n, file_off, base + rva, machine,
            insn_cap, show_bytes, g_insns.data(), insn_cap, err, (int)sizeof(err));
        if (n <= 0)
        {
            g_insns.clear();
            snprintf(g_status, sizeof(g_status), "%s", err[0] ? err : "Disassembly failed");
            return 0;
        }
        g_insns.resize((size_t)n);
    }

    std::vector<uint64_t> starts;
    starts.push_back(entry_va);
    if (g_origin == kOriginHex)
    {
        uint32_t file_off = 0, sel_n = 0;
        if (g_host->hex_cursor(g_host->ctx, &file_off, &sel_n))
        {
            for (const LyLine& l : g_insns)
            {
                if (l.file_off == file_off)
                {
                    starts.push_back(l.va);
                    break;
                }
            }
        }
    }
    for (const LyLine& l : g_insns)
    {
        if (WantCancel())
            break;
        if (l.flow == kLyFlowCall && l.target_va)
            starts.push_back(l.target_va);
        if (!strncmp(l.mnemonic, "push", 4) && strstr(l.operands, "rbp"))
            starts.push_back(l.va);
    }
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());

    for (uint64_t va : starts)
    {
        if ((int)g_funcs.size() >= kMaxFuncs)
            break;
        int idx = InsnIndexByVa(g_insns, va);
        if (idx < 0)
            continue;
        LyFunction fn{};
        fn.start_va = va;
        fn.start_idx = idx;
        fn.end_idx = idx;
        fn.analyzed = 0;
        LyMakeSubName(va, va == entry_va, fn.name, (int)sizeof(fn.name));
        g_funcs.push_back(fn);
    }

    for (int i = 0; i < (int)g_funcs.size(); i++)
    {
        int next = (i + 1 < (int)g_funcs.size()) ? g_funcs[(size_t)(i + 1)].start_idx : (int)g_insns.size();
        g_funcs[(size_t)i].end_idx = next - 1;
        if (g_funcs[(size_t)i].end_idx < g_funcs[(size_t)i].start_idx)
            g_funcs[(size_t)i].end_idx = g_funcs[(size_t)i].start_idx;
        const LyLine& last = g_insns[(size_t)g_funcs[(size_t)i].end_idx];
        g_funcs[(size_t)i].end_va = last.va + last.size;
    }

    if (g_funcs.empty())
    {
        snprintf(g_status, sizeof(g_status), "No functions in executable code");
        Logf(BsiSevError, "%s", g_status);
        return 0;
    }

    g_func_sel = 0;
    int entry_i = FuncStartIndex(entry_va);
    if (entry_i >= 0)
        g_func_sel = entry_i;
    ReportProgress(Tr("lydis.stage.xrefs", "Resolving references..."), 0.85f);
    BuildDocument(image, image_n, base);
    EnsureAnalyzed(g_func_sel);
    g_sel = g_funcs[(size_t)g_func_sel].start_idx;
    g_scroll_listing = true;
    snprintf(g_status, sizeof(g_status), "%d functions, %d instructions",
        (int)g_funcs.size(), (int)g_insns.size());
    Logf(BsiSevInfo, "%s", g_status);
    if (g_host->image_epoch)
        g_seen_epoch = g_host->image_epoch(g_host->ctx);
    ReportProgress(Tr("lydis.stage.ready", "Preparing disassembly..."), 1.f);
    if (g_host && BSI_HOST_HAS(g_host, progress_clear) && g_host->progress_clear)
        g_host->progress_clear(g_host->ctx, kId);
    return 1;
}

static void EnsureAnalyzed(int fi)
{
    if (fi < 0 || fi >= (int)g_funcs.size())
        return;
    LyFunction& fn = g_funcs[(size_t)fi];
    if (fn.analyzed)
    {
        g_lines = fn.insns;
        return;
    }
    if (fn.start_idx < 0 || fn.end_idx < fn.start_idx || fn.end_idx >= (int)g_insns.size())
        return;
    fn.insns.assign(g_insns.begin() + fn.start_idx, g_insns.begin() + fn.end_idx + 1);
    BuildCfgAndXrefs(fn);
    BuildIrAndAnalysis(fn);
    BuildDecompilerDoc(fn);
    fn.analyzed = 1;
    g_lines = fn.insns;
}

static void SelectFunction(int fi)
{
    if (fi < 0 || fi >= (int)g_funcs.size())
        return;
    g_func_sel = fi;
    EnsureAnalyzed(fi);
    g_sel = g_funcs[(size_t)fi].start_idx;
    g_dec_sel = 0;
    g_dec_sel_end = 0;
    g_scroll_listing = true;
    GotoInsn(g_sel);
}

static void GotoInsn(int i)
{
    if (i < 0 || i >= (int)g_insns.size() || !g_host)
        return;
    g_sel = i;
    g_scroll_listing = true;
    const LyLine& line = g_insns[(size_t)i];
    int fi = FuncIndexByVa(line.va);
    if (fi >= 0)
    {
        g_func_sel = fi;
        EnsureAnalyzed(fi);
    }
    PushNav(line.va);
    g_flash_until = ImGui::GetTime() + 0.45;
    g_pushed_hex_off = line.file_off;
    if (g_host->hex_select)
        g_host->hex_select(g_host->ctx, line.file_off, line.size);
    else if (g_host->hex_goto)
        g_host->hex_goto(g_host->ctx, line.file_off);
}

static void GotoVa(uint64_t va)
{
    int i = InsnIndexByVa(g_insns, va);
    if (i >= 0)
    {
        GotoInsn(i);
        return;
    }
    int fi = FuncStartIndex(va);
    if (fi >= 0)
        SelectFunction(fi);
}

static void SyncFromHex()
{
    if (!g_host || !g_host->hex_cursor || g_insns.empty())
        return;
    uint32_t off = 0, n = 0;
    if (!g_host->hex_cursor(g_host->ctx, &off, &n))
        return;
    if (off == g_pushed_hex_off)
        return;
    for (int i = 0; i < (int)g_insns.size(); i++)
    {
        const LyLine& l = g_insns[(size_t)i];
        if (off >= l.file_off && off < l.file_off + l.size)
        {
            if (g_sel != i)
            {
                g_sel = i;
                g_scroll_listing = true;
                int fi = FuncIndexByVa(l.va);
                if (fi >= 0)
                {
                    g_func_sel = fi;
                    EnsureAnalyzed(fi);
                }
            }
            g_pushed_hex_off = off;
            return;
        }
    }
}

static void KickAnalyze()
{
    if (g_busy.load())
        return;
    g_dirty = false;
    g_cancel.store(0);
    g_busy.store(1);
    ReportProgress(Tr("lydis.stage.exec", "Finding executable code..."), -1.f);
    if (g_worker.joinable())
        g_worker.join();
    g_worker = std::thread([]() {
        Rebuild();
        g_busy.store(0);
    });
}

static void EnsureListing()
{
    if (g_host && g_host->image_epoch)
    {
        uint64_t e = g_host->image_epoch(g_host->ctx);
        if (e != g_seen_epoch)
        {
            g_dirty = true;
            snprintf(g_status, sizeof(g_status), "%s",
                Tr("lydis.code_changed", "Code changed. Updating analysis..."));
        }
    }
    if (g_dirty && !g_busy.load())
        KickAnalyze();
}

static void CopyListing()
{
    if (!g_host || !g_host->clipboard_set)
        return;
    if (g_insns.empty())
    {
        Logf(BsiSevWarning, "Nothing to copy");
        return;
    }
    std::string text;
    text.reserve(g_insns.size() * 80);
    for (const LyLine& line : g_insns)
    {
        text += line.text;
        text += "\r\n";
    }
    if (g_host->clipboard_set(g_host->ctx, text.c_str()))
        Logf(BsiSevSuccess, "Copied %d lines", (int)g_insns.size());
    else
        Logf(BsiSevError, "Clipboard failed");
}

static void NavBack()
{
    if (g_nav_i <= 0)
        return;
    g_nav_lock = true;
    g_nav_i--;
    GotoVa(g_nav[(size_t)g_nav_i]);
    g_nav_lock = false;
}

static void NavForward()
{
    if (g_nav_i + 1 >= (int)g_nav.size())
        return;
    g_nav_lock = true;
    g_nav_i++;
    GotoVa(g_nav[(size_t)g_nav_i]);
    g_nav_lock = false;
}

static void ParseGoTo()
{
    const char* p = g_goto;
    while (*p == ' ')
        p++;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;
    uint64_t v = 0;
    int any = 0;
    while (*p)
    {
        unsigned char c = (unsigned char)*p++;
        int d = -1;
        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'a' && c <= 'f')
            d = 10 + c - 'a';
        else if (c >= 'A' && c <= 'F')
            d = 10 + c - 'A';
        else
            break;
        any = 1;
        v = (v << 4) | (uint64_t)d;
    }
    if (!any)
        return;
    if (v < 0x10000ull && g_host && g_host->image_base)
        v += g_host->image_base(g_host->ctx);
    GotoVa(v);
}

static ImVec4 Col4(uint32_t tok)
{
    return ImGui::ColorConvertU32ToFloat4(CodeCol(tok));
}

static void DrawListingView()
{
    SyncFromHex();
    const bool busy = g_busy.load() != 0;

    if (ImGui::SmallButton("<"))
        NavBack();
    ImGui::SameLine();
    if (ImGui::SmallButton(">"))
        NavForward();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.f);
    if (ImGui::InputTextWithHint("##goto", Tr("lydis.goto", "Go to address"), g_goto, (int)sizeof(g_goto),
            ImGuiInputTextFlags_EnterReturnsTrue))
        ParseGoTo();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(160.f);
    ImGui::InputTextWithHint("##search_listing", Tr("lydis.search", "Search"), g_search, (int)sizeof(g_search));
    if (g_search[0] && ImGui::IsItemDeactivatedAfterEdit())
    {
        for (int i = 0; i < (int)g_insns.size(); i++)
        {
            if (strstr(g_insns[(size_t)i].text, g_search) || strstr(g_insns[(size_t)i].mnemonic, g_search)
                || strstr(g_insns[(size_t)i].operands, g_search))
            {
                GotoInsn(i);
                break;
            }
        }
    }
    ImGui::SameLine();
    int sb = CfgShowBytes();
    if (ImGui::SmallButton(sb ? "Bytes" : "Bytes*"))
        CfgSetShowBytes(!sb);

    ImGuiIO& io = ImGui::GetIO();
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows))
    {
        if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_G, false))
            ImGui::SetKeyboardFocusHere(-1);
        if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false))
            NavBack();
        if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_RightArrow, false))
            NavForward();
        if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false) && g_sel >= 0 && g_sel < (int)g_insns.size()
            && g_host && g_host->clipboard_set)
            g_host->clipboard_set(g_host->ctx, g_insns[(size_t)g_sel].text);
    }

    if (busy || (g_rows.empty() && g_insns.empty()))
    {
        ImGui::BeginChild("ly_empty", ImVec2(0.f, -28.f), ImGuiChildFlags_None);
        ImGui::Dummy(ImVec2(1.f, ImGui::GetWindowHeight() * 0.28f));
        ImGui::TextWrapped("%s", busy
            ? Tr("lydis.analyzing", "Analyzing executable code...")
            : Tr("lydis.empty", "Select a function or address to inspect its assembly."));
        ImGui::TextDisabled("%s", Tr("lydis.empty_hint",
            "Assembly is the machine-level code executed by the processor."));
        ImGui::EndChild();
    }
    else
    {
        PushMonoFont();
        const float ch = ImGui::CalcTextSize("0").x;
        const float addr_w = CfgShowAddr() ? ch * 13.f : 0.f;
        const float bytes_w = CfgShowBytes() ? ch * 20.f : 0.f;
        const float mn_w = ch * 10.f;
        ImGui::BeginChild("ly_code", ImVec2(0.f, -28.f), ImGuiChildFlags_None,
            ImGuiWindowFlags_HorizontalScrollbar);
        if (ImGui::IsWindowFocused())
        {
            if (ImGui::IsKeyPressed(ImGuiKey_UpArrow) && g_sel > 0)
                GotoInsn(g_sel - 1);
            if (ImGui::IsKeyPressed(ImGuiKey_DownArrow) && g_sel + 1 < (int)g_insns.size())
                GotoInsn(g_sel + 1);
            if (ImGui::IsKeyPressed(ImGuiKey_PageUp))
                GotoInsn(g_sel > 32 ? g_sel - 32 : 0);
            if (ImGui::IsKeyPressed(ImGuiKey_PageDown))
                GotoInsn(g_sel + 32 < (int)g_insns.size() ? g_sel + 32 : (int)g_insns.size() - 1);
            if (ImGui::IsKeyPressed(ImGuiKey_Enter) && g_sel >= 0 && g_sel < (int)g_insns.size()
                && g_insns[(size_t)g_sel].target_va)
                GotoVa(g_insns[(size_t)g_sel].target_va);
        }

        ImGuiListClipper clipper;
        clipper.Begin((int)g_rows.size());
        while (clipper.Step())
        {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
            {
                const LyRow& row = g_rows[(size_t)i];
                bool sel = (row.kind == kLyRowInsn && row.insn_idx == g_sel);
                if (g_scroll_listing && sel)
                {
                    ImGui::SetScrollHereY(0.25f);
                    g_scroll_listing = false;
                }
                ImVec2 p = ImGui::GetCursorScreenPos();
                float w = ImGui::GetWindowWidth();
                float h = ImGui::GetTextLineHeightWithSpacing();
                if (row.kind == kLyRowHeader)
                    h *= 1.15f;
                ImDrawList* dl = ImGui::GetWindowDrawList();
                ImU32 bg = 0;
                if (sel)
                    bg = CodeCol(BsiTokFunction) & 0x22FFFFFFu;
                else if (row.kind == kLyRowHeader)
                    bg = CodeCol(BsiTokComment) & 0x18FFFFFFu;
                if (sel && ImGui::GetTime() < g_flash_until)
                    bg = CodeCol(BsiTokFunction) & 0x44FFFFFFu;
                if (bg)
                    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), bg);

                char rid[24];
                snprintf(rid, sizeof(rid), "##r%d", i);
                ImGui::PushID(i);
                if (ImGui::InvisibleButton(rid, ImVec2(w, h)))
                {
                    if (row.insn_idx >= 0)
                        GotoInsn(row.insn_idx);
                    if (row.kind == kLyRowHeader && row.xref_n)
                        g_xref_sel = row.func_idx;
                }
                if (ImGui::IsItemHovered())
                {
                    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), CodeCol(BsiTokAddress) & 0x14FFFFFFu);
                    if (row.kind == kLyRowInsn)
                    {
                        if (ImGui::BeginTooltip())
                        {
                            ImGui::TextUnformatted(Tr("lydis.tip.addr", "Where this instruction is located in memory."));
                            ImGui::TextUnformatted(Tr("lydis.tip.bytes", "The raw machine-code bytes for this instruction."));
                            ImGui::EndTooltip();
                        }
                    }
                    if (ImGui::IsMouseDoubleClicked(0) && row.target_va)
                        GotoVa(row.target_va);
                }
                if (ImGui::BeginPopupContextItem("insn_ctx"))
                {
                    if (row.target_va && ImGui::MenuItem(Tr("lydis.menu.follow", "Follow")))
                        GotoVa(row.target_va);
                    if (ImGui::MenuItem(Tr("lydis.menu.copy_insn", "Copy instruction")) && g_host && g_host->clipboard_set
                        && row.insn_idx >= 0 && row.insn_idx < (int)g_insns.size())
                        g_host->clipboard_set(g_host->ctx, g_insns[(size_t)row.insn_idx].text);
                    if (ImGui::MenuItem(Tr("lydis.menu.copy_addr", "Copy address")) && g_host && g_host->clipboard_set)
                    {
                        char a[32];
                        snprintf(a, sizeof(a), "0x%llX", (unsigned long long)row.va);
                        g_host->clipboard_set(g_host->ctx, a);
                    }
                    if (ImGui::MenuItem(Tr("lydis.menu.hex", "Open in Hex")))
                    {
                        if (g_host && g_host->hex_select)
                            g_host->hex_select(g_host->ctx, row.file_off, row.size ? row.size : 1);
                    }
                    if (row.xref_n && ImGui::MenuItem(Tr("lydis.menu.xrefs", "References")))
                        g_xref_sel = row.func_idx >= 0 ? row.func_idx : FuncIndexByVa(row.va);
                    ImGui::EndPopup();
                }
                ImGui::SameLine(0.f, 0.f);
                float x = 8.f;
                if (row.kind == kLyRowHeader)
                {
                    ImGui::SetCursorPosX(x);
                    ImGui::TextColored(Col4(BsiTokFunction), "%s", row.mnemonic);
                    if (row.comment[0])
                    {
                        ImGui::SameLine();
                        ImGui::TextColored(Col4(BsiTokComment), "  %s", row.comment);
                    }
                }
                else if (row.kind == kLyRowLabel)
                {
                    ImGui::SetCursorPosX(x + addr_w + bytes_w);
                    ImGui::TextColored(Col4(BsiTokLabel), "%s:", row.mnemonic);
                }
                else
                {
                    if (CfgShowAddr())
                    {
                        ImGui::SetCursorPosX(x);
                        ImGui::TextColored(Col4(BsiTokAddress), "%012llX", (unsigned long long)row.va);
                    }
                    x += addr_w + 8.f;
                    if (CfgShowBytes())
                    {
                        char b[40];
                        LyFormatBytes(row.bytes, row.bytes_n, b, (int)sizeof(b));
                        ImGui::SameLine(x, 0.f);
                        ImGui::TextColored(Col4(BsiTokBytes), "%s", b);
                    }
                    x += bytes_w + 8.f;
                    ImGui::SameLine(x, 0.f);
                    uint32_t mt = BsiTokMnemonic;
                    if (row.flow == kLyFlowCall || row.flow == kLyFlowRet)
                        mt = BsiTokKeyword;
                    else if (row.flow == kLyFlowJmp || row.flow == kLyFlowCondJmp)
                        mt = BsiTokBranch;
                    ImGui::TextColored(Col4(mt), "%-8s", row.mnemonic);
                    x += mn_w;
                    ImGui::SameLine(x, 0.f);
                    for (uint8_t t = 0; t < row.op_n; t++)
                    {
                        ImGui::TextColored(Col4(LyTokToBsi(row.ops[t].kind)), "%s", row.ops[t].text);
                        if (t + 1 < row.op_n)
                            ImGui::SameLine(0.f, 0.f);
                    }
                    if (row.comment[0])
                    {
                        ImGui::SameLine(0.f, ch * 3.f);
                        ImGui::TextColored(Col4(BsiTokComment), "; %s", row.comment);
                    }
                }
                ImGui::PopID();
            }
        }
        ImGui::EndChild();
        PopMonoFont();
    }

    if (busy)
    {
        ImGui::TextUnformatted(g_stage_text[0] ? g_stage_text : Tr("lydis.analyzing", "Analyzing code..."));
        float f = g_frac.load();
        ImGui::ProgressBar(f < 0.f ? (float)(-ImGui::GetTime() * 0.25 - floor(-ImGui::GetTime() * 0.25)) : f,
            ImVec2(-80.f, 0.f));
        ImGui::SameLine();
        if (ImGui::SmallButton(Tr("lydis.cancel", "Cancel")))
            g_cancel.store(1);
    }
    else if (g_status[0])
        ImGui::TextDisabled("%s", g_status);
} 

static void DrawDecompilerView()
{
    if (g_funcs.empty())
    {
        ImGui::TextWrapped("Select a function to see a C-like reconstruction of what it does.");
        return;
    }
    EnsureAnalyzed(g_func_sel);
    const LyFunction& fn = g_funcs[(size_t)g_func_sel];
    ImGui::Text("%s  0x%llX", fn.name, (unsigned long long)fn.start_va);
    ImGui::SameLine();
    ImGui::TextDisabled("Reconstructed from machine code; not original source.");
    ImGui::SetNextItemWidth(-1.f);
    ImGui::InputTextWithHint("##search_decompile", "Find in decompiler", g_search, (int)sizeof(g_search));
    if (g_search[0] && ImGui::IsItemDeactivatedAfterEdit())
    {
        for (int i = 0; i < (int)fn.dec_lines.size(); i++)
        {
            if (strstr(fn.dec_lines[(size_t)i].text, g_search))
            {
                g_dec_sel = i;
                g_dec_sel_end = i;
                int li = (int)fn.dec_lines[(size_t)i].insn_idx;
                if (li >= 0 && li < (int)fn.insns.size())
                    GotoVa(fn.insns[(size_t)li].va);
                break;
            }
        }
    }

    PushMonoFont();
    ImGui::BeginChild("ly_decompiler", ImVec2(0.f, 0.f), ImGuiChildFlags_Borders,
        ImGuiWindowFlags_HorizontalScrollbar);
    ImGuiListClipper clipper;
    clipper.Begin((int)fn.dec_lines.size());
    while (clipper.Step())
    {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
        {
            const LyDecLine& ln = fn.dec_lines[(size_t)i];
            int a = g_dec_sel < g_dec_sel_end ? g_dec_sel : g_dec_sel_end;
            int b = g_dec_sel < g_dec_sel_end ? g_dec_sel_end : g_dec_sel;
            bool selected = (i >= a && i <= b && a >= 0);
            char id[24];
            snprintf(id, sizeof(id), "##dl%d", i);
            if (ImGui::Selectable(id, selected, ImGuiSelectableFlags_AllowOverlap))
            {
                if (ImGui::GetIO().KeyShift && g_dec_sel >= 0)
                    g_dec_sel_end = i;
                else
                {
                    g_dec_sel = i;
                    g_dec_sel_end = i;
                }
                int li = (int)ln.insn_idx;
                if (li >= 0 && li < (int)fn.insns.size())
                    GotoVa(fn.insns[(size_t)li].va);
            }
            ImGui::SameLine(0.f, 0.f);
            ImGui::TextDisabled("%4d  ", i + 1);
            ImGui::SameLine();
            uint32_t tok = BsiTokUnknown;
            if (strstr(ln.text, "goto") || strstr(ln.text, "return") || strstr(ln.text, "if ("))
                tok = BsiTokKeyword;
            else if (ln.text[0] == '/' && ln.text[1] == '*')
                tok = BsiTokComment;
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(CodeCol(tok)), "%s", ln.text);
        }
    }
    if (ImGui::IsWindowFocused() && ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false)
        && g_host && g_host->clipboard_set && g_dec_sel >= 0)
    {
        int a = g_dec_sel < g_dec_sel_end ? g_dec_sel : g_dec_sel_end;
        int b = g_dec_sel < g_dec_sel_end ? g_dec_sel_end : g_dec_sel;
        std::string text;
        for (int i = a; i <= b && i < (int)fn.dec_lines.size(); i++)
        {
            text += fn.dec_lines[(size_t)i].text;
            text += "\r\n";
        }
        g_host->clipboard_set(g_host->ctx, text.c_str());
    }
    if (ImGui::IsWindowFocused() && ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A, false))
    {
        g_dec_sel = 0;
        g_dec_sel_end = (int)fn.dec_lines.size() - 1;
    }
    ImGui::EndChild();
    PopMonoFont();
}

static void DrawFunctionList(const char* child_id)
{
    if (ImGui::BeginChild(child_id, ImVec2(0.f, 0.f), ImGuiChildFlags_Borders))
    {
        ImGuiListClipper clipper;
        clipper.Begin((int)g_funcs.size());
        while (clipper.Step())
        {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
            {
                const LyFunction& f = g_funcs[(size_t)i];
                char label[96];
                snprintf(label, sizeof(label), "%s  (%d insn)", f.name, f.end_idx - f.start_idx + 1);
                if (ImGui::Selectable(label, i == g_func_sel))
                    SelectFunction(i);
                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0))
                    SelectFunction(i);
            }
        }
    }
    ImGui::EndChild();
}

static void BindImGui(const BsiUi* ui)
{
    if (ui && BSI_UI_HAS(ui, imgui) && ui->imgui)
        ImGui::SetCurrentContext((ImGuiContext*)ui->imgui);
}

static void GotoLine(int i)
{
    GotoInsn(i);
}

extern "C" {

BSI_PLUGIN_EXPORT const BsiPluginInfo* BsiPluginGetInfo(void)
{
    static const BsiPluginInfo info = {
        kId,
        kName,
        kVersion,
        "bsi",
        "x86/x64 listing of executable sections, functions, and decompiler.",
        BSI_PLUGIN_ABI_VERSION,
        BsiKindTool | BsiKindView
    };
    return &info;
}

BSI_PLUGIN_EXPORT int BsiPluginInit(const BsiHost* host)
{
    if (!BsiHostCompatible(host))
        return 1;
    if (!BSI_HOST_HAS(host, hex_cursor))
        return 1;
    g_host = host;
    ClearListing();
    Logf(BsiSevInfo, "Ready");
    return 0;
}

BSI_PLUGIN_EXPORT void BsiPluginShutdown(void)
{
    StopWorker();
    g_host = nullptr;
}

BSI_PLUGIN_EXPORT int BsiPluginToolCount(void)
{
    return 2;
}

BSI_PLUGIN_EXPORT int BsiPluginToolInfo(int index, BsiToolInfo* out)
{
    if (!out)
        return 0;
    if (index == kToolEntry)
    {
        out->id = "disasm_entry";
        out->parent = kName;
        out->label = "Disassemble at entry";
        return 1;
    }
    if (index == kToolHex)
    {
        out->id = "disasm_hex";
        out->parent = kName;
        out->label = "Disassemble at hex";
        return 1;
    }
    return 0;
}

BSI_PLUGIN_EXPORT int BsiPluginToolRun(int index)
{
    if (index == kToolEntry)
        g_origin = kOriginEntry;
    else if (index == kToolHex)
        g_origin = kOriginHex;
    else
        return 0;
    g_dirty = true;
    KickAnalyze();
    return 1;
}

BSI_PLUGIN_EXPORT int BsiPluginViewCount(void)
{
    return 4;
}

BSI_PLUGIN_EXPORT int BsiPluginViewInfo(int index, BsiViewInfo* out)
{
    if (!out)
        return 0;

    if (index == 0)
    {
        out->id = "disasm";
        out->label = "Disassembly";
        out->region = BsiViewRegionCenter;
        out->default_open = 1;
        out->utility = 0;
        out->menu_group = BsiViewMenuView;
        out->min_w = 280.f;
        out->min_h = 0.f;
        out->meta_version = 1;
        return 1;
    }
    if (index == 1)
    {
        out->id = "decompile";
        out->label = "Decompiler";
        out->region = BsiViewRegionRight;
        out->default_open = 1;
        out->utility = 0;
        out->menu_group = BsiViewMenuView;
        out->min_w = 320.f;
        out->min_h = 0.f;
        out->meta_version = 1;
        return 1;
    }

    if (index == 2)
    {
        out->id = "symbols";
        out->label = "Symbols";
        out->region = BsiViewRegionLeft;
        out->default_open = 1;
        out->utility = 0;
        out->menu_group = BsiViewMenuView;
        out->min_w = 240.f;
        out->min_h = 0.f;
        out->meta_version = 1;
        return 1;
    }
    if (index == 3)
    {
        out->id = "xrefs";
        out->label = "Xrefs";
        out->region = BsiViewRegionBottom;
        out->default_open = 0;
        out->utility = 1;
        out->menu_group = BsiViewMenuPanel;
        out->min_w = 280.f;
        out->min_h = 140.f;
        out->meta_version = 1;
        return 1;
    }

    return 0;
}

BSI_PLUGIN_EXPORT int BsiPluginViewDraw(int index, const BsiUi* ui)
{
    if (!ui)
        return 0;
    BindImGui(ui);
    EnsureListing();
    if (index == 0)
    {
        DrawListingView();
        return 1;
    }
    if (index == 1)
    {
        DrawDecompilerView();
        return 1;
    }
    if (index == 2)
    {
        ImGui::TextUnformatted(Tr("lydis.symbols", "Functions"));
        ImGui::SetNextItemWidth(-1.f);
        ImGui::InputTextWithHint("##fnfind", Tr("lydis.search", "Search"), g_search, (int)sizeof(g_search));
        DrawFunctionList("sym_fns");
        return 1;
    }
    if (index == 3)
    {
        ImGui::TextUnformatted(Tr("lydis.xrefs", "Xrefs"));
        if (g_sel < 0 || g_sel >= (int)g_insns.size())
        {
            ImGui::TextDisabled("%s", Tr("lydis.xrefs_empty", "Select an instruction to see references."));
            return 1;
        }
        const LyLine& cur = g_insns[(size_t)g_sel];
        ImGui::TextDisabled("0x%llX", (unsigned long long)cur.va);
        int shown = 0;
        for (const LyLine& l : g_insns)
        {
            if (l.target_va != cur.va)
                continue;
            char buf[96];
            snprintf(buf, sizeof(buf), "0x%llX  %s", (unsigned long long)l.va, l.mnemonic);
            if (ImGui::Selectable(buf, false))
                GotoVa(l.va);
            shown++;
            if (shown > 64)
            {
                ImGui::TextDisabled("...");
                break;
            }
        }
        if (!shown)
            ImGui::TextDisabled("%s", Tr("lydis.xrefs_none", "No incoming references."));
        return 1;
    }
    return 0;
}

BSI_PLUGIN_EXPORT int BsiPluginHasSettings(void)
{
    return 1;
}

BSI_PLUGIN_EXPORT void BsiPluginDrawSettings(const BsiUi* ui)
{
    if (!ui)
        return;
    int max_insn = CfgMaxInsn();
    int show_bytes = CfgShowBytes();
    if (ui->label)
        ui->label(ui->ctx, "Max instructions");
    if (ui->input_int)
    {
        int prev = max_insn;
        if (ui->input_int(ui->ctx, "##max_insn", &max_insn))
        {
            max_insn = ClampInsn(max_insn);
            if (max_insn != prev)
            {
                CfgSetMaxInsn(max_insn);
                g_dirty = true;
            }
        }
    }
    if (ui->hint)
        ui->hint(ui->ctx, "32 to 250000 (full image linear sweep cap)");
    if (ui->checkbox)
    {
        int prev = show_bytes;
        if (ui->checkbox(ui->ctx, "show_bytes", "Show bytes", &show_bytes) && show_bytes != prev)
        {
            CfgSetShowBytes(show_bytes);
        }
    }
}

BSI_PLUGIN_EXPORT void BsiPluginOnJob(int ready)
{
    ClearListing();
    if (ready)
        g_origin = kOriginEntry;
}

}
