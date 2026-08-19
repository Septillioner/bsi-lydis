#include "bsi_plugin.h"
#include "disasm.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <vector>
#include <string>
#include <algorithm>
#include <ctype.h>

static const char kId[] = "com.bsi.lydis";
static const char kName[] = "Lydis";
static const char kVersion[] = "0.1.0";
static const char kModule[] = "lydis";
static const char kCfgMaxInsn[] = "max_insn";
static const char kCfgShowBytes[] = "show_bytes";

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
    std::vector<LyLine> insns;
    std::vector<LyBlock> blocks;
    std::vector<LyXref> xrefs;
    std::vector<LyIrInst> ir;
    std::vector<LyStackSlot> stack_slots;
    std::vector<LyDecLine> dec_lines;
};

static const BsiHost* g_host;
static std::vector<LyLine> g_lines;
static std::vector<LyFunction> g_funcs;
static char g_status[192];
static char g_search[96];
static int g_origin = kOriginEntry;
static int g_sel = -1;
static int g_func_sel = 0;
static bool g_dirty = true;

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

static void ClearListing()
{
    g_lines.clear();
    g_funcs.clear();
    g_func_sel = 0;
    g_sel = -1;
    g_status[0] = 0;
    g_search[0] = 0;
    g_dirty = true;
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
static void GotoLine(int i);

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
                g_sel = i;
                GotoLine(i);
                return;
            }
            int32_t ob = ParseStackOffset(b);
            if (ob == stack_off)
            {
                g_sel = i;
                GotoLine(i);
                return;
            }
        }
        else
        {
            int32_t o = ParseStackOffset(l.operands);
            if (o == stack_off)
            {
                g_sel = i;
                GotoLine(i);
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
    g_lines.clear();
    g_sel = -1;
    g_status[0] = 0;
    g_dirty = false;
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

    uint32_t file_off = 0;
    uint32_t rva = 0;
    uint64_t base = g_host->image_base ? g_host->image_base(g_host->ctx) : 0;
    if (g_origin == kOriginHex)
    {
        uint32_t sel_n = 0;
        if (!g_host->hex_cursor(g_host->ctx, &file_off, &sel_n))
        {
            snprintf(g_status, sizeof(g_status), "No hex cursor");
            Logf(BsiSevWarning, "%s", g_status);
            return 0;
        }
        if (g_host->off_to_rva)
            g_host->off_to_rva(g_host->ctx, file_off, &rva);
    }
    else
    {
        rva = g_host->entry_rva ? g_host->entry_rva(g_host->ctx) : 0;
        if (!g_host->rva_to_off || !g_host->rva_to_off(g_host->ctx, rva, &file_off))
        {
            snprintf(g_status, sizeof(g_status), "Entry RVA 0x%X has no file offset", rva);
            Logf(BsiSevError, "%s", g_status);
            return 0;
        }
    }

    const uint64_t entry_va = base + rva;

    // Function discovery: decode entry, then decode direct call/jump targets
    // discovered inside decoded functions (bounded).
    g_funcs.clear();
    g_lines.clear();

    std::vector<uint64_t> work;
    std::vector<uint64_t> seen;
    work.push_back(entry_va);

    const int kMaxFuncs = 16;

    auto Seen = [&](uint64_t va) -> int
    {
        for (uint64_t x : seen)
            if (x == va)
                return 1;
        return 0;
    };

    while (!work.empty() && (int)g_funcs.size() < kMaxFuncs)
    {
        uint64_t start_va = work.back();
        work.pop_back();
        if (Seen(start_va))
            continue;
        seen.push_back(start_va);

        uint32_t start_file_off = 0;
        if (start_va == entry_va)
            start_file_off = file_off;
        else
        {
            if (!g_host->rva_to_off || start_va < base)
                continue;
            uint32_t start_rva = (uint32_t)(start_va - base);
            if (!g_host->rva_to_off(g_host->ctx, start_rva, &start_file_off))
                continue;
        }

        LyLine buf[kLyLineCap];
        char err[160];
        int n = LyDisasm(image, image_n, start_file_off, start_va, machine,
            CfgMaxInsn(), CfgShowBytes(), buf, kLyLineCap, err, (int)sizeof(err));
        if (n <= 0)
            continue;

        LyFunction fn{};
        fn.start_va = start_va;
        fn.end_va = buf[(size_t)(n - 1)].va + buf[(size_t)(n - 1)].size;
        fn.insns.assign(buf, buf + n);
        BuildCfgAndXrefs(fn);
        BuildIrAndAnalysis(fn);
        BuildDecompilerDoc(fn);
        g_funcs.push_back(std::move(fn));

        // Discover new function entry points from direct call/jump targets.
        for (const LyLine& l : g_funcs.back().insns)
        {
            if (!l.target_va)
                continue;
            if (l.flow != kLyFlowCall && l.flow != kLyFlowJmp && l.flow != kLyFlowCondJmp)
                continue;
            if (!Seen(l.target_va) && (int)g_funcs.size() < kMaxFuncs)
                work.push_back(l.target_va);
        }
    }

    if (g_funcs.empty())
    {
        snprintf(g_status, sizeof(g_status), "Function discovery produced no functions");
        Logf(BsiSevError, "%s", g_status);
        return 0;
    }

    g_func_sel = 0;
    // UI listing/decompiler show the currently selected function.
    g_lines = g_funcs[(size_t)g_func_sel].insns;
    Logf(BsiSevInfo, "%d functions decoded (entry VA 0x%llX, listing %d insn)",
        (int)g_funcs.size(), (unsigned long long)entry_va, (int)g_lines.size());
    return 1;
}

static void EnsureListing()
{
    if (g_dirty)
        Rebuild();
}

static void CopyListing()
{
    if (!g_host || !g_host->clipboard_set)
        return;
    if (g_lines.empty())
    {
        Logf(BsiSevWarning, "Nothing to copy");
        return;
    }
    std::string text;
    text.reserve(g_lines.size() * 80);
    for (const LyLine& line : g_lines)
    {
        text += line.text;
        text += "\r\n";
    }
    if (g_host->clipboard_set(g_host->ctx, text.c_str()))
        Logf(BsiSevSuccess, "Copied %d lines", (int)g_lines.size());
    else
        Logf(BsiSevError, "Clipboard failed");
}

static void GotoLine(int i)
{
    if (i < 0 || i >= (int)g_lines.size() || !g_host)
        return;
    const LyLine& line = g_lines[(size_t)i];
    if (g_host->hex_select)
        g_host->hex_select(g_host->ctx, line.file_off, line.size);
    else if (g_host->hex_goto)
        g_host->hex_goto(g_host->ctx, line.file_off);
}

extern "C" {

BSI_PLUGIN_EXPORT const BsiPluginInfo* BsiPluginGetInfo(void)
{
    static const BsiPluginInfo info = {
        kId,
        kName,
        kVersion,
        "bsi",
        "x86/x64 disassembly from entry point or hex cursor.",
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
    g_lines.clear();
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
    return Rebuild();
}

BSI_PLUGIN_EXPORT int BsiPluginViewCount(void)
{
    return 7; // Listing, Decompiler, CFG Graph, Program Tree, Symbols, Strings, Types
}

BSI_PLUGIN_EXPORT int BsiPluginViewInfo(int index, BsiViewInfo* out)
{
    if (!out)
        return 0;

    if (index == 0)
    {
        out->id = "disasm";
        out->label = "Listing";
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
        out->id = "cfg_graph";
        out->label = "CFG Graph";
        out->region = BsiViewRegionBottom;
        out->default_open = 0;
        out->utility = 0;
        out->menu_group = BsiViewMenuView;
        out->min_w = 280.f;
        out->min_h = 240.f;
        out->meta_version = 1;
        return 1;
    }

    if (index == 3)
    {
        out->id = "program_tree";
        out->label = "Program Tree";
        out->region = BsiViewRegionLeft;
        out->default_open = 1;
        out->utility = 0;
        out->menu_group = BsiViewMenuView;
        out->min_w = 240.f;
        out->min_h = 0.f;
        out->meta_version = 1;
        return 1;
    }

    if (index == 4)
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

    if (index == 5)
    {
        out->id = "strings";
        out->label = "Strings";
        out->region = BsiViewRegionBottom;
        out->default_open = 0;
        out->utility = 0;
        out->menu_group = BsiViewMenuView;
        out->min_w = 280.f;
        out->min_h = 180.f;
        out->meta_version = 1;
        return 1;
    }

    if (index == 6)
    {
        out->id = "types";
        out->label = "Types";
        out->region = BsiViewRegionBottom;
        out->default_open = 0;
        out->utility = 0;
        out->menu_group = BsiViewMenuView;
        out->min_w = 280.f;
        out->min_h = 180.f;
        out->meta_version = 1;
        return 1;
    }

    return 0;
}

BSI_PLUGIN_EXPORT int BsiPluginViewDraw(int index, const BsiUi* ui)
{
    if (!ui)
        return 0;

    EnsureListing();

    if (index == 0)
    {
        if (ui->section)
            ui->section(ui->ctx, kName);
        if (g_status[0] && ui->hint)
            ui->hint(ui->ctx, g_status);
        if (ui->button && ui->button(ui->ctx, "from_entry", "From entry"))
        {
            g_origin = kOriginEntry;
            g_dirty = true;
            Rebuild();
        }
        if (ui->same_line)
            ui->same_line(ui->ctx);
        if (ui->button && ui->button(ui->ctx, "from_hex", "From hex"))
        {
            g_origin = kOriginHex;
            g_dirty = true;
            Rebuild();
        }
        if (ui->same_line)
            ui->same_line(ui->ctx);
        if (ui->button && ui->button(ui->ctx, "copy", "Copy listing"))
            CopyListing();

        if (ui->input_text)
            ui->input_text(ui->ctx, "search_listing", g_search, (int)sizeof(g_search));
        if (ui->button && ui->button(ui->ctx, "find_listing", "Find"))
        {
            if (g_search[0])
            {
                for (int i = 0; i < (int)g_lines.size(); i++)
                {
                    if (strstr(g_lines[(size_t)i].text, g_search))
                    {
                        g_sel = i;
                        GotoLine(i);
                        break;
                    }
                }
            }
        }

        if (ui->begin_child && ui->end_child && ui->selectable)
        {
            if (ui->begin_child(ui->ctx, "listing", 0.f, 0.f))
            {
                for (int i = 0; i < (int)g_lines.size(); i++)
                {
                    char id[24];
                    snprintf(id, sizeof(id), "ln%d", i);
                    if (ui->selectable(ui->ctx, id, g_lines[(size_t)i].text, g_sel == i))
                    {
                        g_sel = i;
                        GotoLine(i);
                    }
                }
            }
            ui->end_child(ui->ctx);
        }
        else if (ui->label)
        {
            for (const LyLine& line : g_lines)
                ui->label(ui->ctx, line.text);
        }

        // Xrefs navigation for the currently selected instruction.
        if (!g_funcs.empty() && ui->selectable && g_sel >= 0 && g_sel < (int)g_lines.size())
        {
            const LyFunction& fn = g_funcs[(size_t)g_func_sel];
            const uint64_t from_va = g_lines[(size_t)g_sel].va;
            if (ui->label)
                ui->label(ui->ctx, "Xrefs from selected:");

            int printed = 0;
            for (const LyXref& x : fn.xrefs)
            {
                if (x.from_va != from_va)
                    continue;
                int to_i = InsnIndexByVa(fn.insns, x.to_va);
                if (to_i < 0)
                    continue;

                char id[24];
                snprintf(id, sizeof(id), "xr%d", printed);
                const char* k = (x.kind == kLyXrefCall) ? "call" :
                    (x.kind == kLyXrefJmp) ? "jmp" : "cjmp";
                char text[96];
                snprintf(text, sizeof(text), "%s -> 0x%llX", k, (unsigned long long)x.to_va);
                if (ui->selectable(ui->ctx, id, text, g_sel == to_i))
                {
                    g_sel = to_i;
                    GotoLine(to_i);
                }
                printed++;
                if (printed >= 32)
                    break;
            }
        }
        return 1;
    }

    if (index == 1)
    {
        if (ui->section)
            ui->section(ui->ctx, "Decompiler");
        if (g_status[0] && ui->hint)
            ui->hint(ui->ctx, g_status);

        if (g_funcs.empty())
        {
            if (ui->label)
                ui->label(ui->ctx, "Select a function to see decompiler output.");
            return 1;
        }

        const LyFunction& fn = g_funcs[(size_t)g_func_sel];

        if (ui->input_text)
            ui->input_text(ui->ctx, "search_decompile", g_search, (int)sizeof(g_search));
        if (ui->button && ui->button(ui->ctx, "find_decompile", "Find"))
        {
            if (g_search[0])
            {
                for (int i = 0; i < (int)fn.dec_lines.size(); i++)
                {
                    if (strstr(fn.dec_lines[(size_t)i].text, g_search))
                    {
                        g_sel = (int)fn.dec_lines[(size_t)i].insn_idx;
                        GotoLine(g_sel);
                        break;
                    }
                }
            }
        }

        if (fn.dec_lines.empty())
        {
            if (ui->label)
                ui->label(ui->ctx, "Decompiler output unavailable.");
            return 1;
        }

        if (ui->begin_child && ui->end_child && ui->selectable)
        {
            if (ui->begin_child(ui->ctx, "decompiler", 0.f, 0.f))
            {
                for (int i = 0; i < (int)fn.dec_lines.size(); i++)
                {
                    char id[24];
                    snprintf(id, sizeof(id), "dl%d", i);
                    const LyDecLine& ln = fn.dec_lines[(size_t)i];
                    if (ui->selectable(ui->ctx, id, ln.text, g_sel == (int)ln.insn_idx))
                    {
                        g_sel = (int)ln.insn_idx;
                        GotoLine(g_sel);
                    }
                }
            }
            ui->end_child(ui->ctx);
        }
        else if (ui->label)
        {
            for (const LyDecLine& ln : fn.dec_lines)
                ui->label(ui->ctx, ln.text);
        }

        return 1;
    }

    if (g_funcs.empty())
        return 0;

    const LyFunction& fn = g_funcs[(size_t)g_func_sel];
    if (index == 2)
    {
        if (ui->section)
            ui->section(ui->ctx, "CFG Graph");
        if (g_status[0] && ui->hint)
            ui->hint(ui->ctx, g_status);

        if (ui->begin_child && ui->end_child)
        {
            if (ui->begin_child(ui->ctx, "cfg", 0.f, 0.f))
            {
                if (ui->label)
                    ui->label(ui->ctx, "Blocks + successors (click a block to jump).");

                char buf[256];
                for (int bi = 0; bi < (int)fn.blocks.size(); bi++)
                {
                    const LyBlock& b = fn.blocks[(size_t)bi];
                    const LyLine& start = fn.insns[(size_t)b.start_insn];
                    char id[24];
                    snprintf(id, sizeof(id), "bb%d", bi);
                    snprintf(buf, sizeof(buf), "B @ 0x%llX (%d insn) [succ=%d]",
                        (unsigned long long)start.va,
                        b.end_insn - b.start_insn + 1,
                        (int)b.succ.size());

                    if (ui->selectable && ui->selectable(ui->ctx, id, buf, g_sel == b.start_insn))
                    {
                        g_sel = b.start_insn;
                        GotoLine(g_sel);
                    }

                    for (int si = 0; si < (int)b.succ.size(); si++)
                    {
                        int s = b.succ[(size_t)si];
                        if (s < 0 || s >= (int)fn.blocks.size())
                            continue;
                        const LyBlock& sb = fn.blocks[(size_t)s];
                        const LyLine& st = fn.insns[(size_t)sb.start_insn];
                        if (ui->label)
                        {
                            char line[160];
                            snprintf(line, sizeof(line), "  -> B_%d @ 0x%llX", s, (unsigned long long)st.va);
                            ui->label(ui->ctx, line);
                        }
                    }
                }
            }
            ui->end_child(ui->ctx);
        }
        return 1;
    }

    if (index == 3)
    {
        if (ui->section)
            ui->section(ui->ctx, "Program Tree");
        if (ui->hint)
            ui->hint(ui->ctx, "Functions + blocks. Click a function to switch the Listing/Decompiler.");

        if (ui->begin_child && ui->end_child && ui->selectable)
        {
            if (ui->begin_child(ui->ctx, "functions", 0.f, 0.f))
            {
                for (int fi = 0; fi < (int)g_funcs.size(); fi++)
                {
                    const LyFunction& f = g_funcs[(size_t)fi];
                    char id[24];
                    snprintf(id, sizeof(id), "fn%d", fi);
                    char text[96];
                    snprintf(text, sizeof(text), "fn 0x%llX (%d insn, %d blocks)",
                        (unsigned long long)f.start_va,
                        (int)f.insns.size(),
                        (int)f.blocks.size());
                    if (ui->selectable(ui->ctx, id, text, fi == g_func_sel))
                    {
                        g_func_sel = fi;
                        g_lines = g_funcs[(size_t)g_func_sel].insns;
                        g_sel = 0;
                        if (!g_lines.empty())
                            GotoLine(0);
                    }
                }
            }

            ui->end_child(ui->ctx);

            if (ui->begin_child(ui->ctx, "blocks", 0.f, 0.f))
            {
                for (int bi = 0; bi < (int)fn.blocks.size(); bi++)
                {
                    const LyBlock& b = fn.blocks[(size_t)bi];
                    const LyLine& start = fn.insns[(size_t)b.start_insn];
                    char id[24];
                    snprintf(id, sizeof(id), "bb%d", bi);
                    char text[80];
                    snprintf(text, sizeof(text), "Block @ 0x%llX (%d insn)",
                        (unsigned long long)start.va, b.end_insn - b.start_insn + 1);
                    if (ui->selectable(ui->ctx, id, text, g_sel == b.start_insn))
                    {
                        g_sel = b.start_insn;
                        GotoLine(g_sel);
                    }
                }
            }
            ui->end_child(ui->ctx);
        }
        return 1;
    }

    if (index == 4)
    {
        if (ui->section)
            ui->section(ui->ctx, "Symbols");
        if (ui->hint)
            ui->hint(ui->ctx, "Only stack slot hints are exposed for now.");

        if (ui->input_text)
            ui->input_text(ui->ctx, "search_symbols", g_search, (int)sizeof(g_search));
        if (ui->button && ui->button(ui->ctx, "find_symbols", "Find"))
        {
            if (g_search[0])
            {
                for (const LyStackSlot& s : fn.stack_slots)
                {
                    char label[120];
                    const char* t = "unknown";
                    if (s.type_kind == kLyTypeI8)
                        t = "i8";
                    else if (s.type_kind == kLyTypeI16)
                        t = "i16";
                    else if (s.type_kind == kLyTypeI32)
                        t = "i32";
                    else if (s.type_kind == kLyTypeI64)
                        t = "i64";
                    snprintf(label, sizeof(label), "stack[%d] : %s", s.offset, t);
                    if (strstr(label, g_search))
                    {
                        GotoFirstInsnUsingStackOffset(s.offset);
                        break;
                    }
                }
            }
        }

        if (ui->begin_child && ui->end_child)
        {
            if (ui->begin_child(ui->ctx, "symbols", 0.f, 0.f))
            {
                char buf[200];
                int si = 0;
                for (const LyStackSlot& s : fn.stack_slots)
                {
                    const char* t = "unknown";
                    if (s.type_kind == kLyTypeI8)
                        t = "i8";
                    else if (s.type_kind == kLyTypeI16)
                        t = "i16";
                    else if (s.type_kind == kLyTypeI32)
                        t = "i32";
                    else if (s.type_kind == kLyTypeI64)
                        t = "i64";
                    snprintf(buf, sizeof(buf), "stack[%d] : %s", s.offset, t);
                    if (g_search[0] && !strstr(buf, g_search))
                        continue;

                    int sel = 0;
                    if (g_sel >= 0 && g_sel < (int)g_lines.size())
                    {
                        const LyLine& cur = g_lines[(size_t)g_sel];
                        char a[64];
                        char b[96];
                        if (SplitTwoOperands(cur.operands, a, (int)sizeof(a), b, (int)sizeof(b)))
                        {
                            sel = (ParseStackOffset(a) == s.offset) || (ParseStackOffset(b) == s.offset);
                        }
                        else
                        {
                            sel = (ParseStackOffset(cur.operands) == s.offset);
                        }
                    }

                    if (ui->selectable)
                    {
                        char id[24];
                        snprintf(id, sizeof(id), "sym%d", si++);
                        if (ui->selectable(ui->ctx, id, buf, sel))
                            GotoFirstInsnUsingStackOffset(s.offset);
                    }
                    else if (ui->label)
                    {
                        ui->label(ui->ctx, buf);
                    }
                }
            }
            ui->end_child(ui->ctx);
        }
        return 1;
    }

    if (index == 5)
    {
        if (ui->section)
            ui->section(ui->ctx, "Strings");
        if (ui->label)
            ui->label(ui->ctx, "Strings analysis not implemented yet.");
        return 1;
    }

    if (index == 6)
    {
        if (ui->section)
            ui->section(ui->ctx, "Types");
        if (ui->label)
            ui->label(ui->ctx, "Type recovery not implemented yet (placeholders only).");
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
        ui->hint(ui->ctx, "32 to 512");
    if (ui->checkbox)
    {
        int prev = show_bytes;
        if (ui->checkbox(ui->ctx, "show_bytes", "Show bytes", &show_bytes) && show_bytes != prev)
        {
            CfgSetShowBytes(show_bytes);
            g_dirty = true;
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
