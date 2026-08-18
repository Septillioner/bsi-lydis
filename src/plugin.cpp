#include "bsi_plugin.h"
#include "disasm.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <vector>
#include <string>

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

static const BsiHost* g_host;
static std::vector<LyLine> g_lines;
static char g_status[192];
static int g_origin = kOriginEntry;
static int g_sel = -1;
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
    g_sel = -1;
    g_status[0] = 0;
    g_dirty = true;
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

    uint64_t va = base + rva;
    LyLine buf[kLyLineCap];
    char err[160];
    int n = LyDisasm(image, image_n, file_off, va, machine,
        CfgMaxInsn(), CfgShowBytes(), buf, kLyLineCap, err, (int)sizeof(err));
    if (n < 0)
    {
        snprintf(g_status, sizeof(g_status), "%s", err[0] ? err : "Disasm failed");
        Logf(BsiSevError, "%s", g_status);
        return 0;
    }
    if (n == 0)
    {
        snprintf(g_status, sizeof(g_status), "%s", err[0] ? err : "No instructions");
        return 0;
    }
    g_lines.assign(buf, buf + n);
    Logf(BsiSevInfo, "%d insn from %s at file 0x%X (VA 0x%llX)",
        n, g_origin == kOriginHex ? "hex" : "entry", file_off, (unsigned long long)va);
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
    return 1;
}

BSI_PLUGIN_EXPORT int BsiPluginViewInfo(int index, BsiViewInfo* out)
{
    if (index != 0 || !out)
        return 0;
    out->id = "disasm";
    out->label = "Disassembly";
    return 1;
}

BSI_PLUGIN_EXPORT int BsiPluginViewDraw(int index, const BsiUi* ui)
{
    if (index != 0 || !ui)
        return 0;
    EnsureListing();
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
    return 1;
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
