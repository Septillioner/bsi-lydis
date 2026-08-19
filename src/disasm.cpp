#include "disasm.h"
#include "format.h"

extern "C" {
#include <Zydis.h>
}

#include <stdio.h>
#include <string.h>
#include <ctype.h>

int LyMachineOk(uint16_t machine)
{
    return machine == kLyMachineI386 || machine == kLyMachineAmd64;
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

static uint64_t ParseHexTarget(const char* ops)
{
    if (!ops)
        return 0;

    // 1) Try 0x... patterns.
    for (const char* p = ops; *p; p++)
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
                return v;
        }
    }

    // 2) Try ...h suffix patterns (common x86 style).
    for (const char* p = ops; *p; p++)
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
            return v;
        p = start;
    }

    return 0;
}

static void FillLineText(LyLine* line, int show_bytes)
{
    char bytes[48];
    bytes[0] = 0;
    if (show_bytes)
    {
        int used = 0;
        int n = line->bytes_n;
        if (n > 10)
            n = 10;
        for (int i = 0; i < n && used < (int)sizeof(bytes) - 4; i++)
            used += snprintf(bytes + used, sizeof(bytes) - (size_t)used, "%02X ", line->bytes[i]);
        if (line->size > 10 && used < (int)sizeof(bytes) - 3)
            snprintf(bytes + used, sizeof(bytes) - (size_t)used, "..");
        snprintf(line->text, kLyTextCap, "%016llX  %-32s %s %s",
            (unsigned long long)line->va, bytes, line->mnemonic, line->operands);
    }
    else
    {
        snprintf(line->text, kLyTextCap, "%016llX  %s %s",
            (unsigned long long)line->va, line->mnemonic, line->operands);
    }
}

int LyDecodeOne(const uint8_t* image, size_t image_n,
    uint32_t file_off, uint64_t va, uint16_t machine,
    int show_bytes, LyLine* out)
{
    if (!image || !out || (size_t)file_off >= image_n || !LyMachineOk(machine))
        return 0;

    memset(out, 0, sizeof(*out));
    ZydisMachineMode mode = machine == kLyMachineAmd64
        ? ZYDIS_MACHINE_MODE_LONG_64
        : ZYDIS_MACHINE_MODE_LEGACY_32;
    ZydisStackWidth sw = machine == kLyMachineAmd64
        ? ZYDIS_STACK_WIDTH_64
        : ZYDIS_STACK_WIDTH_32;

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, sw)))
        return 0;
    ZydisDecodedInstruction inst;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, image + file_off,
            image_n - file_off, &inst, operands)) || inst.length == 0)
        return 0;

    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&fmt, ZYDIS_FORMATTER_PROP_HEX_PREFIX, (ZyanUPointer)"0x");
    ZydisFormatterSetProperty(&fmt, ZYDIS_FORMATTER_PROP_HEX_UPPERCASE, ZYAN_FALSE);

    char text[256];
    text[0] = 0;
    ZydisFormatterFormatInstruction(&fmt, &inst, operands, inst.operand_count_visible,
        text, sizeof(text), va, ZYAN_NULL);

    out->file_off = file_off;
    out->size = inst.length;
    out->va = va;
    out->bytes_n = inst.length;
    if (out->bytes_n > kLyInsnBytesCap)
        out->bytes_n = kLyInsnBytesCap;
    memcpy(out->bytes, image + file_off, out->bytes_n);

    const char* sep = strpbrk(text, " \t");
    if (sep)
    {
        size_t m = (size_t)(sep - text);
        if (m >= kLyMnemonicCap)
            m = kLyMnemonicCap - 1;
        memcpy(out->mnemonic, text, m);
        out->mnemonic[m] = 0;
        while (*sep == ' ' || *sep == '\t')
            sep++;
        char pretty[kLyOperandsCap];
        LyBeautifyOperands(sep, pretty, (int)sizeof(pretty));
        snprintf(out->operands, kLyOperandsCap, "%s", pretty);
    }
    else
        snprintf(out->mnemonic, kLyMnemonicCap, "%s", text);

    if (inst.meta.category == ZYDIS_CATEGORY_RET)
        out->flow = kLyFlowRet;
    else if (inst.meta.category == ZYDIS_CATEGORY_CALL)
        out->flow = kLyFlowCall;
    else if (inst.meta.category == ZYDIS_CATEGORY_UNCOND_BR)
        out->flow = kLyFlowJmp;
    else if (inst.meta.category == ZYDIS_CATEGORY_COND_BR)
        out->flow = kLyFlowCondJmp;

    if (out->flow == kLyFlowCall || out->flow == kLyFlowJmp || out->flow == kLyFlowCondJmp)
    {
        for (ZyanU8 i = 0; i < inst.operand_count_visible; i++)
        {
            ZyanU64 abs = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, &operands[i], va, &abs)))
            {
                out->target_va = abs;
                break;
            }
        }
        if (!out->target_va)
            out->target_va = ParseHexTarget(out->operands);
    }

    for (ZyanU8 i = 0; i < inst.operand_count_visible; i++)
    {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            ZyanU64 abs = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, &operands[i], va, &abs)))
            {
                out->mem_va = abs;
                break;
            }
        }
    }

    FillLineText(out, show_bytes);
    return 1;
}

void LyFillDataByte(const uint8_t* image, uint32_t file_off, uint64_t va, int show_bytes, LyLine* out)
{
    memset(out, 0, sizeof(*out));
    out->file_off = file_off;
    out->size = 1;
    out->va = va;
    out->bytes_n = 1;
    out->bytes[0] = image[file_off];
    snprintf(out->mnemonic, kLyMnemonicCap, "db");
    snprintf(out->operands, kLyOperandsCap, "0x%02X", out->bytes[0]);
    FillLineText(out, show_bytes);
}

int LyDisasm(const uint8_t* image, size_t image_n,
    uint32_t file_off, uint64_t va, uint16_t machine,
    int max_insn, int show_bytes,
    LyLine* out, int cap, char* err, int err_cap)
{
    if (err && err_cap > 0)
        err[0] = 0;
    if (!image || !out || cap <= 0)
    {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "Bad disasm args");
        return -1;
    }
    if (!LyMachineOk(machine))
    {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "Unsupported machine 0x%04X (x86/x64 only)", machine);
        return -1;
    }
    if ((size_t)file_off >= image_n)
    {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "Offset 0x%X is past the image", file_off);
        return -1;
    }
    if (max_insn < kLyInsnMin)
        max_insn = kLyInsnMin;
    if (max_insn > kLyInsnMax)
        max_insn = kLyInsnMax;
    if (max_insn > cap)
        max_insn = cap;

    int n = 0;
    size_t off = file_off;
    uint64_t runtime = va;
    while (n < max_insn && off < image_n)
    {
        if (!LyDecodeOne(image, image_n, (uint32_t)off, runtime, machine, show_bytes, &out[n]))
            break;
        off += out[n].size;
        runtime += out[n].size;
        n++;
    }
    if (n == 0 && err && err_cap > 0)
        snprintf(err, err_cap, "No instruction at 0x%X", file_off);
    return n;
}
