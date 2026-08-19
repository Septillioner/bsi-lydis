#include "disasm.h"

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

    ZydisMachineMode mode = machine == kLyMachineAmd64
        ? ZYDIS_MACHINE_MODE_LONG_64
        : ZYDIS_MACHINE_MODE_LEGACY_32;

    int n = 0;
    size_t off = file_off;
    uint64_t runtime = va;
    while (n < max_insn && off < image_n)
    {
        ZydisDisassembledInstruction insn{};
        ZyanStatus st = ZydisDisassembleIntel(mode, runtime,
            image + off, image_n - off, &insn);
        if (!ZYAN_SUCCESS(st) || insn.info.length == 0)
            break;

        LyLine& line = out[n];
        line.file_off = (uint32_t)off;
        line.size = insn.info.length;
        line.va = runtime;
        line.bytes_n = insn.info.length;
        if (line.bytes_n > kLyInsnBytesCap)
            line.bytes_n = kLyInsnBytesCap;
        if (line.bytes_n > 0)
            memcpy(line.bytes, image + off, line.bytes_n);
        else
            line.bytes_n = 0;
        line.mnemonic[0] = 0;
        line.operands[0] = 0;
        const char* asm_text = insn.text ? insn.text : "";
        if (asm_text[0])
        {
            const char* sep = strpbrk(asm_text, " \t");
            if (sep)
            {
                size_t m = (size_t)(sep - asm_text);
                if (m >= kLyMnemonicCap)
                    m = kLyMnemonicCap - 1;
                memcpy(line.mnemonic, asm_text, m);
                line.mnemonic[m] = 0;

                const char* ops = sep;
                while (*ops == ' ' || *ops == '\t')
                    ops++;
                snprintf(line.operands, kLyOperandsCap, "%s", ops);
            }
            else
            {
                snprintf(line.mnemonic, kLyMnemonicCap, "%s", asm_text);
            }
        }
        line.flow = kLyFlowNone;
        line.target_va = 0;
        if (MnStarts(line.mnemonic, "ret"))
        {
            line.flow = kLyFlowRet;
        }
        else if (MnStarts(line.mnemonic, "call"))
        {
            line.flow = kLyFlowCall;
            line.target_va = ParseHexTarget(line.operands);
        }
        else if (MnStarts(line.mnemonic, "jmp"))
        {
            line.flow = kLyFlowJmp;
            line.target_va = ParseHexTarget(line.operands);
        }
        else if (line.mnemonic[0] == 'j' || line.mnemonic[0] == 'J')
        {
            // Rough heuristic: treat j* (except plain jmp) as conditional jumps.
            if (!MnStarts(line.mnemonic, "jmp"))
            {
                line.flow = kLyFlowCondJmp;
                line.target_va = ParseHexTarget(line.operands);
            }
        }
        if (show_bytes)
        {
            char bytes[48];
            bytes[0] = 0;
            int used = 0;
            uint8_t len = insn.info.length;
            if (len > 10)
                len = 10;
            for (uint8_t i = 0; i < len && used < (int)sizeof(bytes) - 4; i++)
                used += snprintf(bytes + used, sizeof(bytes) - (size_t)used, "%02X ", image[off + i]);
            if (insn.info.length > 10 && used < (int)sizeof(bytes) - 3)
                snprintf(bytes + used, sizeof(bytes) - (size_t)used, "..");
            snprintf(line.text, kLyTextCap, "%016llX  %-32s %s",
                (unsigned long long)runtime, bytes, asm_text);
        }
        else
        {
            snprintf(line.text, kLyTextCap, "%016llX  %s",
                (unsigned long long)runtime, asm_text);
        }
        off += insn.info.length;
        runtime += insn.info.length;
        n++;
    }
    if (n == 0 && err && err_cap > 0)
        snprintf(err, err_cap, "No instruction at 0x%X", file_off);
    return n;
}
