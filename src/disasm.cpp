#include "disasm.h"

extern "C" {
#include <Zydis.h>
}

#include <stdio.h>
#include <string.h>

int LyMachineOk(uint16_t machine)
{
    return machine == kLyMachineI386 || machine == kLyMachineAmd64;
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
                (unsigned long long)runtime, bytes, insn.text);
        }
        else
        {
            snprintf(line.text, kLyTextCap, "%016llX  %s",
                (unsigned long long)runtime, insn.text);
        }
        off += insn.info.length;
        runtime += insn.info.length;
        n++;
    }
    if (n == 0 && err && err_cap > 0)
        snprintf(err, err_cap, "No instruction at 0x%X", file_off);
    return n;
}
