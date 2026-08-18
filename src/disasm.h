#pragma once

#include <stdint.h>
#include <stddef.h>

enum
{
    kLyMachineI386 = 0x014C,
    kLyMachineAmd64 = 0x8664,
    kLyInsnMin = 32,
    kLyInsnMax = 512,
    kLyInsnDefault = 128,
    kLyLineCap = 512,
    kLyTextCap = 160
};

struct LyLine
{
    uint32_t file_off;
    uint32_t size;
    uint64_t va;
    char     text[kLyTextCap];
};

int LyMachineOk(uint16_t machine);
int LyDisasm(const uint8_t* image, size_t image_n,
    uint32_t file_off, uint64_t va, uint16_t machine,
    int max_insn, int show_bytes,
    LyLine* out, int cap, char* err, int err_cap);
