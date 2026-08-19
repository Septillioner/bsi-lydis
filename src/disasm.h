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
    kLyTextCap = 160,
    kLyInsnBytesCap = 16,
    kLyMnemonicCap = 32,
    kLyOperandsCap = 96
};

enum
{
    kLyFlowNone = 0,
    kLyFlowJmp = 1,
    kLyFlowCondJmp = 2,
    kLyFlowCall = 3,
    kLyFlowRet = 4
};

struct LyLine
{
    uint32_t file_off;
    uint32_t size;
    uint64_t va;
    uint8_t  bytes[kLyInsnBytesCap];
    uint8_t  bytes_n;
    char     mnemonic[kLyMnemonicCap];
    char     operands[kLyOperandsCap];
    uint32_t flow;
    uint64_t target_va;
    char     text[kLyTextCap];
};

int LyMachineOk(uint16_t machine);
int LyDisasm(const uint8_t* image, size_t image_n,
    uint32_t file_off, uint64_t va, uint16_t machine,
    int max_insn, int show_bytes,
    LyLine* out, int cap, char* err, int err_cap);
