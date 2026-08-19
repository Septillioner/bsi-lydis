#pragma once

#include "disasm.h"
#include <stdint.h>

enum
{
    kLyTokAddr = 0,
    kLyTokBytes,
    kLyTokMnemonic,
    kLyTokReg,
    kLyTokImm,
    kLyTokMem,
    kLyTokOp,
    kLyTokSym,
    kLyTokFn,
    kLyTokStr,
    kLyTokCmt,
    kLyTokLabel,
    kLyTokImport,
    kLyTokBranch
};

enum
{
    kLyRowInsn = 0,
    kLyRowHeader = 1,
    kLyRowLabel = 2
};

struct LyTok
{
    uint16_t kind;
    char text[80];
};

struct LyRow
{
    uint8_t  kind;
    uint8_t  block_lead;
    int      insn_idx;
    int      func_idx;
    uint64_t va;
    uint32_t file_off;
    uint32_t size;
    uint32_t flow;
    uint64_t target_va;
    uint8_t  bytes[kLyInsnBytesCap];
    uint8_t  bytes_n;
    uint16_t xref_n;
    char     mnemonic[kLyMnemonicCap];
    char     comment[96];
    LyTok    ops[14];
    uint8_t  op_n;
};

void LyBeautifyOperands(const char* in, char* out, int cap);
int  LyTokenizeOperands(const char* ops, LyTok* toks, int cap);
uint32_t LyTokToBsi(uint16_t kind);
void LyMakeLabel(uint64_t va, char* out, int cap);
void LyMakeSubName(uint64_t va, int is_entry, char* out, int cap);
void LyFormatBytes(const uint8_t* b, int n, char* out, int cap);
int  LyLooksLikeRegister(const char* s);
