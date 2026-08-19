#include "format.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

void LyMakeLabel(uint64_t va, char* out, int cap)
{
    snprintf(out, (size_t)cap, "loc_%llX", (unsigned long long)va);
}

void LyMakeSubName(uint64_t va, int is_entry, char* out, int cap)
{
    if (is_entry)
        snprintf(out, (size_t)cap, "entry");
    else
        snprintf(out, (size_t)cap, "sub_%llX", (unsigned long long)va);
}

void LyFormatBytes(const uint8_t* b, int n, char* out, int cap)
{
    out[0] = 0;
    if (!b || cap < 4)
        return;
    int used = 0;
    if (n > 8)
        n = 8;
    for (int i = 0; i < n && used < cap - 3; i++)
        used += snprintf(out + used, (size_t)(cap - used), "%02X ", b[i]);
}

int LyLooksLikeRegister(const char* s)
{
    static const char* kRegs[] = {
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip",
        "eax","ebx","ecx","edx","esi","edi","ebp","esp","eip",
        "ax","bx","cx","dx","si","di","bp","sp",
        "al","ah","bl","bh","cl","ch","dl","dh",
        "r8","r9","r10","r11","r12","r13","r14","r15",
        "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
        "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
        "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
        "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
        "ymm0","ymm1","ymm2","ymm3","ymm4","ymm5","ymm6","ymm7",
        "cs","ds","es","ss","fs","gs", nullptr
    };
    if (!s || !s[0])
        return 0;
    for (int i = 0; kRegs[i]; i++)
        if (_stricmp(s, kRegs[i]) == 0)
            return 1;
    return 0;
}

uint32_t LyTokToBsi(uint16_t kind)
{
    switch (kind)
    {
    case kLyTokAddr: return 0;
    case kLyTokBytes: return 1;
    case kLyTokMnemonic: return 2;
    case kLyTokReg: return 3;
    case kLyTokImm: return 4;
    case kLyTokMem: return 5;
    case kLyTokSym: return 6;
    case kLyTokStr: return 7;
    case kLyTokCmt: return 8;
    case kLyTokFn: return 11;
    case kLyTokLabel: return 16;
    case kLyTokOp: return 15;
    case kLyTokImport: return 19;
    case kLyTokBranch: return 20;
    default: return 18;
    }
}

static int IsIdentChar(char c)
{
    return isalnum((unsigned char)c) || c == '_' || c == '.';
}

void LyBeautifyOperands(const char* in, char* out, int cap)
{
    if (!out || cap <= 1)
        return;
    out[0] = 0;
    if (!in)
        return;

    char buf[256];
    int o = 0;
    int br = 0;
    for (const char* p = in; *p && o < (int)sizeof(buf) - 2; p++)
    {
        if (*p == '[')
            br++;
        else if (*p == ']' && br)
            br--;

        if (br && (*p == '+' || *p == '-') && p != in)
        {
            if (o && buf[o - 1] != ' ' && buf[o - 1] != '[')
                buf[o++] = ' ';
            buf[o++] = *p;
            if (p[1] && p[1] != ' ' && p[1] != ']')
                buf[o++] = ' ';
            continue;
        }
        if (*p == ',' && p[1] && p[1] != ' ')
        {
            buf[o++] = ',';
            buf[o++] = ' ';
            continue;
        }
        buf[o++] = *p;
    }
    buf[o] = 0;

    // Normalize 0padded hex and ...h to 0x
    o = 0;
    for (char* p = buf; *p && o < cap - 1; )
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            p += 2;
            uint64_t v = 0;
            while (isxdigit((unsigned char)*p))
            {
                char c = *p++;
                v <<= 4;
                if (c <= '9')
                    v |= (uint64_t)(c - '0');
                else
                    v |= (uint64_t)(10 + (tolower((unsigned char)c) - 'a'));
            }
            o += snprintf(out + o, (size_t)(cap - o), "0x%llX", (unsigned long long)v);
            continue;
        }
        if (isxdigit((unsigned char)*p))
        {
            char* s = p;
            while (isxdigit((unsigned char)*p))
                p++;
            if (*p == 'h' || *p == 'H')
            {
                uint64_t v = 0;
                for (char* q = s; q < p; q++)
                {
                    char c = *q;
                    v <<= 4;
                    if (c <= '9')
                        v |= (uint64_t)(c - '0');
                    else
                        v |= (uint64_t)(10 + (tolower((unsigned char)c) - 'a'));
                }
                p++;
                o += snprintf(out + o, (size_t)(cap - o), "0x%llX", (unsigned long long)v);
                continue;
            }
            p = s;
        }
        out[o++] = *p++;
    }
    out[o] = 0;
}

int LyTokenizeOperands(const char* ops, LyTok* toks, int cap)
{
    if (!ops || !toks || cap <= 0)
        return 0;
    int n = 0;
    const char* p = ops;
    while (*p && n < cap)
    {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        if (*p == '[' || strncmp(p, "byte ptr", 8) == 0 || strncmp(p, "word ptr", 8) == 0
            || strncmp(p, "dword ptr", 9) == 0 || strncmp(p, "qword ptr", 9) == 0
            || strncmp(p, "xmmword ptr", 11) == 0 || strncmp(p, "ymmword ptr", 11) == 0)
        {
            const char* start = p;
            int depth = 0;
            while (*p)
            {
                if (*p == '[')
                    depth++;
                if (*p == ']')
                {
                    depth--;
                    p++;
                    if (depth <= 0)
                        break;
                    continue;
                }
                p++;
            }
            size_t m = (size_t)(p - start);
            if (m >= sizeof(toks[n].text))
                m = sizeof(toks[n].text) - 1;
            memcpy(toks[n].text, start, m);
            toks[n].text[m] = 0;
            toks[n].kind = kLyTokMem;
            n++;
            continue;
        }
        if (*p == ',' || *p == '+' || *p == '*' || *p == '-')
        {
            toks[n].kind = kLyTokOp;
            toks[n].text[0] = *p++;
            toks[n].text[1] = 0;
            n++;
            continue;
        }
        if (IsIdentChar(*p) || *p == '0')
        {
            const char* start = p;
            while (IsIdentChar(*p) || *p == 'x' || *p == 'X')
                p++;
            size_t m = (size_t)(p - start);
            if (m >= sizeof(toks[n].text))
                m = sizeof(toks[n].text) - 1;
            memcpy(toks[n].text, start, m);
            toks[n].text[m] = 0;
            if (toks[n].text[0] == '0' && (toks[n].text[1] == 'x' || toks[n].text[1] == 'X'))
                toks[n].kind = kLyTokImm;
            else if (LyLooksLikeRegister(toks[n].text))
                toks[n].kind = kLyTokReg;
            else if (strncmp(toks[n].text, "sub_", 4) == 0 || strncmp(toks[n].text, "FUN_", 4) == 0)
                toks[n].kind = kLyTokFn;
            else if (strncmp(toks[n].text, "loc_", 4) == 0)
                toks[n].kind = kLyTokLabel;
            else
                toks[n].kind = kLyTokSym;
            n++;
            continue;
        }
        toks[n].kind = kLyTokOp;
        toks[n].text[0] = *p++;
        toks[n].text[1] = 0;
        n++;
    }
    return n;
}
