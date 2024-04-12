#include "BisqueCrypto.h"

static const std::string b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static inline bool IsBase64(BYTE c) { return (isalnum(c) || (c == '+') || (c == '/')); }

std::vector<uint8> RB64Decode(const char* data)
{
    std::vector<uint8> out;

    std::string in(data);
    for (auto& i : in)
    {
        switch (i)
        {
        case '_':
            i = '=';
            break;
        case '.':
            i = '+';
            break;
        case ',':
            i = '/';
            break;
        }
    }

    uint8 arr4[4];
    uint8 arr3[3];
    int iMod4 = 0;
    int rest = in.size();

    for (int i = 0; rest && (in[i] != '=') && IsBase64(in[i]); rest--, i++)
    {
        arr4[iMod4++] = in[i];
        if (iMod4 == 4)
        {
            for (int x = 0; x < 4; x++)
                arr4[x] = b64_chars.find(arr4[x]);

            arr3[0] = (arr4[0] << 2) + ((arr4[1] & 0x30) >> 4);
            arr3[1] = ((arr4[1] & 0xf) << 4) + ((arr4[2] & 0x3c) >> 2);
            arr3[2] = ((arr4[2] & 0x3) << 6) + arr4[3];

            for (int x = 0; x < 3; x++)
                out.push_back(arr3[x]);

            iMod4 = 0;
        }
    }

    if (iMod4)
    {
        for (int j = iMod4; j < 4; j++)
            arr4[j] = 0;

        for (int j = 0; j < 4; j++)
            arr4[j] = b64_chars.find(arr4[j]);

        arr3[0] = (arr4[0] << 2) + ((arr4[1] & 0x30) >> 4);
        arr3[1] = ((arr4[1] & 0xf) << 4) + ((arr4[2] & 0x3c) >> 2);
        arr3[2] = ((arr4[2] & 0x3) << 6) + arr4[3];

        for (int j = 0; j < (iMod4 - 1); j++)
            out.push_back(arr3[j]);
    }

    return out;
}


std::string RB64Encode(const uint8* buf, uint32 bufLen)
{
    std::string ret;
    int i = 0;
    int j = 0;
    uint8 arr3[3];
    uint8 arr4[4];

    for (; bufLen--;)
    {
        arr3[i++] = *(buf++);
        if (i == 3) {
            arr4[0] = (arr3[0] & 0xfc) >> 2;
            arr4[1] = ((arr3[0] & 0x03) << 4) + ((arr3[1] & 0xf0) >> 4);
            arr4[2] = ((arr3[1] & 0x0f) << 2) + ((arr3[2] & 0xc0) >> 6);
            arr4[3] = arr3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += b64_chars[arr4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            arr3[j] = 0x00;

        arr4[0] = (arr3[0] & 0xfc) >> 2;
        arr4[1] = ((arr3[0] & 0x03) << 4) + ((arr3[1] & 0xf0) >> 4);
        arr4[2] = ((arr3[1] & 0x0f) << 2) + ((arr3[2] & 0xc0) >> 6);
        arr4[3] = arr3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += b64_chars[arr4[j]];

        for (; i++ < 3;)
            ret += '=';
    }

    for (auto& i : ret)
    {
        switch (i)
        {
        case '=':
            i = '_';
            break;
        case '+':
            i = '.';
            break;
        case '/':
            i = ',';
            break;
        }
    }

    return ret;
}