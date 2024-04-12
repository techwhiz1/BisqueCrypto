#include "BisqueCrypto.h"
#include "MD159_Constants.h"
#include <intrin.h>


// Seconde table de remplissage du IV
static const uint8 g_CryptoTable1[] =
{
    // unk_2996EB2
    0xCD, 0xEF, 0x83, 0xC2, 0xC9, 0x08, 0x4B, 0xCA,
    0x4D, 0x7D, 0xD1, 0xE9, 0x6C, 0x3B, 0x15, 0xDE,
    
    // unk_2996EC2
    0x39, 0x5A, 0x93, 0x36, 0x40, 0x59, 0x99, 0x3E,
    0x5C, 0x3D, 0x4D, 0x08, 0x89, 0x9C, 0xC6, 0xFF,
    
    // unk_2996ED2
    0x82, 0x9B, 0x4F, 0x5E, 0x19, 0xE9, 0x40, 0x5A,
    0xCC, 0xFB, 0x0C, 0x13, 0x9C, 0x37, 0x45, 0x0D,
    
    // unk_2996EE2
    0x0A, 0x3E, 0xFD, 0xAD, 0x2E, 0xDD, 0xD5, 0x6E,
    0xD8, 0x6F, 0xDF, 0x83, 0x1C, 0x93, 0x05, 0xD8
};

/*
    Cette table permet de définir un nombre de tours
    relatif à la taille de la clé utilisé
*/
static const uint32 g_RoundsTable[] = {
    4, 8, 4, 10, 4, 12, 4, 14, 0
};

int64 MD159::InitializeKey(const char* pKey, uint32 keyLen)
{
    V128* v12; // x0
    V128* v13; // x25
    int v14; // w27
    __int64 v15; // x8
    int v16; // w14
    __int64 v17; // x13
    uint64 v18; // x15
    int v19; // w16
    V128* v20; // x0
    uint8 v21; // w8
    __int64 i; // x9
    char v23; // w10
    V128* v24; // x8

    V128 v25; // q1
    V128 v26; // q2
    V128 v27; // q3
    V128 v28; // q1
    V128 v29; // q2
    V128 v30; // q3
    V128 v31; // q1
    V128 v32; // q2
    V128 v33; // q3
    V128 v34; // q1
    V128 v35; // q3
    V128 v36; // q2

    uint64* v37; // x22
    uint64 j; // x8
    uint64 v39; // x10
    uint32 v40; // w9
    uint32 v41; // w16
    uint32 v42; // w12
    uint32 v43; // w15
    uint32 v44; // w8
    uint32 v45; // w17
    uint32 v46; // w13
    uint32 v47; // w14
    __int64 v48; // x0
    uint32 v49; // w8
    uint32 v50; // w9
    int v51; // w11
    uint32 v52; // w11
    __int64 v53; // x14
    uint32 v54; // w9
    __int64 v55; // x0
    __int64 k; // x10
    uint64 v57; // x11
    __int64 v58; // x0
    uint32 v59; // w8
    uint32 v60; // w9
    int v61; // w12
    char* v62; // x13
    uint32 v63; // w12
    int v64; // w15
    char* v65; // x0
    uint32 v66; // w9
    char* v67; // x14
    int v68; // w17
    char* v69; // x1
    char* v70; // x9
    int v71; // w13
    __int64 v72; // x2

    m_KeyContext = KeyContext();
    uint64* pKeyCtx = (uint64*)&m_KeyContext;
    if (!pKeyCtx)
        return 0x80000001LL;
    memset(pKeyCtx, 0, sizeof(KeyContext));


    uint64 vSz = 0;
    HIDWORD(vSz) = keyLen - 4;
    LODWORD(vSz) = keyLen - 4;
    uint32 v4 = vSz >> 2;
    if (v4 <= 7 && ((171u >> ((uint32)(keyLen - 4) >> 2)) & 1) != 0) { }
    else
        return 0x80000004LL;

    int roundsCount = g_RoundsTable[v4];
    int cryptoFlag = 0xE0000000LL; // flag par defaut

    *((DWORD*)pKeyCtx + 2) = 0x80000000;

    v12 = (V128*)malloc(16 * roundsCount + 56);
    m_KeyContext.m_Alloc0 = (void*)v12;
    memset(v12, 0, 32);

    *((DWORD*)v12 + 6) = 16 * roundsCount + 16;
    v13 = v12;
    v14 = keyLen >> 2;
    v12 = (V128*)((char*)v12 + 40);

    *((DWORD*)v13 + 4) = keyLen >> 2;
    *((DWORD*)v13 + 5) = roundsCount;
    *((V128**)v13 + 4) = v12;

    memcpy(v12, pKey, keyLen);
    if (keyLen >> 2 < 4 * roundsCount + 4)
    {
        v15 = *((uint64*)v13 + 4);
        v16 = 1;
        v17 = keyLen >> 2;

        for (;;)
        {
            v18 = *(uint32*)(v15 + 4LL * (uint32)(v17 - 1));
            v19 = v17 - (uint32)v17 / v14 * v14;
            if (v19)
            {
                if (v14 >= 7 && v19 == 4)
                    LODWORD(v18) = ((unsigned __int16)((uint8)g_SBox2[g_SBox4[(uint8)v18]] | ((uint8)g_SBox2[g_SBox4[BYTE1(v18)]] << 8)) | ((uint8)g_SBox2[g_SBox4[BYTE2(v18)]] << 16)) & 0xFFFFFF | ((uint8)g_SBox2[g_SBox4[v18 >> 24]] << 24);
            }
            else
            {
                LODWORD(v18) = (((unsigned __int16)((uint8)g_SBox2[g_SBox4[v18 >> 24]] | ((uint8)g_SBox2[g_SBox4[(uint8)v18]] << 8)) | ((uint8)g_SBox2[g_SBox4[BYTE1(v18)]] << 16)) & 0xFFFFFF | ((uint8)g_SBox2[g_SBox4[BYTE2(v18)]] << 24)) ^ v16;
                if (v16)
                    v16 = (uint8)g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v16]] + 25) % 0xFF]];
            }
            *(DWORD*)(v15 + 4 * v17) = *(DWORD*)(v15 + 4LL * (uint32)(v17 - v14)) ^ v18;
            if (++v17 >= (uint64)(uint32)(4 * *((DWORD*)v13 + 5) + 4))
                break;
            v14 = *((DWORD*)v13 + 4);
        }
    }

    pKeyCtx[2] = (uint64)v13;


    if ((cryptoFlag & 0x40000000) != 0)
    {
        *((DWORD*)pKeyCtx + 2) |= 0x40000000u;
        v20 = (V128*)malloc(544);
        m_KeyContext.m_Alloc1 = (void*)v20;
        pKeyCtx[3] = (uint64)v20;

        v20[14] = *(V128*)&g_SBox2[224];
        v20[15] = *(V128*)&g_SBox2[240];
        v20[12] = *(V128*)&g_SBox2[192];
        v20[13] = *(V128*)&g_SBox2[208];
        *((WORD*)v20 + 128) = 0;
        v20[10] = *(V128*)&g_SBox2[160];
        v20[11] = *(V128*)&g_SBox2[176];
        v20[8] = *(V128*)&g_SBox2[128];
        v20[9] = *(V128*)&g_SBox2[144];
        *((V128**)v20 + 33) = v20 + 17;
        v20[6] = *(V128*)&g_SBox2[96];
        v20[7] = *(V128*)&g_SBox2[112];
        v20[4] = *(V128*)&g_SBox2[64];
        v20[5] = *(V128*)&g_SBox2[80];
        v20[2] = *(V128*)&g_SBox2[32];
        v20[3] = *(V128*)&g_SBox2[48];
        *v20 = *(V128*)g_SBox2;
        v20[1] = *(V128*)&g_SBox2[16];

        v21 = *pKey + 66;
        *(uint8*)v20 = *((uint8*)v20 + v21);
        *((uint8*)v20 + v21) = 66;
        for (i = 1LL; i != 256; ++i)
        {
            v23 = *((uint8*)v20 + i);
            v21 += v23 + pKey[(uint32)i - (int)i / (int)keyLen * keyLen];
            *((uint8*)v20 + i) = *((uint8*)v20 + v21);
            *((uint8*)v20 + v21) = v23;
        }

        v24 = (V128*)*((uint64*)v20 + 33);

        v25 = v20[3];
        v26 = *v20;
        v27 = v20[1];
        v24[2] = v20[2];
        v24[3] = v25;
        *v24 = v26;
        v24[1] = v27;
        v28 = v20[7];
        v29 = v20[4];
        v30 = v20[5];
        v24[6] = v20[6];
        v24[7] = v28;
        v24[4] = v29;
        v24[5] = v30;
        v31 = v20[11];
        v32 = v20[8];
        v33 = v20[9];
        v24[10] = v20[10];
        v24[11] = v31;
        v24[8] = v32;
        v24[9] = v33;
        v35 = v20[13];
        v34 = v20[14];
        v36 = v20[12];
        *(V128*)((char*)v24 + 239) = *(V128*)((char*)v20 + 239);
        v24[13] = v35;
        v24[14] = v34;
        v24[12] = v36;
    }

    if ((cryptoFlag & 0x20000000) != 0)
    {
        *((DWORD*)pKeyCtx + 2) |= 0x20000000u;
        v37 = (uint64*)malloc(8336);
        m_KeyContext.m_Alloc2 = (void*)v37;

        memcpy(v37, g_CryptoTable1, sizeof(g_CryptoTable1));

        v37[8] = 0x894426A1C8BF6F09LL;
        memcpy(v37 + 9, g_CryptoTableBase, 4096);

        // initialisation de la table de chiffrement (utilisé dans le noyau de l'algorithme)
        for (j = 0LL; j != 72; j += 4LL)
            *(DWORD*)((char*)v37 + j) ^= (((uint8)pKey[j - j / keyLen * keyLen] << 24) | ((uint8)pKey[j + 1 - (j + 1) / keyLen * keyLen] << 16)) & 0xFFFF00FF | ((uint8)pKey[j + 2 - (j + 2) / keyLen * keyLen] << 8) | (uint8)pKey[j + 3 - (j + 3) / keyLen * keyLen];
        
        v39 = 0LL;
        v40 = 0;
        LOBYTE(v41) = 0;
        LOBYTE(v42) = 0;
        LOBYTE(v43) = 0;
        v44 = 0;
        LOBYTE(v45) = 0;
        LOBYTE(v46) = 0;
        LOBYTE(v47) = 0;
        do
        {
            v48 = 0LL;
            v49 = ((v44 & 0xFFFF00FF | ((uint8)v45 << 8)) & 0xFFFFFF | ((uint8)v47 << 24)) & 0xFF00FFFF | ((uint8)v46 << 16);
            v50 = ((v40 & 0xFFFF00FF | ((uint8)v41 << 8)) & 0xFFFFFF | ((uint8)v43 << 24)) & 0xFF00FFFF | ((uint8)v42 << 16);
            do
            {
                v51 = *(DWORD*)((char*)v37 + v48);
                v48 += 4LL;
                v52 = v51 ^ v49;
                v49 = (((*((DWORD*)v37 + BYTE2(v52) + 274) + *((DWORD*)v37 + HIBYTE(v52) + 18)) ^ *((DWORD*)v37
                    + BYTE1(v52)
                    + 530))
                    + *((DWORD*)v37 + (uint8)v52 + 786)) ^ v50;
                v50 = v52;
            } while (v48 != 60);
            v53 = 4 * v39;
            v39 += 2LL;
            v54 = *((DWORD*)v37 + 15) ^ v49;
            v44 = *((DWORD*)v37 + 17) ^ v54;
            v55 = v53 | 4;
            v40 = (((*((DWORD*)v37 + BYTE2(v54) + 274) + *((DWORD*)v37 + HIBYTE(v54) + 18)) ^ *((DWORD*)v37
                + BYTE1(v54)
                + 530))
                + *((DWORD*)v37 + (uint8)v54 + 786)) ^ v52 ^ *((DWORD*)v37 + 16);
            *(DWORD*)((char*)v37 + v53) = v44;
            v47 = HIBYTE(v44);
            v46 = HIWORD(v44);
            v45 = v44 >> 8;
            v43 = HIBYTE(v40);
            v42 = HIWORD(v40);
            v41 = v40 >> 8;
            *(DWORD*)((char*)v37 + v55) = v40;
        } while (v39 < 18);

        for (k = 0LL; k != 4; ++k)
        {
            v57 = 0LL;
            do
            {
                v58 = 0LL;
                v59 = ((v44 & 0xFFFF00FF | ((uint8)v45 << 8)) & 0xFFFFFF | ((uint8)v47 << 24)) & 0xFF00FFFF | ((uint8)v46 << 16);
                v60 = ((v40 & 0xFFFF00FF | ((uint8)v41 << 8)) & 0xFFFFFF | ((uint8)v43 << 24)) & 0xFF00FFFF | ((uint8)v42 << 16);
                do
                {
                    v61 = *(DWORD*)((char*)v37 + v58);
                    v62 = (char*)(v37 + 9);
                    v58 += 4LL;
                    v63 = v61 ^ v59;
                    v59 = (((*((DWORD*)v37 + BYTE2(v63) + 274) + *((DWORD*)v37 + HIBYTE(v63) + 18)) ^ *((DWORD*)v37
                        + BYTE1(v63)
                        + 530))
                        + *((DWORD*)v37 + (uint8)v63 + 786)) ^ v60;
                    v60 = v63;
                } while (v58 != 60);
                v64 = *((DWORD*)v37 + 16);
                v65 = &v62[1024 * k];
                v66 = *((DWORD*)v37 + 15) ^ v59;
                v44 = *((DWORD*)v37 + 17) ^ v66;
                v67 = &v62[4 * BYTE2(v66)];
                v68 = *(DWORD*)&v62[4 * HIBYTE(v66)];
                v69 = &v62[4 * BYTE1(v66)];
                v70 = &v62[4 * (uint8)v66];
                v71 = *((DWORD*)v67 + 256);
                LODWORD(v69) = *((DWORD*)v69 + 512);
                LODWORD(v70) = *((DWORD*)v70 + 768);
                v72 = (4 * v57) | 4;
                *(DWORD*)&v65[4 * v57] = v44;
                v57 += 2LL;
                v40 = (((v71 + v68) ^ (uint32)v69) + (DWORD)v70) ^ v63 ^ v64;
                v47 = HIBYTE(v44);
                v46 = HIWORD(v44);
                v45 = v44 >> 8;
                v43 = HIBYTE(v40);
                v42 = HIWORD(v40);
                v41 = v40 >> 8;
                *(DWORD*)&v65[v72] = v40;
            } while (v57 < 256);
        }
        pKeyCtx[4] = (uint64)v37;
    }

    return 0;
}



#pragma region(DECRYPTING)
static void DoDecryptRound159(uint8* a1)
{
    __int64 v1; // x9
    char* v2; // x10
    char v3; // w17
    char v4; // w16
    char* v5; // x17
    char* v6; // x17
    __int64 v7; // x16
    char v8; // w2
    __int64 v9; // x17
    char v10; // w3
    __int64 v11; // x1
    char v12; // w3
    char v13; // w4
    __int64 v14; // x2
    char v15; // w3
    char v16; // w4
    char v17; // w3
    char v18; // w4
    char v19; // w3
    char v20; // w4
    char v21; // w16
    uint8 v23[16]; // [xsp+8h] [xbp-18h] BYREF

    v1 = 0LL;
    v2 = (char*)a1 + 12;
    do
    {
        v6 = &v2[v1];
        v7 = *((uint8*)a1 + v1);
        if (*((uint8*)a1 + v1))
        {
            v8 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v7]] + 223) % 255]];
            v9 = (uint8)*(v6 - 8);
            if (v9)
                goto LABEL_6;
        }
        else
        {
            v8 = 0;
            v9 = (uint8)*(v6 - 8);
            if (v9)
            {
            LABEL_6:
                v10 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v9]] + 104) % 255]];
                goto LABEL_9;
            }
        }
        v10 = 0;

    LABEL_9:
        v11 = (uint8)v2[v1 - 4];
        v12 = v10 ^ v8;
        if (v2[v1 - 4])
            v13 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v11]] + 238) % 255]];
        else
            v13 = 0;
        v14 = (uint8)v2[v1];
        v15 = v12 ^ v13;
        if (v2[v1])
            v16 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v14]] + 199) % 255]];
        else
            v16 = 0;

        v23[v1] = v15 ^ v16;

        if ((DWORD)v7)
        {
            v17 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v7]] + 199) % 255]];
            if ((DWORD)v9)
                goto LABEL_17;
        }
        else
        {
            v17 = 0;
            if ((DWORD)v9)
            {
            LABEL_17:
                v17 ^= g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v9]] + 223) % 255]];
                if ((DWORD)v11)
                    goto LABEL_18;
                goto LABEL_22;
            }
        }
        if ((DWORD)v11)
        {
        LABEL_18:
            v17 ^= g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v11]] + 104) % 255]];
            if ((DWORD)v14)
                goto LABEL_19;
            goto LABEL_23;
        }

    LABEL_22:
        if ((DWORD)v14)
        {
        LABEL_19:
            v18 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v14]] + 238) % 255]];
            goto LABEL_24;
        }

    LABEL_23:
        v18 = 0;

    LABEL_24:
        v23[v1 + 4] = v17 ^ v18;
        if ((DWORD)v7)
        {
            v19 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v7]] + 238) % 255]];
            if ((DWORD)v9)
                goto LABEL_26;
        }
        else
        {
            v19 = 0;
            if ((DWORD)v9)
            {
            LABEL_26:
                v19 ^= g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v9]] + 199) % 255]];
                if ((DWORD)v11)
                    goto LABEL_27;
                goto LABEL_31;
            }
        }
        if ((DWORD)v11)
        {
        LABEL_27:
            v19 ^= g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v11]] + 223) % 255]];
            if ((DWORD)v14)
                goto LABEL_28;
            goto LABEL_32;
        }

    LABEL_31:
        if ((DWORD)v14)
        {
        LABEL_28:
            v20 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v14]] + 104) % 255]];
            goto LABEL_33;
        }

    LABEL_32:
        v20 = 0;

    LABEL_33:
        v23[v1 + 8] = v19 ^ v20;

        if ((DWORD)v7)
            LOBYTE(v7) = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v7]] + 104) % 255]];

        if ((DWORD)v9)
            LOBYTE(v9) = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v9]] + 238) % 255]];

        v21 = v9 ^ v7;
        if ((DWORD)v11)
        {
            v21 ^= g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v11]] + 199) % 255]];
            if ((DWORD)v14)
                goto LABEL_2;
        }
        else if ((DWORD)v14)
        {
        LABEL_2:
            v3 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v14]] + 223) % 255]];
            goto LABEL_3;
        }
        v3 = 0;

    LABEL_3:
        v4 = v21 ^ v3;
        v5 = (char*)(&v23[v1++]);
        v5[12] = v4;
    }
    while (v1 != 4);

    ((uint64*)a1)[0] = ((uint64*)v23)[0];
    ((uint64*)a1)[1] = ((uint64*)v23)[1];
}


/*
    Retourne le nombre de blocs de données traités
*/
int MD159::Decrypt(const uint8* data, uint32 sz, std::vector<uint8>& decrypted)
{
    // aligner sz sur 128 bits
    if (sz % 16 != 0)
        sz += (16 - (sz % 16));

    decrypted.resize(sz);
    uint8* outDecBuf = decrypted.data();

    uint8* v8; // x24
    uint8* v10; // x9
    int v11; // w10
    __int64 v12; // x12
    uint8* v13; // x14
    char v14; // w11
    uint8* v15; // x9
    __int64 v18; // x9
    __int64 v19; // x11
    __int64 v20; // x10
    __int64 v21; // x8
    __int64 v23; // x12
    __int64 v24; // x14
    char v25; // w11
    __int64 v27; // x12
    __int64 v28; // x13
    char v29; // w10
    uint8 v31[16];

    int blocksCount = -1;
    if ((sz & 0xF) == 0)
    {
        blocksCount = sz / 16;
        if ((int)(sz / 16) >= 1)
        {
            int iBlock = 0;
            v8 = *(uint8**)(((uint8*)&m_KeyContext) + 16);

            do // itère chaque bloc (sz/16)
            {
                // P-Box par bloc
                {
                    v8[0] = data[0];
                    v8[4] = data[1];
                    v8[8] = data[2];
                    v8[12] = data[3];
                    v8[1] = data[4];
                    v8[5] = data[5];
                    v8[9] = data[6];
                    v8[13] = data[7];
                    v8[2] = data[8];
                    v8[6] = data[9];
                    v8[10] = data[10];
                    v8[14] = data[11];
                    v8[3] = data[12];
                    v8[7] = data[13];
                    v8[11] = data[14];
                    v8[15] = data[15];
                }

                v11 = *((DWORD*)v8 + 5) * 4;
                for (uint32 i = 0; i < 16; i++)
                {
                    v12 = i >> 2;
                    v13 = &v8[4 * (i & 3)];
                    v14 = 8 * (i & 3);
                    v13[v12] ^= (*(DWORD*)(*((uint64*)v8 + 4) + 4LL * ((int)v12 + v11)) & (uint32)(0xFF << v14)) >> v14;
                }

                int roundIt = *((DWORD*)v8 + 5);
                for (;;)
                {
                    --roundIt;

                    // P-Box par tour
                    {
                        v31[0] = v8[0];
                        v31[5] = v8[4];
                        v31[10] = v8[8];
                        v31[15] = v8[12];
                        v31[1] = v8[1];
                        v31[6] = v8[5];
                        v31[11] = v8[9];
                        v31[12] = v8[13];
                        v31[2] = v8[2];
                        v31[7] = v8[6];
                        v31[8] = v8[10];
                        v31[13] = v8[14];
                        v31[3] = v8[3];
                        v31[4] = v8[7];
                        v31[9] = v8[11];
                        v31[14] = v8[15];
                        memcpy(v8, v31, 16);
                    }

                    v18 = (__int64)v8;

                    for (uint32 i = 0; i < 16; i++)
                    {
                        v19 = i >> 2;
                        v20 = v18 + 4LL * (i & 3);
                        *(uint8*)(v20 + v19) = g_SBox2[g_SBox0[*(uint8*)(v20 + v19)]];
                    }
                    v21 = (__int64)v8;

                    if (roundIt <= 0)
                        break;

                    for (uint32 i = 0; i != 16; i++)
                    {
                        v23 = i >> 2;
                        v24 = v21 + 4LL * (i & 3);
                        v25 = 8 * (i & 3);
                        *(uint8*)(v24 + v23) ^= (*(DWORD*)(*(uint64*)(v21 + 32) + 4LL * ((int)v23 + 4 * roundIt)) & (uint32)(0xFF << v25)) >> v25;
                    }
                    DoDecryptRound159(v8);
                }

                for (uint32 j = 0; j != 16; ++j)
                {
                    v27 = j >> 2;
                    v28 = v21 + 4LL * (j & 3);
                    v29 = 8 * (j & 3);
                    *(uint8*)(v28 + v27) ^= (*(DWORD*)(*(uint64*)(v21 + 32) + 4LL * (uint32)v27) & (uint32)(0xFF << v29)) >> v29;
                }

                outDecBuf[0] = v8[0];
                outDecBuf[1] = v8[4];
                outDecBuf[2] = v8[8];
                outDecBuf[3] = v8[12];
                outDecBuf[4] = v8[1];
                outDecBuf[5] = v8[5];
                outDecBuf[6] = v8[9];
                outDecBuf[7] = v8[13];
                outDecBuf[8] = v8[2];
                outDecBuf[9] = v8[6];
                outDecBuf[10] = v8[10];
                outDecBuf[11] = v8[14];
                outDecBuf[12] = v8[3];
                outDecBuf[13] = v8[7];
                outDecBuf[14] = v8[11];
                outDecBuf[15] = v8[15];
                
                data += 16;
                outDecBuf += 16;
                iBlock++;
            } while (iBlock != blocksCount);
        }
    }

    return blocksCount;
}



static DWORD* __fastcall DecryptBlockMD144(DWORD* result, unsigned int* a2, BYTE* a3)
{
    unsigned __int64 v3; // x11
    int v4; // w10
    unsigned int v5; // w12
    int v6; // w8
    DWORD* v7; // x9
    unsigned int v8; // w8
    int v9; // w13
    unsigned int v10; // w10
    int v11; // w12
    int v12; // w11
    int v13; // w14
    int v14; // w15
    int v15; // w9
    int v16; // w8

    v3 = 17LL;
    v4 = bswap32(*a2);
    v5 = bswap32(a2[1]);
    do
    {
        v6 = result[v3];
        v7 = result + 18;
        --v3;
        v8 = v6 ^ v4;
        v4 = (((result[BYTE2(v8) + 274] + result[HIBYTE(v8) + 18]) ^ result[BYTE1(v8) + 530])
            + result[(unsigned __int8)v8 + 786]) ^ v5;
        v5 = v8;
    } while (v3 > 2);
    v9 = result[1];
    v10 = result[2] ^ v4;
    v11 = *result ^ v10;
    v12 = v7[HIBYTE(v10)];
    v13 = v7[BYTE2(v10) + 256];
    v14 = v7[BYTE1(v10) + 512];
    v15 = v7[(unsigned __int8)v10 + 768];
    *a3 = HIBYTE(v11);
    a3[1] = BYTE2(v11);
    a3[2] = BYTE1(v11);
    v16 = (((v13 + v12) ^ v14) + v15) ^ v8 ^ v9;
    a3[3] = v11;
    a3[4] = HIBYTE(v16);
    a3[5] = BYTE2(v16);
    a3[6] = BYTE1(v16);
    a3[7] = v16;
    return result;
}


int MD159::DecryptMD144(const uint8* data, uint32 sz, std::vector<uint8>& decrypted)
{
    // aligner sz sur 64 bits
    if (sz % 8 != 0)
        sz += (8 - (sz % 8));

    decrypted.resize(sz);

    uint64 v4;
    uint32* a2 = (uint32*)data;
    BYTE* a3 = (BYTE*)decrypted.data();

    if ((sz & 7) != 0)
    {
        LODWORD(v4) = -1;
    }
    else
    {
        v4 = sz >> 3;
        if ((int)(sz >> 3) >= 1)
        {
            int v8 = sz >> 3;
            do
            {
                DecryptBlockMD144(*(DWORD**)(((uint8*)&m_KeyContext) + 32), a2, a3);
                a2 += 2;
                --v8;
                a3 += 8;
            } while (v8);
        }
    }
    return (unsigned int)v4;
}

int MD159::DecryptMD40S(const uint8* data, uint32 size, std::vector<uint8>& decrypted)
{
    __int64 v4; // x8
    __int64 v5; // x9
    char v6; // w11
    unsigned __int8 v7; // w10
    unsigned __int8 v8; // w11
    char v9; // w13
    char v10; // t1
    __int64 v11; // x10
    __m128i* v12; // x11
    __m128i v13; // q1
    __m128i v14; // q2
    __m128i v15; // q3
    __m128i v16; // q1
    __m128i v17; // q2
    __m128i v18; // q3
    __m128i v19; // q1
    __m128i v20; // q2
    __m128i v21; // q3
    __m128i v22; // q1
    __m128i v23; // q3
    __m128i v24; // q2

    if (size)
    {
        decrypted.resize(size);
        uint8* pBufOut = decrypted.data();

        v4 = *(QWORD*)(((uint8*)&m_KeyContext) + 24);
        v5 = size;
        do
        {
            if (*(unsigned __int8*)(v4 + 256) == 255)
            {
                v11 = *(QWORD*)(((uint8*)&m_KeyContext) + 24);
                v12 = *(__m128i**)(v11 + 264);
                *(WORD*)(v11 + 256) = 0;
                v13 = v12[11];
                v14 = v12[8];
                v15 = v12[9];
                _mm_storeu_si128((__m128i*)(v11 + 160), v12[10]);
                _mm_storeu_si128((__m128i*)(v11 + 176), v13);
                _mm_storeu_si128((__m128i*)(v11 + 128), v14);
                _mm_storeu_si128((__m128i*)(v11 + 144), v15);
                v16 = v12[7];
                v17 = v12[4];
                v18 = v12[5];
                _mm_storeu_si128((__m128i*)(v11 + 96), v12[6]);
                _mm_storeu_si128((__m128i*)(v11 + 112), v16);
                _mm_storeu_si128((__m128i*)(v11 + 64), v17);
                _mm_storeu_si128((__m128i*)(v11 + 80), v18);
                v19 = v12[3];
                v20 = *v12;
                v21 = v12[1];
                _mm_storeu_si128((__m128i*)(v11 + 32), v12[2]);
                _mm_storeu_si128((__m128i*)(v11 + 48), v19);
                _mm_storeu_si128((__m128i*)v11, v20);
                _mm_storeu_si128((__m128i*)(v11 + 16), v21);
                v23 = v12[13];
                v22 = v12[14];
                v24 = v12[12];
                _mm_storeu_si128((__m128i*)(v11 + 239), *(__m128i*)((char*)v12 + 239));
                _mm_storeu_si128((__m128i*)(v11 + 208), v23);
                _mm_storeu_si128((__m128i*)(v11 + 224), v22);
                _mm_storeu_si128((__m128i*)(v11 + 192), v24);
            }
            v6 = *(BYTE*)(v4 + 257);
            --v5;
            v7 = *(BYTE*)(v4 + 256) + 1;
            *(BYTE*)(v4 + 256) = v7;
            v8 = v6 + *(BYTE*)(v4 + v7);
            *(BYTE*)(v4 + 257) = v8;
            v9 = *(BYTE*)(v4 + v7);
            *(BYTE*)(v4 + v7) = *(BYTE*)(v4 + v8);
            *(BYTE*)(v4 + v8) = v9;
            v10 = *data++;
            *pBufOut++ = *(BYTE*)(v4
                + (unsigned __int8)(*(BYTE*)(v4 + *(unsigned __int8*)(v4 + 257))
                    + *(BYTE*)(v4 + *(unsigned __int8*)(v4 + 256)))) ^ v10;
        } while (v5);
    }
    return 0;
}
#pragma endregion





#pragma region(ENCRYPTING)
static void DoEncryptRoundMD128(uint8* pBuf)
{
    char v3; // w16
    char* v4; // x1
    uint8* v5; // x16
    int64 v6; // x17
    char v7; // w3
    int64 v8; // x16
    char v9; // w4
    int64 v10; // x1
    int64 v11; // x2
    char v12; // w3
    int v13; // w4
    int v14; // w5
    uint32 v15; // w6
    char v16; // w4
    char v17; // w5
    char v18; // w4
    char v19; // w5
    uint8 v21[16]; // [xsp+8h] [xbp-18h] BYREF

    int64 v1 = 0LL;
    uint8* v2 = pBuf + 12;
    do
    {
        v5 = &v2[v1];
        v6 = pBuf[v1];
        if (pBuf[v1])
        {
            v7 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v6]] + 25) % 0xFF]];
            v8 = (uint8)*(v5 - 8);
            if (v8)
                goto LABEL_5;
        }
        else
        {
            v7 = 0;
            v8 = (uint8)*(v5 - 8);
            if (v8)
            {
            LABEL_5:
                v9 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v8]] + 1) % 0xFF]];
                goto LABEL_8;
            }
        }
        v9 = 0;

    LABEL_8:
        v10 = (uint8)v2[v1 - 4];
        v11 = (uint8)v2[v1];
        v21[v1] = v9 ^ v7 ^ v10 ^ v11;

        if ((DWORD)v8)
        {
            v12 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v8]] + 25) % 0xFF]] ^ v6;
            if ((DWORD)v10)
                goto LABEL_10;
        }
        else
        {
            v12 = v6;
            if ((DWORD)v10)
            {
            LABEL_10:
                v13 = (uint8)g_SBox2[g_SBox1[v10]];
                v14 = v13 + 1;
                v15 = (v13 + 1) / 0xFFu;
                v16 = g_SBox2[g_SBox3[(v13 + 25) % 0xFFu]];
                v17 = v12 ^ v11 ^ g_SBox2[g_SBox3[v14 - 255 * v15]];
                goto LABEL_13;
            }
        }
        v16 = 0;
        v17 = v12 ^ v11;

    LABEL_13:
        v18 = v8 ^ v6 ^ v16;
        v21[v1 + 4] = v17;

        if ((DWORD)v11)
            v19 = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v11]] + 1) % 0xFF]];
        else
            v19 = 0;

        v21[v1 + 8] = v18 ^ v19;

        if ((DWORD)v6)
            LOBYTE(v6) = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v6]] + 1) % 0xFF]];

        if ((DWORD)v11)
            LOBYTE(v11) = g_SBox2[g_SBox3[((uint32)(uint8)g_SBox2[g_SBox1[v11]] + 25) % 0xFF]];

        v3 = v10 ^ v8;
        v4 = (char*)(&v21[v1++]);
        v4[12] = v3 ^ v6 ^ v11;
    } while (v1 != 4);

    ((uint64*)pBuf)[0] = ((uint64*)v21)[0];
    ((uint64*)pBuf)[1] = ((uint64*)v21)[1];
}

int MD159::Encrypt(const uint8* data, uint32 size, std::vector<uint8>& encrypted)
{
    // aligner sz sur 128 bits
    if (size % 16 != 0)
        size += (16 - (size % 16));

    encrypted.resize(size);
    uint8* outEncBuf = encrypted.data();
    memset(outEncBuf, 0, size);

    uint64 blockCount; // x19
    int blockIterator = 0; // w23
    uint8* v8; // x24
    __int64 v11; // x12
    uint8* v12; // x13
    char v13; // w10
    uint8* v15; // x9
    uint32 v16; // w10
    __int64 v18; // x12
    uint8* v19; // x11
    __int64 v23; // x12
    uint8* v24; // x14
    char v25; // w11
    __int64 v28; // x11
    uint8* v29; // x13
    char v30; // w10
    uint8 v32[16]; // [xsp+8h] [xbp-68h]

    uint64 sz = size;
    if ((sz & 0xF) != 0)
    {
        LODWORD(blockCount) = -1;
    }
    else
    {
        blockCount = sz >> 4;
        if ((int)(sz >> 4) >= 1)
        {
            v8 = *(uint8**)(((uint8*)&m_KeyContext) + 16);

            do
            {
                v8[0] = data[0];
                v8[4] = data[1];
                v8[8] = data[2];
                v8[12] = data[3];
                v8[1] = data[4];
                v8[5] = data[5];
                v8[9] = data[6];
                v8[13] = data[7];
                v8[2] = data[8];
                v8[6] = data[9];
                v8[10] = data[10];
                v8[14] = data[11];
                v8[3] = data[12];
                v8[7] = data[13];
                v8[11] = data[14];
                v8[15] = data[15];

                for (uint32 i = 0; i != 16; i++)
                {
                    v11 = i >> 2;
                    v12 = &v8[4 * (i & 3)];
                    v13 = 8 * (i & 3);
                    v12[v11] ^= (*(DWORD*)(*((QWORD*)v8 + 4) + 4LL * (uint32)v11) & (uint32)(255 << v13)) >> v13;
                }

                for (int iRound = 1;; iRound++)
                {
                    int roundCount = *((DWORD*)v8 + 5);

                    for (uint32 i = 0; i != 16; i++)
                    {
                        v18 = i >> 2;
                        v19 = &v8[4 * (i & 3)];
                        v19[v18] = g_SBox2[g_SBox4[(uint8)v19[v18]]];
                    }

                    v32[0] = v8[0];
                    v32[4] = v8[5];
                    v32[8] = v8[10];
                    v32[12] = v8[15];
                    v32[1] = v8[1];
                    v32[5] = v8[6];
                    v32[9] = v8[11];
                    v32[13] = v8[12];
                    v32[2] = v8[2];
                    v32[6] = v8[7];
                    v32[10] = v8[8];
                    v32[14] = v8[13];
                    v32[3] = v8[3];
                    v32[7] = v8[4];
                    v32[11] = v8[9];
                    v32[15] = v8[14];

                    *(V128*)v8 = *(V128*)v32;

                    if (iRound >= roundCount)
                        break;

                    DoEncryptRoundMD128(v8);

                    for (uint32 i = 0; i != 16; i++)
                    {
                        v23 = i >> 2;
                        v24 = &v8[4 * (i & 3)];
                        v25 = 8 * (i & 3);
                        v24[v23] ^= (*(DWORD*)(*((QWORD*)v8 + 4) + 4LL * ((int)v23 + 4 * iRound)) & (uint32)(255 << v25)) >> v25;
                    }
                }

                int v27 = 4 * *((DWORD*)v8 + 5);
                for (uint32 i = 0; i != 16; i++)
                {
                    v28 = i >> 2;
                    v29 = &v8[4 * (i & 3)];
                    v30 = 8 * (i & 3);
                    v29[v28] ^= (*(DWORD*)(*((QWORD*)v8 + 4) + 4LL * ((int)v28 + v27)) & (uint32)(255 << v30)) >> v30;
                }

                outEncBuf[0] = v8[0];
                outEncBuf[1] = v8[4];
                outEncBuf[2] = v8[8];
                outEncBuf[3] = v8[12];
                outEncBuf[4] = v8[1];
                outEncBuf[5] = v8[5];
                outEncBuf[6] = v8[9];
                outEncBuf[7] = v8[13];
                outEncBuf[8] = v8[2];
                outEncBuf[9] = v8[6];
                outEncBuf[10] = v8[10];
                outEncBuf[11] = v8[14];
                outEncBuf[12] = v8[3];
                outEncBuf[13] = v8[7];
                outEncBuf[14] = v8[11];
                outEncBuf[15] = v8[15];

                outEncBuf += 16;
                data += 16;
                blockIterator++;
            } while (blockIterator != (DWORD)blockCount);
        }
    }

    return (uint32)blockCount;
}
#pragma endregion
