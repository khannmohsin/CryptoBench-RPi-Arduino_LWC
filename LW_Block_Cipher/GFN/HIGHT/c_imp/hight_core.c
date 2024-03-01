#include "hight.h"

/* Generate Encryption Key and Encryption Function */

void encKeySchedule(u8 enc_WK[8], u8 enc_SK[128], const u8 MK[16]) {
    i32 i, j;
    
    // Generate whitening keys using direct assignments instead of loop
    enc_WK[0] = MK[12];
    enc_WK[1] = MK[13];
    enc_WK[2] = MK[14];
    enc_WK[3] = MK[15];
    enc_WK[4] = MK[0];
    enc_WK[5] = MK[1];
    enc_WK[6] = MK[2];
    enc_WK[7] = MK[3];

    // u8 delta[128] = { 0x00, };
    // u8 state = 0b01011010; // 0x5a

    // delta[0] = state;
    
    // // Generate δ array and subkeys without s array
    // for (i = 1; i < 128; i++) {
    //     bool new_bit = ((delta[i-1] >> 3) & 0x01) ^ (delta[i-1] & 0x01);
    //     state = (u8)(new_bit << 7) | (u8)(delta[i-1] & 0x7F);
    //     state >>= 1;

    //     // Assign the new value to delta[i] using the updated state
    //     delta[i] = state & 0x7F;
    // }


    // u8 delta[128] = { 0x00, };

    // u8 s[134] = { 0, 1, 0, 1, 1, 0, 1 };
    // delta[0] = (s[6] << 6) | (s[5] << 5) | (s[4] << 4) |
    //            (s[3] << 3) | (s[2] << 2) | (s[1] << 1) | s[0];
    // printf("0x%02xU, ", delta[0]);
    // // Generate δ array and subkeys
    // for (i = 1; i < 128; i++) {
    //     s[i + 6] = s[i + 2] ^ s[i - 1]; // XOR operation
    //     delta[i] = (s[i + 6] << 6) | (s[i + 5] << 5) | (s[i + 4] << 4) |
    //                (s[i + 3] << 3) | (s[i + 2] << 2) | (s[i + 1] << 1) | s[i];
    //     if (i % 8 == 0) puts("");
    //     printf("0x%02xU, ", delta[i]);
    // } puts("");

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++)
            enc_SK[16 * i + j + 0] = MK[((j - i) & 7) + 0] + delta_table[16 * i + j + 0];
        for (j = 0; j < 8; j++)
            enc_SK[16 * i + j + 8] = MK[((j - i) & 7) + 8] + delta_table[16 * i + j + 8];
    }

    // for (i = 0; i < 8; i++) {
    //     for (j = 0; j < 8; j++) {
    //         printf("%x, %d\n", j-i, (j-i) & 7);
    //         enc_SK[16 * i + j + 0] = MK[((j - i) & 7) + 0] + delta[16 * i + j + 0];
    //     }
    //     puts("");
    //     for (j = 0; j < 8; j++) {
    //         printf("%d, %d\n", j-i + 8, ((j-i) & 7) + 8);
    //         enc_SK[16 * i + j + 8] = MK[((j - i) & 7) + 8] + delta[16 * i + j + 8];
    //     }
    //     puts("");
    //     puts("==================================================================");
    // }

}

void HIGHT_Encrypt(u8 dst[8], const u8 src[8], const u8 MK[16]) {
    u8 WK[8] = {
        MK[12], MK[13], MK[14], MK[15],
        MK[ 0], MK[ 1], MK[ 2], MK[ 3]
    };
    u8 SK[128];
    // WK[0] = MK[12];
    // WK[1] = MK[13];
    // WK[2] = MK[14];
    // WK[3] = MK[15];
    // WK[4] = MK[0];
    // WK[5] = MK[1];
    // WK[6] = MK[2];
    // WK[7] = MK[3];

    // u8 delta[128] = { 0x00, };
    // u8 rCon = 0x5a; // 0b01011010

    // delta[0] = rCon;
    
    // // Generate δ array and subkeys without s array
    // for (i32 i = 1; i < 128; i++) {
    //     bool new_bit = ((delta[i-1] >> 3) & 0x01) ^ (delta[i-1] & 0x01);
    //     rCon = (u8)(new_bit << 7) | (u8)(delta[i-1] & 0x7F);
    //     rCon >>= 1;

    //     // Assign the new value to delta[i] using the updated state
    //     delta[i] = rCon & 0x7F;
    // }

    for (u8 i = 0; i < 8; i++) {
        for (u8 j = 0; j < 8; j++)
            SK[16 * i + j + 0] = MK[((j - i) & 7) + 0] + delta_table[16 * i + j + 0];
        for (u8 j = 0; j < 8; j++)
            SK[16 * i + j + 8] = MK[((j - i) & 7) + 8] + delta_table[16 * i + j + 8];
    }

    u8 state[8];
    memcpy(state, src, 8);
    
    state[0] += WK[0];
    state[2] ^= WK[1];
    state[4] += WK[2];
    state[6] ^= WK[3];
    // printf("Initial  = ");
    // for(int i = 7; i >= 0; i--) {
    //     printf("%02x", state[i]);
    // } puts("");
    
    // Assume F0 and F1 are already optimized and inlined
    for (u8 i = 0; i < 31; i++) {
        // if (i) {
        // printf("Round %02d = ", i);  
        //     for(int i = 7; i >= 0; i--) {
        //         printf("%02x", state[i]);
        //     } puts("");
        // }
        u8 t0 = state[7], t1 = state[6];
        state[7] = state[6];
        state[6] = state[5] + (F1(state[4]) ^ SK[i * 4 + 2]);
        state[5] = state[4];
        state[4] = state[3] ^ (F0(state[2]) + SK[i * 4 + 1]);
        state[3] = state[2];
        state[2] = state[1] + (F1(state[0]) ^ SK[i * 4 + 0]);
        state[1] = state[0];
        state[0] = t0       ^ (F0(t1      ) + SK[i * 4 + 3]);
    }
   
    // printf("Round 31 = ");  
    // for(int i = 7; i >= 0; i--) {
    //     printf("%02x", state[i]);
    // } puts("");

    state[1] += (F1(state[0]) ^ SK[124]);
    state[3] ^= (F0(state[2]) + SK[125]);
    state[5] += (F1(state[4]) ^ SK[126]);
    state[7] ^= (F0(state[6]) + SK[127]);

    // printf("Round 32 = ");  
    // for(int i = 7; i >= 0; i--) {
    //     printf("%02x", state[i]);
    // } puts("");

    state[0] += WK[4];
    state[2] ^= WK[5];
    state[4] += WK[6];
    state[6] ^= WK[7];
    
    // printf("CT = ");  
    // for(int i = 7; i >= 0; i--) {
    //     printf("%02x", state[i]);
    // } puts("");

    memcpy(dst, state, 8);
}

/* Generate Decryption Key and Decryption Function */

void decKeySchedule(u8 dec_WK[8], u8 dec_SK[128], const u8 MK[16]) {
    i32 i, j;
    
    // Generate whitening keys using direct assignments instead of loop
    dec_WK[0] = MK[12];
    dec_WK[1] = MK[13];
    dec_WK[2] = MK[14];
    dec_WK[3] = MK[15];
    dec_WK[4] = MK[0];
    dec_WK[5] = MK[1];
    dec_WK[6] = MK[2];
    dec_WK[7] = MK[3];

    // u8 delta[128] = { 0x00, };
    // u8 state = 0b01011010; // 0x5a

    // delta[0] = state;
    
    // // Generate δ array and subkeys without s array
    // for (i = 1; i < 128; i++) {
    //     u8 new_bit = ((delta[i-1] >> 3) & 0x01) ^ (delta[i-1] & 0x01);
    //     state = (u8)(new_bit << 7) | (u8)(delta[i-1] & 0x7F);
    //     state >>= 1;

    //     // Assign the new value to delta[i] using the updated state
    //     delta[i] = state & 0x7F;
    // }

    for (i = 7; i >= 0; i--) {
        for (j = 7; j >= 0; j--)
            dec_SK[127 - (16 * i + j + 8)] = MK[((j - i) & 7) + 8] + delta_table[16 * i + j + 8];
        for (j = 7; j >= 0; j--)
            dec_SK[127 - (16 * i + j + 0)] = MK[((j - i) & 7) + 0] + delta_table[16 * i + j + 0];
    }
}

void HIGHT_Decrypt(u8 dst[8], const u8 src[8], const u8 MK[16]) {
    u8 WK[8] = {
        MK[12], MK[13], MK[14], MK[15],
        MK[ 0], MK[ 1], MK[ 2], MK[ 3]
    };
    
    u8 SK[128];
    // decKeySchedule(WK, SK, MK);

    // WK[0] = MK[12];
    // WK[1] = MK[13];
    // WK[2] = MK[14];
    // WK[3] = MK[15];
    // WK[4] = MK[0];
    // WK[5] = MK[1];
    // WK[6] = MK[2];
    // WK[7] = MK[3];

    // u8 delta[128] = { 0x00, };
    // u8 rCon = 0x5a;

    // delta[0] = rCon;
    
    // // Generate δ array and subkeys without s array
    // for (u8 i = 1; i < 128; i++) {
    //     u8 new_bit = ((delta[i-1] >> 3) & 0x01) ^ (delta[i-1] & 0x01);
    //     rCon = (u8)(new_bit << 7) | (u8)(delta[i-1] & 0x7F);
    //     rCon >>= 1;

    //     // Assign the new value to delta[i] using the updated state
    //     delta[i] = rCon & 0x7F;
    // }

    for (i8 i = 7; i >= 0; i--) {
        for (i8 j = 7; j >= 0; j--)
            SK[127 - (16 * i + j + 8)] = MK[((j - i) & 7) + 8] + delta_table[16 * i + j + 8];
        for (i8 j = 7; j >= 0; j--)
            SK[127 - (16 * i + j + 0)] = MK[((j - i) & 7) + 0] + delta_table[16 * i + j + 0];
    }

    u8 state[8] = { 0x00, };
    memcpy(state, src, 8);
    state[0] -= WK[4];
    state[2] ^= WK[5];
    state[4] -= WK[6];
    state[6] ^= WK[7];

    state[1] -= (F1(state[0]) ^ SK[3]); // SK[127- 124]
    state[3] ^= (F0(state[2]) + SK[2]); // SK[127- 125]
    state[5] -= (F1(state[4]) ^ SK[1]); // SK[127- 126]
    state[7] ^= (F0(state[6]) + SK[0]); // SK[127- 127]

    for (i8 i = 1; i < 32; i++) {
        u8 temp0 = state[0];
        u8 temp2 = state[2];
        u8 temp4 = state[4];
        u8 temp6 = state[6];

        state[0] = state[1];
        state[2] = state[3];
        state[4] = state[5];
        state[6] = state[7];

        state[7] = temp0 ^ (F0(state[7]) + SK[i * 4 + 0]);
        state[5] = temp6 - (F1(state[5]) ^ SK[i * 4 + 1]);
        state[3] = temp4 ^ (F0(state[3]) + SK[i * 4 + 2]);
        state[1] = temp2 - (F1(state[1]) ^ SK[i * 4 + 3]);
    }

    state[0] -= WK[0];
    state[2] ^= WK[1];
    state[4] -= WK[2];
    state[6] ^= WK[3];
    
    memcpy(dst, state, 8);
}

/* == Development Version ======================================================== */

void keySchedule_Dev(u8 WK[8], u8 SK[128], const u8 MK[16]) {
    u8 i = 0;
    u8 n = 0;
    
    u8 buffer[16], temp[8];
    memcpy(buffer, MK, 16);
    for (int k = 0; k < 16; k++)
        printf("%02x:", buffer[k]);
    printf("\n");

    // Generate whitening keys
    for (i = 0; i < 4; i++)
        WK[i] = MK[i + 12];
    for (i = 4; i < 8; i++)
        WK[i] = MK[i - 4];

    // Initialize s array
    u8 s[134]; // 7 + 127
    s[0] = 0; s[1] = 1; s[2] = 0; s[3] = 1; s[4] = 1; s[5] = 0; s[6] = 1;

    u8 delta = (0 << 7) |
               (s[6] << 6) |
               (s[5] << 5) |
               (s[4] << 4) |
               (s[3] << 3) |
               (s[2] << 2) |
               (s[1] << 1) |
               (s[0] << 0);

    // Generate δ array and subkeys
    for (i = 0; i < 128; i++) {
        if (i > 0) {
            s[i + 6] = s[i + 2] ^ s[i - 1]; // XOR operation for s_{i+6}
            delta = (0 << 7) |
                    (s[i + 6] << 6) |
                    (s[i + 5] << 5) |
                    (s[i + 4] << 4) |
                    (s[i + 3] << 3) |
                    (s[i + 2] << 2) |
                    (s[i + 1] << 1) |
                    (s[i + 0] << 0);
        }
        // printf("%u: %02x\n", i, delta);

        n = i / 16;
        u8 shift = 1;
        if (i % 16 == 0 && n > 0) {
            // // Rotate the first 8-byte segment
            // memcpy(temp, buffer + n, 8 - n);
            // memmove(buffer + 8 - n, buffer, n);
            // memcpy(buffer, temp, 8 - n);

            // Right rotate the first 8-byte segment
            memcpy(temp, buffer + 8 - shift, shift); // Store the last n bytes of the first segment
            memmove(buffer + shift, buffer, 8 - shift); // Shift the first (8-n) bytes to the right
            memcpy(buffer, temp, shift); // Move the last n bytes to the beginning


            printf("\n\n%d\nFRONT; %u:\n", n, i);
            for (int k = 0; k < 16; k++) {
                if (k == 8) printf(" | ");
                printf("%02x:", buffer[k]);
            }
            printf("\n==============================================================\n");

            // // Rotate the second 8-byte segment
            // memcpy(temp, buffer + 8 + n, 8 - n);
            // memmove(buffer + 16 - n, buffer + 8, n);
            // memcpy(buffer + 8, temp, 8 - n);

            // Right rotate the second 8-byte segment
            memcpy(temp, buffer + 16 - shift, shift); // Store the last n bytes of the second segment
            memmove(buffer + 8 + shift, buffer + 8, 8 - shift); // Shift the first (8-n) bytes of the second segment to the right
            memcpy(buffer + 8, temp, shift); // Move the last n bytes to the beginning of the second segment

            printf(" BACK; %u:\n", i);
            for (int k = 0; k < 16; k++) {
                if (k == 8) printf(" | ");
                printf("%02x:", buffer[k]);
            }
            printf("\n==============================================================\n");
        }
        
        SK[i] = buffer[i % 16] + delta;
        printf("SK[%03d] = %02x = %02x + %02x\n", i, SK[i], buffer[i % 16], delta);

    }

#if 0
    u8 buffer[16], temp;
    memcpy(buffer, MK, 16);

    // Generate whitening keys using direct assignments instead of loop
    WK[0] = buffer[12];
    WK[1] = buffer[13];
    WK[2] = buffer[14];
    WK[3] = buffer[15];
    WK[4] = buffer[0];
    WK[5] = buffer[1];
    WK[6] = buffer[2];
    WK[7] = buffer[3];

    // Initialize s array with direct assignments
    u8 s[134] = {0, 1, 0, 1, 1, 0, 1};

    u8 delta = (s[6] << 6) | (s[5] << 5) | (s[4] << 4) |
               (s[3] << 3) | (s[2] << 2) | (s[1] << 1) | s[0];

    for (u8 i = 0; i < 128; ++i) {
        if (i > 0) {
            s[i + 6] = s[i + 2] ^ s[i - 1]; // XOR operation
            delta = (s[i + 6] << 6) | (s[i + 5] << 5) | (s[i + 4] << 4) |
                    (s[i + 3] << 3) | (s[i + 2] << 2) | (s[i + 1] << 1) | s[i];
        }

        u8 n = i % 16;
        if (n == 0 && i > 15) {
            // Simplified rotations with bitwise operations and avoiding memcpy/memmove
            temp = buffer[7];
            for (u8 j = 7; j > 0; j--) buffer[j] = buffer[j - 1];
            buffer[0] = temp;

            temp = buffer[15];
            for (u8 j = 15; j > 8; j--) buffer[j] = buffer[j - 1];
            buffer[8] = temp;
        }
        
        SK[i] = buffer[n] + delta;
    }
#endif
}

void HIGHT_Encrypt_Dev(u8 dst[8], const u8 src[8], const u8 MK[16]) {
    for (int i = 15; i >= 0; --i)
        printf("%02x:", MK[i]);
    printf("\n\n");
    
    u8 WK[8], SK[128];
    encKeySchedule(WK, SK, MK);

    for(int i = 7; i >= 0; --i)
        printf("%02x:", WK[i]);
    printf("\n\n");

    for(int i = 7; i >= 0; --i)
        printf("%02x:", src[i]);
    printf("\n\n");

    for (int i = 0; i < 32; i++) {
        printf("SK[%03d]||SK[%03d]||SK[%03d]||SK[%03d]: %02x%02x%02x%02x\n",
            4*i+3, 4*i+2, 4*i+1, 4*i, SK[4*i+3], SK[4*i+2], SK[4*i+1], SK[4*i]);
    }
    printf("\n\n");

    // u8 state[8] = {
    //     src[7], src[6] ^ WK[3],
    //     src[5], src[4] + WK[2],
    //     src[3], src[2] ^ WK[1],
    //     src[1], src[0] + WK[0]
    // };

    u8 state[8] = {
        src[0] + WK[0], src[1],
        src[2] ^ WK[1], src[3],
        src[4] + WK[2], src[5],
        src[6] ^ WK[3], src[7]
    };

    // printf("Initial:\n");
    // for (int i = 7; i >= 0; --i)
    //     printf("%02x:", state[i]);
    // puts("");

    u8 temp, temp2;
    for (u8 i = 0; i < 31; i++) {
        // if (i == 31) {
        //     printf("Error!\n");
        //     printf("Internal1 Round 32 | ");
        //     for (int i = 7; i >= 0; --i)
        //         printf("%02x:", state[i]);
        //     puts("");
        //     state[7] ^= (F0(state[6] + SK[127]));
        //     state[5] += (F1(state[4] ^ SK[126]));
        //     state[3] ^= (F0(state[2] + SK[125]));
        //     state[1] += (F1(state[0] ^ SK[124]));
        //     printf("Internal2 Round 32 | ");
        //     for (int i = 7; i >= 0; --i)
        //         printf("%02x:", state[i]);
        //     puts("");
        //     break;
        //     printf("Error!!\n");
        // }

        printf("Round %02d | ", i);
        for (int i = 7; i >= 0; --i)
            printf("%02x:", state[i]);
        puts("");
        
        temp = state[7];
        temp2 = state[6];

        state[7] = state[6];
        state[6] = state[5] + (F1(state[4]) ^ SK[i * 4 + 2]);

        state[5] = state[4];
        state[4] = state[3] ^ (F0(state[2]) + SK[i * 4 + 1]);

        state[3] = state[2]; 
        state[2] = state[1] + (F1(state[0]) ^ SK[i * 4 + 0]);

        state[1] = state[0];
        state[0] =     temp ^ (F0(   temp2) + SK[i * 4 + 3]);
    }

    printf("Round 31 | ");
    for (int i = 7; i >= 0; --i)
        printf("%02x:", state[i]);
    puts("");

    state[7] ^= (F0(state[6]) + SK[127]);
    state[5] += (F1(state[4]) ^ SK[126]);
    state[3] ^= (F0(state[2]) + SK[125]);
    state[1] += (F1(state[0]) ^ SK[124]);

    printf("Round 32 | ");
    for (int i = 7; i >= 0; --i)
        printf("%02x:", state[i]);
    puts("");

    state[0] += WK[4];
    state[2] ^= WK[5];
    state[4] += WK[6];
    state[6] ^= WK[7];

    printf("WK FINAL | ");
    for (int i = 7; i >= 0; --i)
        printf("%02x:", state[i]);
    puts("");
    memcpy(dst, state, 8);
}