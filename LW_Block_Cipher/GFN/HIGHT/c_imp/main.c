#include "hight.h"
#include "hight_utils.h"

void viewKeySchedule(u8* SK) {
    for (int i = 0; i < 32; i++) {
        printf("SK[%03d]||SK[%03d]||SK[%03d]||SK[%03d]: %02x%02x%02x%02x\n",
            4*i+3, 4*i+2, 4*i+1, 4*i, SK[4*i+3], SK[4*i+2], SK[4*i+1], SK[4*i]);
    }
}

int main(void) {
#if 1
    // const char* keyString = "00112233445566778899aabbccddeeff"; // Test Vector 1
    // const char* keyString = "ffeeddccbbaa99887766554433221100"; // Test Vector 2
    // const char* keyString = "000102030405060708090a0b0c0d0e0f"; // Test Vector 3
    const char* keyString = "28dbc3bc49ffd87dcfa509b11d422be7"; // Test Vector 4
    u8 MK[16] = { 0x00, };
    stringToByte(MK, keyString);

    // const char* inputString = "0000000000000000"; // Test Vector 1
    // const char* inputString = "0011223344556677"; // Test Vector 2
    // const char* inputString = "0123456789abcdef"; // Test Vector 3
    const char* inputString = "b41e6be2eba84a14"; // Test Vector 4
    
    u8 PT[8] = { 0x00, };
    stringToByte(PT, inputString);

    u8 CT[8] = { 0x00, };
    u8 myPT[8] = { 0x00, };
    HIGHT_Encrypt(CT, PT, MK);
    HIGHT_Decrypt(myPT, CT, MK);

    u64 enc_cycles, dec_cycles;
    for (u32 i = 0; i < 12000; i++) {
        assign_rand(MK, 16);
        assign_rand(PT, 8);
        enc_cycles = measure_cycles(HIGHT_Encrypt, CT, PT, MK);
        dec_cycles = measure_cycles(HIGHT_Decrypt, myPT, PT, MK);
        if (i >= 1000 && i < 11000) {
            printf("%" PRIu64 "\n", enc_cycles);
            printf("%" PRIu64 "\n", dec_cycles);
            // printf("%llu\n", (long long)cycles / (long long)SIZE);
        }
    }
    // for (int i = 7; i >= 0; i--) {
    //     printf("%02x:", PT[i]);
    // } puts("");
    // for (int i = 7; i >= 0; i--) {
    //     printf("%02x:", CT[i]);
    // } puts("");
    // for (int i = 7; i >= 0; i--) {
    //     printf("%02x:", myPT[i]);
    // } puts("");

    // measure_cpu_time(HIGHT_Encrypt, CT, PT, MK);
    // measure_cpu_time(HIGHT_Decrypt, CT, PT, MK);

    // measure_memory_usage(HIGHT_Encrypt, CT, PT, MK);
    // measure_memory_usage(HIGHT_Decrypt, CT, PT, MK);
    // measure_total_memory_usage(HIGHT_Decrypt, CT, PT, MK);
#endif
#if 0
    printf("KEY = ");
    for (int i = 15; i >= 0; i--) {
        printf("%02x", MK[i]);
    } puts("");
    printf("PT = ");
    for (int i = 7; i >= 0; i--) {
        printf("%02x", PT[i]);
    } puts("");

    HIGHT_Encrypt(CT, PT, MK);

    printf("myCT | ");
    for (int i = 7; i >= 0; i--) {
        printf("%02x:", CT[i]);
    }
    printf("\n");

    HIGHT_Decrypt(myPT, CT, MK);

    printf("myPT | ");
    for (int i = 7; i >= 0; i--) {
        printf("%02x:", myPT[i]);
    }
    printf("\n");

    puts("");
    // printf("ENC: %lu cycles\n", measure_encryption_cycle(HIGHT_Encrypt, CT, PT, MK));
    // printf("ENC: %.3f µs\n", measure_encryption_time(HIGHT_Encrypt, CT, PT, MK)*1000000);
    // printf("Dec: %lu cycles\n", measure_encryption_cycle(HIGHT_Decrypt, myPT, CT, MK));
    // printf("Dec: %.3f µs\n", measure_encryption_time(HIGHT_Decrypt, myPT, CT, MK)*1000000);
#endif
    // for (i32 i = 0; i < 10000; i++) {
    //     printf("%ld\n", measure_encryption_cycle(HIGHT_Encrypt, CT, PT, MK));
    //     printf("%ld\n", measure_encryption_cycle(HIGHT_Decrypt, myPT, CT, MK));
    // }

    // for (int i = 0; i < 8; i++) {
    //     for (int j = 0; j < 8; j++)
    //         printf("SK[%03d] = MK[%02d] + delta[%03d]\n", 16 * i + j + 0, ((j - i) & 7) + 0, 16 * i + j + 0);
    //     for (int j = 0; j < 8; j++)
    //         printf("SK[%03d] = MK[%02d] + delta[%03d]\n", 16 * i + j + 8, ((j - i) & 7) + 8, 16 * i + j + 8);
    // }

    // puts("");

    // for (int i = 7; i >= 0; i--) {
    //     for (int j = 7; j >= 0; j--)
    //         printf("SK[%d] = MK[%d] + delta[%d]\n", 127 - (16 * i + j + 8), ((j - i) & 7) + 8, 16 * i + j + 8);
    //     for (int j = 7; j >= 0; j--)
    //         printf("SK[%d] = MK[%d] + delta[%d]\n", 127 - (16 * i + j + 0), ((j - i) & 7) + 0, 16 * i + j + 0);
    // }

    return 0;
}