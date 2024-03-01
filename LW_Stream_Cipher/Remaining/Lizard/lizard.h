//
// Created by Ivan Kozlov on 12/05/2018.
//
#include <stdint.h>

#ifndef LIZARD_LIZARD_H
#define LIZARD_LIZARD_H

#define KEYSTREAM_SIZE 128
#define LENGTH_TEST 128

void loadkey(uint8_t *key);
void loadIV(uint8_t *iv);
void initRegisters();
void mixing();
void keyadd();
void diffusion();
uint8_t NFSR1();
uint8_t NFSR2();
void _construct(uint8_t  *key, uint8_t *iv);
void _initialization(uint8_t *key, uint8_t *iv);
void keysteamGeneration(int length);
uint8_t* keystreamGenerationSpecification(int length);
uint8_t a();
char* binArray2hex(uint8_t * bin);
void hex2binArray(char* hex, uint8_t * bin);
uint8_t hex2int(char ch);
void test();
void test1();
void test2();
void test3();

#endif //LIZARD_LIZARD_H
