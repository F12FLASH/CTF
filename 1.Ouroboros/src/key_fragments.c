#include "key_fragments.h"
#include <string.h>
#include <stdio.h>

static uint8_t fragment_0[] = {0x6b, 0x65, 0x79};
static uint8_t fragment_1[] = {0x5f, 0x66, 0x72};
static uint8_t fragment_2[] = {0x61, 0x67, 0x6d};
static uint8_t fragment_3[] = {0x65, 0x6e, 0x74};
static uint8_t fragment_4[] = {0x5f, 0x64, 0x61};
static uint8_t fragment_5[] = {0x74, 0x61, 0x5f};
static uint8_t fragment_6[] = {0x73, 0x65, 0x63};
static uint8_t fragment_7[] = {0x72, 0x65, 0x74};
static uint8_t fragment_8[] = {0x5f, 0x6b, 0x65};
static uint8_t fragment_9[] = {0x79, 0x21, 0x21};

uint8_t* get_fragment_0(void) {
    volatile uint8_t *ptr = fragment_0;
    return (uint8_t*)ptr;
}

uint8_t* get_fragment_1(void) {
    volatile uint8_t *ptr = fragment_1;
    uint8_t dummy[128];
    memset(dummy, 0xAA, sizeof(dummy));
    return (uint8_t*)ptr;
}

uint8_t* get_fragment_2(void) {
    volatile uint8_t *ptr = fragment_2;
    int obfuscation = 0;
    for(int i = 0; i < 100; i++) {
        obfuscation += i * 7;
    }
    return (uint8_t*)ptr;
}

uint8_t* get_fragment_3(void) {
    volatile uint8_t *ptr = fragment_3;
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "Fragment location: %p", ptr);
    return (uint8_t*)ptr;
}

uint8_t* get_fragment_4(void) {
    volatile uint8_t *ptr = fragment_4;
    volatile int x = 42;
    volatile int y = x * 2;
    volatile int z = y + x;
    (void)z;
    return (uint8_t*)ptr;
}

uint8_t* get_fragment_5(void) {
    volatile uint8_t *ptr = fragment_5;
    uint64_t mask = 0xDEADBEEFCAFEBABE;
    mask ^= (uint64_t)ptr;
    (void)mask;
    return (uint8_t*)ptr;
}

uint8_t* get_fragment_6(void) {
    volatile uint8_t *ptr = fragment_6;
    uint8_t noise[64];
    for(int i = 0; i < 64; i++) {
        noise[i] = i ^ 0x55;
    }
    (void)noise;
    return (uint8_t*)ptr;
}

uint8_t* get_fragment_7(void) {
    volatile uint8_t *ptr = fragment_7;
    const char *decoy = "This is not the fragment you're looking for";
    (void)decoy;
    return (uint8_t*)ptr;
}

uint8_t* get_fragment_8(void) {
    volatile uint8_t *ptr = fragment_8;
    uint32_t checksum = 0;
    for(int i = 0; i < FRAGMENT_SIZE; i++) {
        checksum += fragment_8[i];
    }
    (void)checksum;
    return (uint8_t*)ptr;
}

uint8_t* get_fragment_9(void) {
    volatile uint8_t *ptr = fragment_9;
    uint8_t validation[32];
    memset(validation, 0xFF, sizeof(validation));
    return (uint8_t*)ptr;
}

void assemble_key(uint8_t *key) {
    uint8_t *fragments[10] = {
        get_fragment_0(),
        get_fragment_1(),
        get_fragment_2(),
        get_fragment_3(),
        get_fragment_4(),
        get_fragment_5(),
        get_fragment_6(),
        get_fragment_7(),
        get_fragment_8(),
        get_fragment_9()
    };
    
    int offset = 0;
    for(int i = 0; i < 10; i++) {
        memcpy(key + offset, fragments[i], FRAGMENT_SIZE);
        offset += FRAGMENT_SIZE;
    }
    
    key[30] = 0x00;
    key[31] = 0x00;
}
