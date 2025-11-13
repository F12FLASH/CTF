#ifndef KEY_FRAGMENTS_H
#define KEY_FRAGMENTS_H

#include <stdint.h>

#define KEY_SIZE 32
#define FRAGMENT_SIZE 3

uint8_t* get_fragment_0(void);
uint8_t* get_fragment_1(void);
uint8_t* get_fragment_2(void);
uint8_t* get_fragment_3(void);
uint8_t* get_fragment_4(void);
uint8_t* get_fragment_5(void);
uint8_t* get_fragment_6(void);
uint8_t* get_fragment_7(void);
uint8_t* get_fragment_8(void);
uint8_t* get_fragment_9(void);

void assemble_key(uint8_t *key);

#endif
