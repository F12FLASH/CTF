#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define KEY_FRAGMENTS 10
#define FRAGMENT_SIZE 16

// Global variables for key fragments
unsigned char key_fragments[KEY_FRAGMENTS][FRAGMENT_SIZE];
int fragments_initialized = 0;

// Advanced anti-debugging
void advanced_anti_debug() {
    // Ptrace check
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        exit(1);
    }
    
    // Timing attack
    clock_t start = clock();
    volatile int i;
    for (i = 0; i < 1000000; i++);
    clock_t end = clock();
    
    if (((double)(end - start)) / CLOCKS_PER_SEC > 0.1) {
        exit(1);
    }
    
    // Environment check
    if (getenv("LD_PRELOAD") != NULL || getenv("PYTHONDEBUG") != NULL) {
        exit(1);
    }
}

// Complex fragment generation
void generate_complex_fragments() {
    if (fragments_initialized) return;
    
    // Fragment 0: Multi-layer mathematical transformation
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        unsigned char val = (i * 13 + 7) % 256;
        val = ((val << 4) | (val >> 4)) & 0xFF;
        val ^= 0xAA;
        val = (val * 3 + 11) % 256;
        key_fragments[0][i] = val;
    }
    
    // Fragment 1: Prime-based with bit manipulation
    int primes[] = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53};
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        unsigned char val = primes[i] * 7;
        val = ((val & 0x0F) << 4) | ((val & 0xF0) >> 4);
        val ^= 0x37;
        val = ~val & 0xFF;
        key_fragments[1][i] = val;
    }
    
    // Fragment 2: Fibonacci with twist
    unsigned long long a = 1, b = 1;
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        unsigned char val = (a + b) % 256;
        val = (val ^ 0x55) + i;
        val = ((val << 3) | (val >> 5)) & 0xFF;
        key_fragments[2][i] = val;
        unsigned long long temp = a;
        a = b;
        b = (temp + b) % 256;
    }
    
    // Fragment 3: Trigonometric approximation
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        double x = i * 0.5;
        double sin_val = x - (x*x*x)/6.0 + (x*x*x*x*x)/120.0;
        unsigned char val = (unsigned char)((sin_val + 1.0) * 128) % 256;
        val = (val * 3 + 17) % 256;
        val ^= 0xDE;
        key_fragments[3][i] = val;
    }
    
    // Fragment 4: Exponential/logarithmic
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        double x = (i + 1) * 0.3;
        unsigned char val = (unsigned char)((exp(x) * 10)) % 256;
        val = ((val & 0xAA) | (~val & 0x55)) & 0xFF;
        val = (val + 0xAD) % 256;
        key_fragments[4][i] = val;
    }
    
    // Fragment 5: Bit reversal with XOR chain
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        unsigned char val = i;
        unsigned char reversed = 0;
        for (int j = 0; j < 8; j++) {
            reversed |= ((val >> j) & 1) << (7 - j);
        }
        val = reversed;
        val = (val ^ 0xBEEF) % 256;
        val = (val * 5 + 3) % 256;
        key_fragments[5][i] = val;
    }
    
    // Fragment 6: Complex polynomial
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        unsigned char val = (3*i*i + 7*i + 13) % 256;
        val = ((val << 1) | (val >> 7)) & 0xFF;
        val ^= 0xCA;
        val = (val + 0xFE) % 256;
        key_fragments[6][i] = val;
    }
    
    // Fragment 7: Modular arithmetic
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        unsigned char val = (i * 17 + 19) % 257;
        val = (val ^ (i * 3)) % 256;
        val = ((val & 0xCC) >> 2) | ((val & 0x33) << 2);
        key_fragments[7][i] = val;
    }
    
    // Fragment 8: Logical operations cascade
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        unsigned char val = i;
        val = (val & 0xF0) >> 4 | (val & 0x0F) << 4;
        val = ~val & 0xFF;
        val = (val | 0xAA) & (val | 0x55);
        val = (val ^ 0x42) % 256;
        key_fragments[8][i] = val;
    }
    
    // Fragment 9: Mixed transformations
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        unsigned char val = (i * 11 + 23) % 256;
        val = ((val << 2) | (val >> 6)) & 0xFF;
        val ^= 0xDEAD % 256;
        val = (val * 13) % 256;
        val = ((val & 0x0F) << 4) | ((val & 0xF0) >> 4);
        key_fragments[9][i] = val;
    }
    
    fragments_initialized = 1;
}

// Self-modifying code with multiple layers
void self_modify_complex() {
    // Make code writable
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)self_modify_complex & ~(page_size - 1);
    mprotect((void*)start, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
    
    // Modify multiple locations with different patterns
    unsigned char *code_ptr = (unsigned char*)self_modify_complex;
    
    // Layer 1: XOR modification
    for (int i = 50; i < 100; i++) {
        code_ptr[i] ^= 0x90;
    }
    
    // Layer 2: Addition modification
    for (int i = 150; i < 200; i++) {
        code_ptr[i] = (code_ptr[i] + 0x37) % 256;
    }
    
    // Layer 3: Bit rotation
    for (int i = 250; i < 300; i++) {
        code_ptr[i] = ((code_ptr[i] << 2) | (code_ptr[i] >> 6)) & 0xFF;
    }
}

// Multi-stage key combination
void combine_key_fragments(unsigned char* final_key) {
    unsigned char stage1_key[FRAGMENT_SIZE];
    unsigned char stage2_key[FRAGMENT_SIZE];
    
    // Stage 1: XOR combination with rotation
    memset(stage1_key, 0, FRAGMENT_SIZE);
    for (int i = 0; i < KEY_FRAGMENTS; i++) {
        for (int j = 0; j < FRAGMENT_SIZE; j++) {
            stage1_key[j] ^= key_fragments[i][(j + i) % FRAGMENT_SIZE];
        }
    }
    
    // Stage 2: Mathematical transformation
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        stage2_key[i] = (stage1_key[i] * 3 + stage1_key[(i + 1) % FRAGMENT_SIZE]) % 256;
        stage2_key[i] ^= key_fragments[i % KEY_FRAGMENTS][(i + 3) % FRAGMENT_SIZE];
    }
    
    // Stage 3: Final complex transformation
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        final_key[i] = stage2_key[i];
        final_key[i] = ((final_key[i] << 4) | (final_key[i] >> 4)) & 0xFF;
        final_key[i] ^= 0xAB;
        final_key[i] = (final_key[i] + 0xCD) % 256;
        final_key[i] = ((final_key[i] & 0x55) << 1) | ((final_key[i] & 0xAA) >> 1);
    }
}

// Main encryption function
PyObject* encrypt_flag(PyObject* self, PyObject* args) {
    advanced_anti_debug();
    
    const char* input;
    if (!PyArg_ParseTuple(args, "s", &input)) {
        return NULL;
    }
    
    generate_complex_fragments();
    self_modify_complex();
    
    // Combine fragments into final key
    unsigned char key[AES_BLOCK_SIZE];
    combine_key_fragments(key);
    
    // AES encryption
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);
    
    size_t input_len = strlen(input);
    size_t encrypted_len = ((input_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char* encrypted = malloc(encrypted_len);
    memset(encrypted, 0, encrypted_len);
    memcpy(encrypted, input, input_len);
    
    AES_cbc_encrypt(encrypted, encrypted, encrypted_len, &aes_key, iv, AES_ENCRYPT);
    
    // Convert to hex
    char* hex_result = malloc(encrypted_len * 2 + 1);
    for (size_t i = 0; i < encrypted_len; i++) {
        sprintf(hex_result + i * 2, "%02x", encrypted[i]);
    }
    
    PyObject* result = Py_BuildValue("s", hex_result);
    free(encrypted);
    free(hex_result);
    
    return result;
}

// Get individual fragments for debugging (will be removed in final version)
PyObject* get_fragment(PyObject* self, PyObject* args) {
    int index;
    if (!PyArg_ParseTuple(args, "i", &index)) {
        return NULL;
    }
    
    if (index < 0 || index >= KEY_FRAGMENTS) {
        PyErr_SetString(PyExc_ValueError, "Invalid fragment index");
        return NULL;
    }
    
    generate_complex_fragments();
    
    char hex_result[FRAGMENT_SIZE * 2 + 1];
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        sprintf(hex_result + i * 2, "%02x", key_fragments[index][i]);
    }
    
    return Py_BuildValue("s", hex_result);
}

static PyMethodDef OuroborosMethods[] = {
    {"encrypt_flag", encrypt_flag, METH_VARARGS, "Encrypt flag with fragmented key"},
    {"get_fragment", get_fragment, METH_VARARGS, "Get specific key fragment"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef ouroborosmodule = {
    PyModuleDef_HEAD_INIT,
    "crypto_extension",
    "Ouroboros self-modifying encryption module",
    -1,
    OuroborosMethods
};

PyMODINIT_FUNC PyInit_crypto_extension(void) {
    return PyModule_Create(&ouroborosmodule);
}