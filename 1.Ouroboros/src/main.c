#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "anti_debug.h"
#include "self_modify.h"
#include "key_fragments.h"
#include "aes_crypto.h"

static const uint8_t encrypted_flag[] = {
    0x5e, 0x57, 0x48, 0x68, 0xd5, 0x5e, 0x75, 0xf6,
    0x12, 0x35, 0x5c, 0x10, 0xe2, 0xec, 0x9c, 0x4b,
    0xee, 0x89, 0xf4, 0x59, 0xd4, 0x74, 0x77, 0xca,
    0xb5, 0xe0, 0x8f, 0x99, 0xe2, 0xcb, 0x3a, 0x81,
    0x92, 0xc7, 0xae, 0x38, 0x04, 0x12, 0xb5, 0xff,
    0x08, 0x96, 0xc5, 0xda, 0x17, 0xdd, 0x63, 0x27,
    0x53, 0xfa, 0x62, 0xed, 0x03, 0xd0, 0x30, 0xdf,
    0x0a, 0x41, 0xa9, 0xab, 0xb0, 0x57, 0x85, 0x2c,
    0x57, 0x95, 0x28
};

void print_banner(void) {
    printf("\n");
    printf("  ╔═══════════════════════════════════════════════════════╗\n");
    printf("  ║                                                       ║\n");
    printf("  ║              ⚡ OUROBOROS CHALLENGE ⚡               ║\n");
    printf("  ║                                                       ║\n");
    printf("  ║       The serpent that devours its own tail...        ║\n");
    printf("  ║       Self-modifying code reveals hidden truths       ║\n");
    printf("  ║                                                       ║\n");
    printf("  ║              Difficulty: MASTER HACKER                ║\n");
    printf("  ║                                                       ║\n");
    printf("  ╚═══════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void obfuscated_sleep(void) {
    volatile int x = 0;
    for(int i = 0; i < 100000; i++) {
        x += i % 13;
    }
}

int verify_integrity(void) {
    uint8_t key[KEY_SIZE];
    assemble_key(key);
    
    uint32_t checksum = 0;
    for(int i = 0; i < KEY_SIZE; i++) {
        checksum += key[i];
    }
    
    return checksum > 0;
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    print_banner();
    
    printf("[*] Initializing anti-debugging mechanisms...\n");
    anti_debug_init();
    obfuscated_sleep();
    
    printf("[*] Checking environment...\n");
    if (check_environment()) {
        printf("[!] Suspicious environment detected! Exiting...\n");
        return 1;
    }
    obfuscated_sleep();
    
    printf("[*] Checking for debugger presence...\n");
    if (check_debugger()) {
        printf("[!] Debugger detected! Exiting...\n");
        return 1;
    }
    obfuscated_sleep();
    
    printf("[*] Performing timing analysis...\n");
    if (check_timing()) {
        printf("[!] Timing anomaly detected! Exiting...\n");
        return 1;
    }
    obfuscated_sleep();
    
    printf("[*] Initializing self-modifying code...\n");
    init_self_modify();
    obfuscated_sleep();
    
    printf("[*] Revealing hidden code...\n");
    reveal_code();
    obfuscated_sleep();
    
    printf("[*] Executing hidden function...\n");
    int result = execute_hidden_function();
    printf("[*] Hidden function returned: %d\n", result);
    obfuscated_sleep();
    
    printf("[*] Assembling key fragments from memory...\n");
    uint8_t key[KEY_SIZE];
    assemble_key(key);
    
    printf("[*] Key fragments located in 10 different functions\n");
    printf("[*] Each fragment is %d bytes\n", FRAGMENT_SIZE);
    printf("[*] Total key size: %d bytes\n", KEY_SIZE);
    obfuscated_sleep();
    
    printf("[*] Verifying key integrity...\n");
    if (!verify_integrity()) {
        printf("[!] Key integrity check failed!\n");
        return 1;
    }
    printf("[✓] Key integrity verified\n");
    obfuscated_sleep();
    
    printf("\n[*] Processing encrypted data...\n");
    printf("[*] Encrypted flag size: %zu bytes\n", sizeof(encrypted_flag));
    obfuscated_sleep();
    
    printf("\n");
    printf("  ╔═══════════════════════════════════════════════════════╗\n");
    printf("  ║                                                       ║\n");
    printf("  ║              🔒 FLAG IS ENCRYPTED 🔒                 ║\n");
    printf("  ║                                                       ║\n");
    printf("  ║   Your mission: Extract the key and decrypt!          ║\n");
    printf("  ║                                                       ║\n");
    printf("  ║   The flag awaits those skilled enough to find it...  ║\n");
    printf("  ║                                                       ║\n");
    printf("  ╚═══════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    printf("[💡] CHALLENGE HINTS:\n");
    printf("    • Key is fragmented across 10 functions\n");
    printf("    • Each function stores exactly 3 bytes\n");
    printf("    • Static analysis can reveal fragment locations\n");
    printf("    • Or use memory forensics to extract from runtime\n");
    printf("    • Anti-debugging will make dynamic analysis harder\n");
    printf("    • The encryption is reversible - study the algorithm!\n");
    printf("\n");
    printf("[!] Good luck, hacker! The serpent guards its secrets well...\n");
    printf("\n");
    
    return 0;
}
