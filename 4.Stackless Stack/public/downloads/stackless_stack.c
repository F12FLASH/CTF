/*
 * Stackless Stack Challenge - Professional Edition
 * Advanced Binary Exploitation Environment
 * 
 * Vulnerability: Buffer overflow in mmap'd region
 * Protection: NX enabled, No PIE, No stack canary
 * Exploitation: ROP chain + mprotect syscall to bypass NX
 * 
 * Author: F12FLASH
 * Difficulty: Master Hacker
 * Version: 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* ===== Configuration Constants ===== */
#define BUFFER_SIZE          0x100
#define MMAP_SIZE            0x2000
#define MAX_INPUT            0x600
#define FLAG_FILE            "/tmp/flag.txt"
#define MAGIC_VALUE          0xdeadbeef
#define XOR_KEY              0x42

/* ===== Data Structures ===== */
typedef struct {
    char data[BUFFER_SIZE];
    void (*callback)(char*);
    unsigned long magic;
} memory_region_t;

/* ===== Function Prototypes ===== */
void display_banner(void);
void setup_environment(void);
void process_data(char *data);
void win_function(void);
void vulnerable_function(memory_region_t *region);
void print_debug_info(memory_region_t *region);
void cleanup(memory_region_t *region);

/* ===== Global Constants ===== */
static const char* BANNER = 
    "╔═══════════════════════════════════════════════════════════╗\n"
    "║                 STACKLESS STACK CHALLENGE                 ║\n"
    "║           Professional Exploitation Environment           ║\n"
    "║                                                           ║\n"
    "║     Type:    Buffer Overflow + ROP Chain                  ║\n"
    "║     Protection: NX | No PIE | No Canary                   ║\n"
    "╚═══════════════════════════════════════════════════════════╝\n\n";

static const char* HINTS = 
    "\n[?] Exploitation Hints:\n"
    "    • Buffer allocated via mmap() - not traditional stack\n"
    "    • Overflow to control callback pointer\n"
    "    • NX enabled - ROP gadgets required\n"
    "    • Use mprotect syscall (10) for memory protection change\n"
    "    • Required gadgets: pop rdi, pop rsi, pop rdx, syscall\n\n";

/* ===== Main Implementation ===== */

/**
 * @brief Display professional banner
 */
void display_banner(void) {
    write(STDOUT_FILENO, BANNER, strlen(BANNER));
}

/**
 * @brief Initialize challenge environment
 */
void setup_environment(void) {
    struct stat file_stat;
    
    if (stat(FLAG_FILE, &file_stat) == 0) {
        return; // Flag file exists
    }
    
    int fd = open(FLAG_FILE, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd >= 0) {
        const char *demo_flag = "DEMO_FLAG{professional_stackless_exploitation}";
        write(fd, demo_flag, strlen(demo_flag));
        close(fd);
    }
}

/**
 * @brief Data processing callback function
 * @param data Pointer to data buffer
 */
void process_data(char *data) {
    write(STDOUT_FILENO, "[*] Processing data with XOR cipher...\n", 40);
    
    for (size_t i = 0; i < BUFFER_SIZE && data[i] != '\0'; i++) {
        data[i] ^= XOR_KEY;
    }
    
    write(STDOUT_FILENO, "[+] Data processing complete!\n", 30);
}

/**
 * @brief Target function for exploitation - reads and displays flag
 */
void win_function(void) {
    char flag_buffer[256] = {0};
    const char *demo_flag = "DEMO_FLAG{successfully_executed_win_function}\n";
    
    int fd = open(FLAG_FILE, O_RDONLY);
    if (fd < 0) {
        write(STDOUT_FILENO, "[!] Flag file not found - demo mode activated\n", 46);
        write(STDOUT_FILENO, demo_flag, strlen(demo_flag));
        return;
    }
    
    ssize_t bytes_read = read(fd, flag_buffer, sizeof(flag_buffer) - 1);
    if (bytes_read > 0) {
        flag_buffer[bytes_read] = '\0';
        write(STDOUT_FILENO, "[🎯] FLAG CAPTURED: ", 20);
        write(STDOUT_FILENO, flag_buffer, bytes_read);
        write(STDOUT_FILENO, "\n", 1);
    } else {
        write(STDOUT_FILENO, "[!] Failed to read flag file\n", 29);
    }
    
    close(fd);
}

/**
 * @brief Print memory layout and debug information
 * @param region Pointer to memory region
 */
void print_debug_info(memory_region_t *region) {
    char info_buffer[512];
    
    int length = snprintf(info_buffer, sizeof(info_buffer),
        "[🔍] Memory Layout Information:\n"
        "    • Region Address:  %p\n"
        "    • Buffer Size:     0x%x bytes\n"
        "    • Callback Pointer: %p\n"
        "    • Magic Value:     0x%lx\n"
        "    • Win Function:    %p\n\n",
        region, BUFFER_SIZE, region->callback, 
        region->magic, win_function);
    
    write(STDOUT_FILENO, info_buffer, length);
}

/**
 * @brief Vulnerable function containing buffer overflow
 * @param region Pointer to memory region structure
 */
void vulnerable_function(memory_region_t *region) {
    char local_buffer[64]; // Small local buffer
    
    const char *prompt = "[💀] Enter your exploit payload: ";
    write(STDOUT_FILENO, prompt, strlen(prompt));
    
    ssize_t bytes_read = read(STDIN_FILENO, region->data, MAX_INPUT);
    
    if (bytes_read > 0) {
        char status_msg[128];
        int msg_len = snprintf(status_msg, sizeof(status_msg),
                             "[📥] Received %ld bytes at address %p\n",
                             bytes_read, region->data);
        write(STDERR_FILENO, status_msg, msg_len);
    }
    
    // Trigger callback if magic value matches
    if (region->magic == MAGIC_VALUE && region->callback != NULL) {
        write(STDOUT_FILENO, "[⚡] Executing callback function...\n", 35);
        region->callback(region->data);
    }
}

/**
 * @brief Cleanup resources
 * @param region Pointer to memory region to cleanup
 */
void cleanup(memory_region_t *region) {
    if (region != MAP_FAILED && region != NULL) {
        munmap(region, MMAP_SIZE);
    }
}

/**
 * @brief Main function - challenge entry point
 */
int main(int argc, char *argv[]) {
    memory_region_t *memory_region;
    
    // Disable buffering for CTF environment
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    display_banner();
    setup_environment();
    
    // Allocate memory region using mmap
    memory_region = (memory_region_t *)mmap(
        NULL, 
        MMAP_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1, 
        0
    );
    
    if (memory_region == MAP_FAILED) {
        perror("[-] mmap allocation failed");
        return EXIT_FAILURE;
    }
    
    // Initialize memory region
    memset(memory_region, 0, sizeof(memory_region_t));
    memory_region->callback = process_data;
    memory_region->magic = MAGIC_VALUE;
    
    print_debug_info(memory_region);
    
    // Display hints if requested
    if (argc > 1 && strcmp(argv[1], "--hints") == 0) {
        write(STDOUT_FILENO, HINTS, strlen(HINTS));
    }
    
    // Core vulnerability
    vulnerable_function(memory_region);
    
    write(STDOUT_FILENO, "[👋] Challenge completed - cleaning up...\n", 42);
    cleanup(memory_region);
    
    return EXIT_SUCCESS;
}

/* ===== Compilation Instructions ===== */
/*
 * Production Build:
 *   gcc -o stackless_stack_pro stackless_stack.c \
 *       -no-pie -fno-stack-protector -z noexecstack -O2
 * 
 * Debug Build:
 *   gcc -o stackless_stack_debug stackless_stack.c \
 *       -no-pie -fno-stack-protector -z noexecstack -g -DDEBUG
 * 
 * Security Features:
 *   - NX (No Execute): Prevents code execution on stack/heap
 *   - No PIE: Fixed memory addresses for easier exploitation
 *   - No Stack Canary: No runtime stack protection
 * 
 * Exploitation Strategy:
 *   1. Overflow buffer to overwrite callback pointer
 *   2. Redirect execution to ROP chain
 *   3. Use mprotect syscall (10) to make memory executable
 *   4. Execute shellcode or call win_function directly
 * 
 * Syscall Reference:
 *   - mprotect(addr, len, prot)
 *   - rax=10, rdi=addr, rsi=len, rdx=prot (7=RWX)
 */