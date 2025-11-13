/**
 * Anti-Debugging Module
 * 
 * Implements multiple layers of debugger detection:
 * - PTRACE_TRACEME: Prevents debugger attachment
 * - /proc/self/status: Monitors TracerPid for active tracers
 * - SIGTRAP handler: Detects signal interception
 * - Timing analysis: Identifies execution slowdowns
 * - Environment checks: Detects LD_PRELOAD and other hooks
 */

#include "anti_debug.h"
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>

static volatile int sigtrap_triggered = 0;

/**
 * SIGTRAP signal handler
 * Used to detect if a debugger is intercepting our signals
 */
void sigtrap_handler(int sig) {
    (void)sig;
    sigtrap_triggered = 1;
}

/**
 * Initialize anti-debugging mechanisms
 * 
 * PTRACE_TRACEME: Only one process can trace this process.
 * If a debugger is already attached, this call will fail.
 * Also sets up the SIGTRAP handler for signal-based detection.
 */
void anti_debug_init(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        printf("Debugger detected via PTRACE_TRACEME!\n");
        exit(1);
    }
    
    signal(SIGTRAP, sigtrap_handler);
}

/**
 * Check for debugger presence using multiple techniques
 * 
 * Method 1: Read /proc/self/status and check TracerPid
 * - TracerPid will be non-zero if a debugger is attached
 * 
 * Method 2: Send ourselves a SIGTRAP signal
 * - If our handler doesn't run, a debugger intercepted it
 * 
 * Returns: 1 if debugger detected, 0 otherwise
 */
int check_debugger(void) {
    FILE *status_file = fopen("/proc/self/status", "r");
    if (status_file == NULL) {
        return 0;
    }
    
    char line[256];
    int tracer_pid = 0;
    
    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer_pid = atoi(line + 10);
            break;
        }
    }
    
    fclose(status_file);
    
    if (tracer_pid != 0) {
        printf("Debugger detected via /proc/self/status (TracerPid: %d)!\n", tracer_pid);
        return 1;
    }
    
    /* SIGTRAP test - send signal to ourselves */
    sigtrap_triggered = 0;
    raise(SIGTRAP);
    usleep(1000);
    
    if (!sigtrap_triggered) {
        printf("Debugger detected via SIGTRAP handler!\n");
        return 1;
    }
    
    return 0;
}

/**
 * Timing-based debugger detection
 * 
 * Measures execution time of a simple loop.
 * If it takes too long, likely due to single-stepping or breakpoints.
 * 
 * Threshold: 50ms (50000 microseconds)
 * Returns: 1 if timing anomaly detected, 0 otherwise
 */
int check_timing(void) {
    struct timeval start, end;
    long elapsed_usec;
    
    gettimeofday(&start, NULL);
    
    /* Simple calculation loop - should be very fast */
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += i;
    }
    
    gettimeofday(&end, NULL);
    
    elapsed_usec = (end.tv_sec - start.tv_sec) * 1000000 + 
                   (end.tv_usec - start.tv_usec);
    
    /* If it takes more than 50ms, something is wrong */
    if (elapsed_usec > 50000) {
        printf("Debugger detected via timing analysis (elapsed: %ld μs)!\n", elapsed_usec);
        return 1;
    }
    
    return 0;
}

/**
 * Environment-based debugger detection
 * 
 * Checks for:
 * - LD_PRELOAD: Commonly used to hook functions (like ptrace)
 * - /proc/self/mem: Should be accessible in normal conditions
 * 
 * Returns: 1 if suspicious environment detected, 0 otherwise
 */
int check_environment(void) {
    const char *ld_preload = getenv("LD_PRELOAD");
    if (ld_preload != NULL) {
        printf("Warning: LD_PRELOAD detected (%s)\n", ld_preload);
        /* Note: We don't exit here as LD_PRELOAD has legitimate uses */
    }
    
    /* Check if we can access our own memory */
    if (access("/proc/self/mem", F_OK) != 0) {
        printf("Debugger detected: /proc/self/mem access restricted!\n");
        return 1;
    }
    
    return 0;
}
