#include <Python.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/ptrace.h>
    #include <sys/time.h>
    #include <unistd.h>
#endif

static int integrity_checksum = 0;

void calculate_checksum() {
    unsigned char *code_ptr = (unsigned char*)calculate_checksum;
    for (int i = 0; i < 64; i++) {
        integrity_checksum += code_ptr[i];
    }
}

PyObject* anti_analysis_check(PyObject* self, PyObject* args) {
#ifndef _WIN32
    // Ptrace anti-debug (Linux only)
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return Py_BuildValue("i", 0);
    }
    
    // Timing check
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    // Waste time
    volatile unsigned long long i;
    for (i = 0; i < 1000000ULL; i++);
    
    gettimeofday(&end, NULL);
    long seconds = end.tv_sec - start.tv_sec;
    long microseconds = end.tv_usec - start.tv_usec;
    double elapsed = seconds + microseconds * 1e-6;
    
    if (elapsed > 0.01) {
        return Py_BuildValue("i", 0);
    }
#else
    // Windows: Check for debugger
    if (IsDebuggerPresent()) {
        return Py_BuildValue("i", 0);
    }
#endif
    
    // Environment check
    if (getenv("DEBUG") != NULL || getenv("GDB") != NULL) {
        return Py_BuildValue("i", 0);
    }
    
    // Integrity check
    calculate_checksum();
    if (integrity_checksum != 8327) { // This will change after self-modification
        return Py_BuildValue("i", 0);
    }
    
    return Py_BuildValue("i", 1);
}

static PyMethodDef AntiAnalysisMethods[] = {
    {"check", anti_analysis_check, METH_NOARGS, "Run anti-analysis checks"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef antianalysismodule = {
    PyModuleDef_HEAD_INIT,
    "anti_analysis", 
    "Advanced anti-analysis module",
    -1,
    AntiAnalysisMethods
};

PyMODINIT_FUNC PyInit_anti_analysis(void) {
    return PyModule_Create(&antianalysismodule);
}