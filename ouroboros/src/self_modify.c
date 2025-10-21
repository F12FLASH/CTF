#include <Python.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
#endif

PyObject* modify_code(PyObject* self, PyObject* args) {
    void* function_addr = (void*)modify_code;
    
#ifndef _WIN32
    // Linux: Get page size and align address
    long page_size = sysconf(_SC_PAGESIZE);
    void* page_addr = (void*)((long)function_addr & ~(page_size - 1));
    
    // Make page writable
    if (mprotect(page_addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        return Py_BuildValue("i", 0);
    }
#else
    // Windows: Change memory protection
    DWORD oldProtect;
    if (!VirtualProtect(function_addr, 4096, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return Py_BuildValue("i", 0);
    }
#endif
    
    // Modify own code
    unsigned char* code = (unsigned char*)function_addr;
    
    // Find a safe offset to modify (after function prologue)
    int offset = 20;
    for (int i = offset; i < offset + 10; i++) {
        code[i] ^= 0xCC; // XOR with breakpoint instruction
    }
    
    return Py_BuildValue("i", 1);
}

static PyMethodDef SelfModifyMethods[] = {
    {"modify", modify_code, METH_NOARGS, "Self-modify code"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef selfmodifymodule = {
    PyModuleDef_HEAD_INIT,
    "self_modify",
    "Self-modifying code module", 
    -1,
    SelfModifyMethods
};

PyMODINIT_FUNC PyInit_self_modify(void) {
    return PyModule_Create(&selfmodifymodule);
}