#include <Python.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

PyObject* modify_code(PyObject* self, PyObject* args) {
    // Get page size and align address
    long page_size = sysconf(_SC_PAGESIZE);
    void* function_addr = (void*)modify_code;
    void* page_addr = (void*)((long)function_addr & ~(page_size - 1));
    
    // Make page writable
    if (mprotect(page_addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        return Py_BuildValue("i", 0);
    }
    
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