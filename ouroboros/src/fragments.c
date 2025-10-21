#include <Python.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Individual fragment functions with unique algorithms
PyObject* fragment_0(PyObject* self, PyObject* args) {
    unsigned char frag[16];
    
    // Complex mathematical sequence
    for (int i = 0; i < 16; i++) {
        int val = (i * 17 + 13) % 256;
        val = ((val << 3) | (val >> 5)) & 0xFF;
        val ^= 0x7B;
        val = (val * 5 + 7) % 256;
        frag[i] = val;
    }
    
    char hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(hex + i * 2, "%02x", frag[i]);
    }
    
    return Py_BuildValue("s", hex);
}

PyObject* fragment_1(PyObject* self, PyObject* args) {
    unsigned char frag[16];
    int seeds[] = {0x12, 0x87, 0x45, 0xAE, 0xFC, 0x39, 0x6B, 0xD1};
    
    for (int i = 0; i < 16; i++) {
        int val = seeds[i % 8];
        val = (val + i * 11) % 256;
        val ^= 0x91;
        val = ((val & 0x0F) << 4) | ((val & 0xF0) >> 4);
        val = (val + 0x37) % 256;
        frag[i] = val;
    }
    
    char hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(hex + i * 2, "%02x", frag[i]);
    }
    
    return Py_BuildValue("s", hex);
}

PyObject* fragment_2(PyObject* self, PyObject* args) {
    unsigned char frag[16];
    unsigned long a = 1, b = 2;
    
    for (int i = 0; i < 16; i++) {
        unsigned long next = (a + b) % 256;
        int val = next;
        val = (val ^ 0x55) + i * 3;
        val = ((val << 1) | (val >> 7)) & 0xFF;
        val ^= 0xAA;
        frag[i] = val;
        a = b;
        b = next;
    }
    
    char hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(hex + i * 2, "%02x", frag[i]);
    }
    
    return Py_BuildValue("s", hex);
}

// Export fragment functions
static PyMethodDef FragmentMethods[] = {
    {"fragment_0", fragment_0, METH_NOARGS, "Get fragment 0"},
    {"fragment_1", fragment_1, METH_NOARGS, "Get fragment 1"},
    {"fragment_2", fragment_2, METH_NOARGS, "Get fragment 2"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef fragmentmodule = {
    PyModuleDef_HEAD_INIT,
    "fragments",
    "Key fragment generation module",
    -1,
    FragmentMethods
};

PyMODINIT_FUNC PyInit_fragments(void) {
    return PyModule_Create(&fragmentmodule);
}