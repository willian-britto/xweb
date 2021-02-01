
#include <Python.h>

typedef PyByteArrayObject PyByteArrayObject;
typedef PyObject PyObject;

static PyObject* None;

static inline void* PY_BYTES_VALUE (const PyObject* const obj) {
    ASSERT(obj);
    ASSERT(PyBytes_CheckExact(obj));
    return PyBytes_AS_STRING(obj);
}

static inline uint PY_BYTES_SIZE (const PyObject* const obj) {
    ASSERT(obj);
    ASSERT(PyBytes_CheckExact(obj));
    return PyBytes_GET_SIZE(obj);
}

static inline PyObject* UINTLL_TO_PY (const uintll value) {
    return PyLong_FromUnsignedLongLong(value);
}

static inline PyObject* PTR_TO_PY (void* const ptr) {
    ASSERT(ptr != NULL);
    return PyLong_FromVoidPtr(ptr);
}

static inline u64 PY_TO_U64 (PyObject* const obj) {
    ASSERT(PyLong_CheckExact(obj));
    return PyLong_AsUnsignedLongLong(obj);
}

static inline uint PY_TO_UINT (PyObject* const obj) {
    ASSERT(PyLong_CheckExact(obj));
    return PyLong_AsUnsignedLong(obj);
}

static inline void* PY_TO_PTR (PyObject* const obj) {
    ASSERT(PyLong_CheckExact(obj));
    return PyLong_AsVoidPtr(obj);
}

static inline void* PY_TO_PTR_NULL (PyObject* const obj) {
    ASSERT(obj == None || PyLong_CheckExact(obj));
    return (obj == None) ? NULL : PyLong_AsVoidPtr(obj);
}
