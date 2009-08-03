#include <windows.h>
#include <wincrypt.h>

#include "Python.h"
#include "keyring_util.h"

static const WCHAR description[] = L"python-keyring-lib.win32crypto";

static PyObject *
crypto_encrypt(PyObject *self, PyObject *args)
{
    const char *password;
    const char *password_encrypted;
    const int non_interactive = 0;
    DATA_BLOB blobin;
    DATA_BLOB blobout;
    int crypted = 0;
    int status = 0;

    if (!PyArg_ParseTuple(args, "s|i", &password, &non_interactive)){
        PyErr_Clear();
        PyErr_SetString(PyExc_TypeError,
                        "encrypt() must be called as encrypt(passwod)");
        return NULL;
    }

    blobin.cbData = strlen(password);
    blobin.pbData = (BYTE*) password;
    
    crypted = CryptProtectData(&blobin, description, NULL, NULL, NULL,
                    CRYPTPROTECT_UI_FORBIDDEN, &blobout);
    if (crypted){
        password_encrypted = string_dump(blobout.pbData, blobout.cbData);
        status = 1;
        LocalFree(blobout.pbData);
    }

    if (!status){
        PyErr_Clear();
        PyErr_SetString(PyExc_OSError, "Can't encrypted password");
        return NULL;
    }
    return Py_BuildValue("s#", password_encrypted, blobout.cbData);
}

static PyObject *
crypto_decrypt(PyObject *self, PyObject *args)
{
    const char *password_encrypted;
    const char *password;
    const int non_interactive;
    const int len_encrypted;
    DATA_BLOB blobin;
    DATA_BLOB blobout;
    LPWSTR descr;
    int decrypted = 0;
    int status = 0;

    if (!PyArg_ParseTuple(args, "s#|i", &password_encrypted, &len_encrypted,
                            &non_interactive)){
        PyErr_Clear();
        PyErr_SetString(PyExc_TypeError,
                            "decrypt() must be called as decrypt(password)");
        return NULL;                                                        
    }


    blobin.cbData = len_encrypted;
    blobin.pbData = password_encrypted;
    
    decrypted = CryptUnprotectData(&blobin, &descr, NULL, NULL, NULL,
                    CRYPTPROTECT_UI_FORBIDDEN, &blobout);

    if (decrypted){
        if (0 == lstrcmpW(descr, description)){
            password = string_dump(blobout.pbData,blobout.cbData);
            status = 1;
        }
        LocalFree(blobout.pbData);
        LocalFree(descr);
    }

    if (!status){
        PyErr_Clear();
        PyErr_SetString(PyExc_OSError, "Can't decrypted password");
        return NULL;
    }

    return Py_BuildValue("s",password);    
}

static struct PyMethodDef crypto_methods[] ={
    {"encrypt", crypto_encrypt, METH_VARARGS},
    {"decrypt", crypto_decrypt, METH_VARARGS},
    {NULL,NULL} /* Sentinel */
};

PyMODINIT_FUNC
initwin32_crypto(void)
{
    Py_InitModule("win32_crypto", crypto_methods);
}
