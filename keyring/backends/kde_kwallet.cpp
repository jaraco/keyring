#include <dbus/dbus.h>
#include <QtCore/QCoreApplication>
#include <QtCore/QString>

#include <kwallet.h>

#include "Python.h"
#include "keyring_util.h"

static PyObject *
kde_kwallet_password_get(PyObject *self, PyObject *args)
{
    const char *realmstring;
    const char *username;
    const char *password;
    bool non_interactive = false;

    if (!PyArg_ParseTuple(args, "ss|i", &realmstring, &username, 
            &non_interactive)){
        PyErr_Clear();
        PyErr_SetString(PyExc_TypeError,
                        "password_get() must be called as (service,username)");
        return NULL;
    }

    if (non_interactive || (!dbus_bus_get(DBUS_BUS_SESSION,NULL))){
        PyErr_Clear();
        PyErr_SetString(PyExc_OSError,"can't get access to dbus");
        return NULL;
    }
    
    QCoreApplication *app;
    if (!qApp) {
        int argc = 1;
        app = new QCoreApplication(argc, (char *[1]){ (char*) "python"});
    }
    QString folder = QString::fromUtf8("Python");
    QString key = QString::fromUtf8(username) + "@" + QString::fromUtf8(realmstring);
    QString wallet_name = KWallet::Wallet::NetworkWallet();
    bool fetch_success = false;
    if (!KWallet::Wallet::keyDoesNotExist(wallet_name, folder, key)){
        KWallet::Wallet *wallet = KWallet::Wallet::openWallet(wallet_name, -1, 
                                                KWallet::Wallet::Synchronous); 
        if (wallet){
            if (wallet->setFolder(folder)){
                QString q_password;
                if (wallet->readPassword(key, q_password) == 0){
                    password = string_dump(q_password.toUtf8().data(), q_password.size());
                    fetch_success = true;
                }
            }
        }
    }
    if (!fetch_success){
        PyErr_Clear();
        PyErr_SetString(PyExc_OSError, "Can't access the password from the system");
        return NULL;
    }
    return Py_BuildValue("s",password);
}

static PyObject *
kde_kwallet_password_set(PyObject *self, PyObject *args)
{
    const char *realmstring;
    const char *username;
    const char *password;
    bool non_interactive = false;

    if (!PyArg_ParseTuple(args,"sss|i", &realmstring, &username, &password, 
            &non_interactive)){
        PyErr_Clear();
        PyErr_SetString(PyExc_TypeError,
            "password_set() must be called as (service,username,password)");
        return NULL;
    }
    if (non_interactive || (!dbus_bus_get(DBUS_BUS_SESSION,NULL))){
        PyErr_Clear();
        PyErr_SetString(PyExc_OSError, "can't get access to dbus");
        return NULL;
    }
    QCoreApplication *app;
    if (! qApp){
        int argc = 1;
        app = new QCoreApplication(argc,(char *[1]) {(char*) "Python"});
    }

    bool write_success = false;
    QString q_password = QString::fromUtf8(password);
    QString wallet_name = KWallet::Wallet::NetworkWallet();
    QString folder = QString::fromUtf8("Python");
    KWallet::Wallet *wallet = KWallet::Wallet::openWallet(wallet_name, -1, 
                                            KWallet::Wallet::Synchronous);
    if (wallet){
        if (!wallet->hasFolder(folder)){
            wallet->createFolder(folder);
        }
        if (wallet->setFolder(folder)){
            QString key = QString::fromUtf8(username) + "@" + QString::fromUtf8(realmstring);
            if (wallet->writePassword(key, q_password) == 0){
                write_success = true;
            }
        }
    }
    return Py_BuildValue("i", write_success != false);
}


static struct PyMethodDef kde_kwallet_methods[] = {
    {"password_set", kde_kwallet_password_set, METH_VARARGS},
    {"password_get", kde_kwallet_password_get, METH_VARARGS},
    {NULL,NULL}/* Sentinel */
};

PyMODINIT_FUNC
initkde_kwallet(void)
{
    Py_InitModule("kde_kwallet", kde_kwallet_methods);
}
