/*
 * Comment by Kang. This lib dose not support non_interactive mode
 */
#include <glib.h>
#include <dbus/dbus.h>
#include <gnome-keyring.h>

#include "Python.h"
#include "keyring_util.h"

static PyObject*
gnome_keyring_password_get(PyObject *self, PyObject *args)
{
    const char *realmstring;
    const char *username;
    const char *password;

    if (!PyArg_ParseTuple(args, "ss", &realmstring, &username)){
        PyErr_Clear();
        PyErr_SetString(PyExc_TypeError, 
                "password_get() must be called as (servicename,username)");
        return NULL;
    }
    if ((! dbus_bus_get(DBUS_BUS_SESSION,NULL)) || 
            (!gnome_keyring_is_available())){
        PyErr_Clear();
        PyErr_SetString(PyExc_OSError, "Can's access the keyring now");
        return NULL;
    }

    GnomeKeyringResult result;
    GList *items;

    result = gnome_keyring_find_network_password_sync(username, realmstring, 
                                           NULL, NULL, NULL, NULL, 0, &items);

    int status = 0;
    if (result == GNOME_KEYRING_RESULT_OK){
        if (items && items->data){
            GnomeKeyringNetworkPasswordData *item;
            item = (GnomeKeyringNetworkPasswordData *)items->data;
            if (item->password){
                size_t len = strlen(item->password);
                password = string_dump(item->password, len);
                status = 1;
            }
            gnome_keyring_network_password_list_free(items);
    }
    }  

    if (!status){
        PyErr_Clear();
        PyErr_SetString(PyExc_OSError, "Can't fech password from system");
        return NULL;
    }
    
    return Py_BuildValue("s",password); 
}
static PyObject*
gnome_keyring_password_set(PyObject *self, PyObject *args)
{
    const char *realmstring;
    const char *username;
    const char *password;

    if (!PyArg_ParseTuple(args, "sss", &realmstring, &username, &password)){
        PyErr_Clear();
        PyErr_SetString(PyExc_TypeError,
            "password_set() must be called as (servicename,username,password)");
        return NULL;
    }
    if ((! dbus_bus_get(DBUS_BUS_SESSION,NULL)) || 
            (!gnome_keyring_is_available())){
        PyErr_Clear();
        PyErr_SetString(PyExc_OSError,
            "Can's access the keyring now");
        return NULL;
    }


    GnomeKeyringResult result;
    guint32 item_id;

    result = gnome_keyring_set_network_password_sync(NULL, username, realmstring,
                                     NULL, NULL, NULL, NULL, 0, password, &item_id);

    return Py_BuildValue("i", (result!=GNOME_KEYRING_RESULT_OK));
}


static struct PyMethodDef gnome_keyring_methods[] = {
    {"password_set", gnome_keyring_password_set, METH_VARARGS},
    {"password_get", gnome_keyring_password_get, METH_VARARGS},
    {} /* Sentinel */
};

static void
init_application_name(void)
{
    const char *application_name = NULL; 
    application_name = g_get_application_name();
    if (!application_name)
        g_set_application_name("Python");
}

PyMODINIT_FUNC
initgnome_keyring(void)
{
    init_application_name();
    Py_InitModule("gnome_keyring", gnome_keyring_methods);
}
