"""
core.py

Created by Kang Zhang on 2009-07-09
"""
import os
import ConfigParser
import imp
import sys

from keyring import logger
from keyring import backend

def set_keyring(keyring):
    """Set current keyring backend.
    """
    global _keyring_backend
    if isinstance(keyring, backend.KeyringBackend):
        _keyring_backend = keyring
    else: raise TypeError("The keyring must be a subclass of KeyringBackend")

def get_keyring():
    """Get current keyring backend.
    """
    return _keyring_backend

def get_password(service_name, username):
    """Get password from the specified service
    """
    return _keyring_backend.get_password(service_name, username)

def set_password(service_name, username, password):
    """Set password for the user in the spcified service
    """
    _keyring_backend.set_password(service_name, username, password)

def init_backend():
    """first try to load the keyring in the config file, if it has not
    been decleared, assign a defult keyring according to the platform.
    """
    #select a backend according to the config file
    keyring = load_config()

    # if the user dose not specify a keyring, we apply a default one
    if keyring is None:

        keyrings = backend.get_all_keyring()
        # rank according the supported
        keyrings.sort(lambda x, y: y.supported() - x.supported())
        # get the most recommend one
        keyring = keyrings[0]

    set_keyring(keyring)

def load_config():
    """load a keyring using the config file, the config file can be
    in the current working directory, or in the user's home directory.
    """
    keyring = None

    # search from current working directory and the home folder
    keyring_cfg_list = [os.path.join(os.getcwd(), "keyringrc.cfg"),
                        os.path.join(os.path.expanduser("~"), "keyringrc.cfg")]
    # initial the keyring_cfg with the fist detected config file
    keyring_cfg = None
    for path in keyring_cfg_list:
        keyring_cfg = path
        if os.path.exists(path):
            break

    if os.path.exists(keyring_cfg):
        config = ConfigParser.RawConfigParser()
        config.read(keyring_cfg)
        # load the keyring-path option
        try:
            if config.has_section("backend"):
                keyring_path = config.get("backend", "keyring-path").strip()
            else:
                keyring_path = None
        except ConfigParser.NoOptionError:
            keyring_path = None

        # load the keyring class name, and load it
        try:
            if config.has_section("backend"):
                keyring_name = config.get("backend", "default-keyring").strip()
            else:
                raise ConfigParser.NoOptionError('backend', 'default-keyring')

            def load_module(name, path):
                """Load the specified module from the disk.
                """
                path_list = name.split('.')
                module_info = imp.find_module(path_list[0], path)
                module_file, pathname, description = module_info
                module = imp.load_module(path_list[0], module_file, \
                                                          pathname, description)
                if module_file:
                    module_file.close()

                if len(path_list) > 1:
                    # for the class name containing dots
                    sub_name = '.'.join(path_list[1:])
                    sub_path = path

                    try:
                        sub_path = path + module.__path__
                    except AttributeError:
                        return module

                    return load_module(sub_name, sub_path)
                return module

            try:
                # avoid import the imported modules
                module = sys.modules[keyring_name[:keyring_name.rfind('.')]]
            except KeyError:
                module = load_module( keyring_name, sys.path+[keyring_path])

            keyring_class = keyring_name.split('.')[-1].strip()
            exec  "keyring_temp = module." + keyring_class + "() " in locals()

            keyring = keyring_temp
        except (ConfigParser.NoOptionError, ImportError):
            logger.warning("Keyring Config file does not write correctly.\n" + \
                           "Config file: %s" % keyring_cfg)

    return keyring

# init the _keyring_backend
init_backend()

