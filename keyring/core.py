"""
core.py

Created by Kang Zhang on 2009-07-09
"""
import os
try:
    import configparser as config_parser
except ImportError:
    import ConfigParser as config_parser
import imp
import sys

from keyring import logger
from keyring import backend
from keyring.util import platform
from keyring.util import loc_compat


def set_keyring(keyring):
    """Set current keyring backend.
    """
    global _keyring_backend
    if isinstance(keyring, backend.KeyringBackend):
        _keyring_backend = keyring
    else:
        raise TypeError("The keyring must be a subclass of KeyringBackend")

def get_keyring():
    """Get current keyring backend.
    """
    return _keyring_backend

def get_password(service_name, username):
    """Get password from the specified service
    """
    return _keyring_backend.get_password(service_name, username)

def set_password(service_name, username, password):
    """Set password for the user in the specified service
    """
    _keyring_backend.set_password(service_name, username, password)

def init_backend():
    """Load a keyring from a config file or for the default platform.

    First try to load the keyring in the config file, if it has not
    been declared, assign a default keyring according to the platform.
    """
    # select a backend according to the config file
    keyring = load_config()

    # if the user doesn't specify a keyring, we apply a default one
    if keyring is None:

        keyrings = backend.get_all_keyring()
        # rank according to the supported result
        keyrings.sort(key = lambda x: -x.supported())
        # get the most recommended one
        keyring = keyrings[0]

    set_keyring(keyring)


def load_keyring(keyring_path, keyring_name):
    """Load the specified keyring name from the specified path

    `keyring_path` can be None and it will not interfere with the loading
    process.
    """

    def load_module(name, path):
        """Load the specified module from the disk.
        """
        path_list = name.split('.')
        module_info = imp.find_module(path_list[0], path)
        module_file, pathname, description = module_info
        module = imp.load_module(path_list[0], module_file,
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
        module = load_module(keyring_name, sys.path+[keyring_path])

    keyring_class = keyring_name.split('.')[-1].strip()
    keyring_temp = getattr(module, keyring_class)()

    return keyring_temp


def load_config():
    """Load a keyring using the config file.

    The config file can be in the current working directory, or in the user's
    home directory.
    """
    keyring = None

    filename = 'keyringrc.cfg'

    local_path = os.path.join(os.getcwd(), filename)
    legacy_path = os.path.join(os.path.expanduser("~"), filename)
    config_path = os.path.join(platform.data_root(), filename)
    loc_compat.relocate_file(legacy_path, config_path)

    # search from current working directory and the data root
    keyring_cfg_candidates = [local_path, config_path]

    # initialize the keyring_config with the first detected config file
    keyring_cfg = None
    for path in keyring_cfg_candidates:
        keyring_cfg = path
        if os.path.exists(path):
            break

    if os.path.exists(keyring_cfg):
        config = config_parser.RawConfigParser()
        config.read(keyring_cfg)
        # load the keyring-path option
        try:
            if config.has_section("backend"):
                keyring_path = config.get("backend", "keyring-path").strip()
            else:
                keyring_path = None
        except config_parser.NoOptionError:
            keyring_path = None

        # load the keyring class name, and then load this keyring
        try:
            if config.has_section("backend"):
                keyring_name = config.get("backend", "default-keyring").strip()
            else:
                raise config_parser.NoOptionError('backend', 'default-keyring')

            keyring = load_keyring(keyring_path, keyring_name)
        except (config_parser.NoOptionError, ImportError):
            logger.warning("Keyring config file contains incorrect values.\n" +
                           "Config file: %s" % keyring_cfg)

    return keyring

# init the _keyring_backend
init_backend()
