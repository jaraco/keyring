def set_keyring( keyring ):
    from backend import KeyringBackend
    if instanceof(keyring, KeyringBackend):
        _keyring_backend = keyring
    else: raise TypeError("The keyring must be a subclass of KeyringBackend")

def get_keyring():
    return _keyring_backend

def getpass(service_name, username):
    return _keyring_backend.getpass(service_name,username)

def setpass(service_name,username,password):
    _keyring_backend.setpass(service_name,username,password)

def _init_backend():
    # select a backend according to the config file
    keyring_impl = _load_config()

    # if the user dose not specify a keyring, we apply a default one
    if keyring_impl is None:
        # TODO set keyring to pure python implementation

        # select a default backend for the platform
        import sys
        platform = sys.platform

        if platform in ['darwin','mac']:
            # for Mac OSX 
            from backend import OSXKeychain
            keyring_impl = OSXKeychain()
        else:
            # detect KDE or Gnome
            import os
            if os.getenv("KDE_FULL_SESSION") == "true":
                # KDE enviroment
                from backend import KDEKWallet 
                keyring_impl = KDEKWallet()
            elif os.getenv("GNOME_DESKTOP_SESSION_ID"):
                # Gnome enviroment
                from backend import GnomeKeyring
                keyring_impl = GnomeKeyring()

    return keyring_impl 

def _load_config():
    import os,ConfigParser

    keyring_impl = None

    # search from current working directory
    keyring_cfg_list = [os.path.join(os.getcwd(),".keyringrc"),
                        os.path.join(os.getenv("HOME"),".keyringrc")]
    keyring_cfg = None
    for path in keyring_cfg_list:
        keyring_cfg = path
        if os.path.exists(path):
            break

    if os.path.exists(keyring_cfg):
        config = ConfigParser.RawConfigParser()
        config.read(keyring_cfg)
        # load the keyring-path option 
        try: keyring_path = config.get("backend","keyring-path").strip()
        except ConfigParser.NoOptionError: keyring_path = None
        # load the keyring class name, and load it
        try:
            keyring_name = config.get("backend","default-keyring").strip()

            import imp
            def find_module(name, path):
                pl = name.split('.')
                fp, pathname, description = imp.find_module(pl[0],path)
                module = imp.load_module(pl[0], fp, pathname, description)
                #print module.__path__
                if len(pl) > 1:
                    # for the class name containing dots
                    sub_name = '.'.join(pl[1:])
                    sub_path = path

                    try: sub_path = module.__path__ 
                    except AttributeError: return module

                    return find_module(sub_name,sub_path)
                return module

            module = find_module( keyring_name, keyring_path)
            keyring_class = keyring_name.split('.')[-1]

            exec "keyring_impl = module." + keyring_class + "()" in locals()
        except ConfigParser.NoOptionError,ImportError:
            print "Keyring Config file does not write correctly.\n" + \
                  "Config file: %s" % keyring_cfg
    
    return keyring_impl

_keyring_backend = _init_backend()

