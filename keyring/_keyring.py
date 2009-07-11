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
    keyring = _load_config()

    if keyring is None:
        # TODO set keyring to pure python implementation

        # select a default backend for the platform
        import sys
        platform = sys.platform

        if platform in ['darwin','mac']:
            # for Mac OSX 
            from backend import OSXKeychain
            keyring = OSXKeychain()
        else:
            # detect KDE or Gnome
            import os
            if os.getenv("KDE_FULL_SESSION") == "true":
                # KDE enviroment
                from backend import KDEKWallet 
                keyring = KDEKWallet()
            elif os.getenv("GNOME_DESKTOP_SESSION_ID"):
                # Gnome enviroment
                from backend import GnomeKeyring
                keyring = GnomeKeyring()

    return keyring 

def _load_config():
    keyring = None
    # search from current working directory
    import os,ConfigParser
    keyring_cfg = os.path.join(os.getcwd(),".keyringrc")
    if not os.path.exists(keyring_cfg):
        #search the user's home folder
        home = os.getenv("HOME")
        keyring_cfg = os.path.join(home,".keyringrc")

    if os.path.exists(keyring_cfg):
        config = ConfigParser.RawConfigParser()
        config.read(keyring_cfg)
        try:
            keyring_name = config.get("backend","default-keyring").strip()
            exec "from backend import " + keyring_name 
            exec "keyring = " + keyring_name + "()"
        except ConfigParser.NoOptionError,ImportError:
            print "Keyring Config file does not write correctly.\n" + \
                  "Config file: %s" % keyring_cfg
    
    return keyring 

_keyring_backend = _init_backend()

