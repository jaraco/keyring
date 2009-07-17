"""
_keyring.py

Created by Kang Zhang on 2009-07-09
"""

def set_keyring( keyring ):
    """Set current keyring backend. 
    """
    import backend
    global _keyring_backend
    if isinstance(keyring, backend.KeyringBackend):
        _keyring_backend = keyring
    else: raise TypeError("The keyring must be a subclass of KeyringBackend")

def get_keyring():
    """Get current keyring backend.
    """
    return _keyring_backend

def getpass(service_name, username):
    """Get password from """
    return _keyring_backend.getpass(service_name,username)

def setpass(service_name,username,password):
    return _keyring_backend.setpass(service_name,username,password)

def _init_backend():
    """first try to load the keyring in the config file, if it has not 
    been decleared, assign a defult keyring according to the platform.
    """
    #select a backend according to the config file
    keyring_impl = _load_config()

    # if the user dose not specify a keyring, we apply a default one
    if keyring_impl is None:
        import backend

        keyrings = backend.get_all_keyring()
        # rank according the supported
        keyrings.sort(lambda x,y: y.supported() - x.supported())
        # get the most recommend one
        keyring_impl = keyrings[0]

    return keyring_impl 

def _load_config():
    """load a keyring using the config file, the config file can be 
    in the current working directory, or in the user's home directory.
    """
    import os,ConfigParser
    keyring_impl = None

    # search from current working directory and the home folder
    keyring_cfg_list = [os.path.join(os.getcwd(),".keyringrc"),
                        os.path.join(os.getenv("HOME"),".keyringrc")]
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
        try: keyring_path = config.get("backend","keyring-path").strip()
        except ConfigParser.NoOptionError: keyring_path = None
        # load the keyring class name, and load it
        try:
            keyring_name = config.get("backend","default-keyring").strip()

            import imp,sys,backend
            def find_module(name, path):
                pl = name.split('.')
                fp, pathname, description = imp.find_module(pl[0],path)
                module = imp.load_module(pl[0], fp, pathname, description)
                if fp: fp.close()
                #print module.__path__
                if len(pl) > 1:
                    # for the class name containing dots
                    sub_name = '.'.join(pl[1:])
                    sub_path = path

                    try: sub_path = path + module.__path__
                    except AttributeError: return module
                    
                    return find_module(sub_name,sub_path)
                return module
            
            try:
                # avoid import the imported modules
                module = sys.modules[keyring_name[:keyring_name.rfind('.')]]
            except KeyError: 
                module = find_module( keyring_name, sys.path+[keyring_path])

            keyring_class = keyring_name.split('.')[-1].strip()
            exec  "keyring_temp = module." + keyring_class + "() " in locals()

            if isinstance(keyring_temp,backend.KeyringBackend):
                keyring_impl = keyring_temp
            else:
                # throw a error if the class is not a keyring
                raise TypeError("%s must be a instance of KeyringBackend" % keyring_name)
        except ConfigParser.NoOptionError,ImportError:
            print "Keyring Config file does not write correctly.\n" + \
                  "Config file: %s" % keyring_cfg
    
    return keyring_impl

# init the _keyring_backend
_keyring_backend = _init_backend()

