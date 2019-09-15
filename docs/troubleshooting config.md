# Troubleshooting Config

What do you do if you've set up your config file but

## Double-check location

When keyring runs, it invokes init_backend which attempts to load a backend either as indicated by the environment, the config, or using heuristics [based on priorities](https://github.com/jaraco/keyring/blob/053e79bc101c45af2b86fb2c323bfb3e96a083cc/keyring/core.py#L93-L97).

Assuming no config is detected from environment variables (it might be worth double-checking), when loading from config, it determines the filename by calling [`keyring.util._platform.config_root()`](https://github.com/jaraco/keyring/blob/053e79bc101c45af2b86fb2c323bfb3e96a083cc/keyring/core.py#L152), which as you can see varies by platform.

Unless you're on Mac or Windows, the [Linux behavior is used](https://github.com/jaraco/keyring/blob/053e79bc101c45af2b86fb2c323bfb3e96a083cc/keyring/util/platform_.py#L53-L62). That setting also is dependent on the environment. If `XDG_CONFIG_HOME` is configured, that is where it will be looking for the config file. If not, it will look for it in `~/.local/share` (however that resolves using `os.expanduser`). The config file is always named "python_keyring".

All of this is to say that there are many variables that go into detecting where the config file should be located.

To directly detect where the config file is expected, in the Python environment in which your application is run, you should execute `keyring.util.platform_.config_root()`. That should definitively indicate where you should put the config file.
