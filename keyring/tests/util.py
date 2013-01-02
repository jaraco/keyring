
import sys

class ImportKiller(object):
    "Context manager to make an import of a given name or names fail."
    def __init__(self, *names):
        self.names = names
    def find_module(self, fullname, path=None):
        if fullname in self.names:
            return self
    def load_module(self, fullname):
        assert fullname in self.names
        raise ImportError(fullname)
    def __enter__(self):
        self.original = {}
        for name in self.names:
            self.original[name] = sys.modules.pop(name, None)
        sys.meta_path.append(self)
    def __exit__(self, *args):
        sys.meta_path.remove(self)
        for key, value in self.original.items():
            if value is not None:
                sys.modules[key] = value
