from distutils.command.build_ext import build_ext

# for test only, will be removed when release
from distutils.dist import Distribution

class KeyringBuildExt(build_ext):
    
    def __init__(self,dist):
        build_ext.__init__(self,dist)

    def build_extensions(self):
        pass

if __name__ == '__main__':
    a = KeyringBuildExt(Distribution())
