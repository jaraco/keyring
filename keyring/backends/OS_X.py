import sys
import subprocess
import re
import binascii

from keyring.backend import KeyringBackend
from keyring.errors import PasswordSetError

class Keyring(KeyringBackend):
    """Mac OS X Keychain"""

    def supported(self):
        """Recommended for all OSX environment.
        """
        return sys.platform == 'darwin' or -1

    @staticmethod
    def set_password(service, username, password):
        if username is None:
            username = ''
        try:
            # set up the call for security.
            call = subprocess.Popen([
                    'security',
                    'add-generic-password',
                    '-a',
                    username,
                    '-s',
                    service,
                    '-w',
                    password,
                    '-U'
                ],
                stderr = subprocess.PIPE,
                stdout = subprocess.PIPE,
            )
            stdoutdata, stderrdata = call.communicate()
            code = call.returncode
            # check return code.
            if code is not 0:
                raise PasswordSetError('Can\'t store password in keychain')
        except:
            raise PasswordSetError("Can't store password in keychain")

    @staticmethod
    def get_password(service, username):
        if username is None:
            username = ''
        try:
            # set up the call to security.
            call = subprocess.Popen([
                    'security',
                    'find-generic-password',
                    '-g',
                    '-a',
                    username,
                    '-s',
                    service
                ],
                stderr = subprocess.PIPE,
                stdout = subprocess.PIPE,
            )
            stdoutdata, stderrdata = call.communicate()
            code = call.returncode
            if code is not 0:
                raise OSError("Can't fetch password from system")
            output = stderrdata
            # check for empty password.
            if output == 'password: \n':
                return ''
            # search for special password pattern.
            matches = re.search('password:(?P<hex>.*?)"(?P<pw>.*)"', output)
            if matches:
                hex = matches.group('hex').strip()
                pw = matches.group('pw')
                if hex:
                    # it's a weird hex password, decode it.
                    return binascii.unhexlify(hex[2:])
                else:
                    # it's a normal password, send it back.
                    return pw
            # nothing was found, it doesn't exist.
            return None
        except:
            return None
