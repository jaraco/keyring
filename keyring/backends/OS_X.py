import platform
import subprocess
import re
import binascii

from keyring.backend import KeyringBackend
from keyring.errors import PasswordSetError
from keyring.errors import PasswordDeleteError
from keyring.util import properties

class Keyring(KeyringBackend):
    """Mac OS X Keychain"""

    # regex for extracting password from security call
    password_regex = re.compile("""password:\s*(?:0x(?P<hex>[0-9A-F]+)\s*)?"""
                                """(?:"(?P<pw>.*)")?""")

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        """
        Preferred for all OS X environments.
        """
        if platform.system() != 'Darwin':
            raise RuntimeError("OS X required")
        return 5

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
            output = stderrdata.decode()
            # check for empty password.
            if output == 'password: \n':
                return ''
            # search for special password pattern.
            matches = Keyring.password_regex.search(output)
            if matches:
                group_dict = matches.groupdict()
                hex = group_dict.get('hex')
                pw = group_dict.get('pw')
                if hex:
                    # it's a weird hex password, decode it.
                    return unicode(binascii.unhexlify(hex), 'utf-8')
                else:
                    # it's a normal password, send it back.
                    return pw
            # nothing was found, it doesn't exist.
            return None
        except:
            return None

    @staticmethod
    def delete_password(service, username):
        if username is None:
            username = ''
        try:
            # set up the call for security.
            call = subprocess.Popen([
                    'security',
                    'delete-generic-password',
                    '-a',
                    username,
                    '-s',
                    service
                ],
                stderr = subprocess.PIPE,
                stdout = subprocess.PIPE
            )
            stdoutdata, stderrdata = call.communicate()
            code = call.returncode
            # check return code.
            if code is not 0:
                raise PasswordDeleteError('Can\'t delete password in keychain')
        except:
            raise PasswordDeleteError("Can't delete password in keychain")

