import platform
import subprocess
import re
import binascii
import functools
import warnings
import textwrap

from ..backend import KeyringBackend
from ..errors import PasswordSetError
from ..errors import PasswordDeleteError
from ..util import properties
from ..py27compat import unicode_str


class SecurityCommand(unicode_str):
    """
    A string suitable for passing as the 'command' parameter to the
    OS X 'security' command.
    """
    def __new__(cls, cmd, store='generic'):
        cls._warn_not_generic(store)
        cmd = '%(cmd)s-%(store)s-password' % vars()
        return super(SecurityCommand, cls).__new__(cls, cmd)

    @staticmethod
    def _warn_not_generic(store):
        """
        In https://github.com/jaraco/keyring/issues/217#issuecomment-204756523,
        Jason observes that the 'internet' store may not be in use at all,
        so this warning serves as a notice that the functionality will
        go away unless users respond that this functionality is in use.
        """
        if store == 'generic':
            return

        msg = textwrap.dedent("""
            {store} password support is being dropped.
            If you rely on this behavior, please report your use
            case at https://github.com/jaraco/keyring/issues/217
            to avoid losing this feature.
            """).lstrip().format(**locals())
        warnings.warn(msg)


class Keyring(KeyringBackend):
    """Mac OS X Keychain"""

    # regex for extracting password from security call
    password_regex = re.compile("""password:\s*(?:0x(?P<hex>[0-9A-F]+)\s*)?"""
                                """(?:"(?P<pw>.*)")?""")
    store = 'generic'

    keychain = None
    "Pathname to keychain filename, overriding default keychain."

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        """
        Preferred for all OS X environments.
        """
        if platform.system() != 'Darwin':
            raise RuntimeError("OS X required")
        return 5

    def set_password(self, service, username, password):
        if username is None:
            username = ''
        try:
            # This two-step process is a stop-gap measure until a ctypes
            # implementation can be created. Fall back to the
            # command-line version when the username/service/password
            # strings contain characters (escapes, newlines, etc.) that
            # the interactive security session can't handle.
            interactive_call = functools.partial(self._interactive_set,
                service, username, password)
            direct_call = functools.partial(self._direct_set,
                service, username, password)
            code = interactive_call() and direct_call()
            # check return code
            if code:
                raise Exception()
        except Exception:
            raise PasswordSetError("Can't store password in keychain")

    def _interactive_set(self, service, username, password):
        """
        Call the security command, supplying parameters through
        the input stream to avoid revealing the password in the
        process status.
        """
        cmd = [
            'security',
            '-i'
        ]
        security_cmd = "{} -a '{}' -s '{}' -p '{}' -U\n".format(
            SecurityCommand('add', self.store),
            username, service, password)
        call = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        stdoutdata, stderrdata = call.communicate(
            security_cmd.encode('utf-8'))
        return call.returncode

    def _direct_set(self, service, username, password):
        """
        Call the security command, supplying the parameters on
        the command line.
        """
        cmd = [
            'security',
            SecurityCommand('add', self.store),
            '-a', username,
            '-s', service,
            '-w', password,
            '-U',
        ]
        call = subprocess.Popen(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        stdoutdata, stderrdata = call.communicate()
        return call.returncode

    def get_password(self, service, username):
        if username is None:
            username = ''
        try:
            # set up the call to security.
            cmd = [
                'security',
                SecurityCommand('find', self.store),
                '-g',
                '-a', username,
                '-s', service,
            ]
            if self.keychain:
                cmd.append(self.keychain)
            call = subprocess.Popen(
                cmd,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE)
            stdoutdata, stderrdata = call.communicate()
            code = call.returncode
            if code != 0:
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
                    return unicode_str(binascii.unhexlify(hex), 'utf-8')
                else:
                    # it's a normal password, send it back.
                    return pw
            # nothing was found, it doesn't exist.
        except:
            pass

    def delete_password(self, service, username):
        del_error = PasswordDeleteError("Can't delete password in keychain")
        if username is None:
            username = ''
        try:
            cmd = [
                'security',
                SecurityCommand('delete', self.store),
                '-a', username,
                '-s', service,
            ]
            # set up the call for security.
            call = subprocess.Popen(
                cmd,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE)
            stdoutdata, stderrdata = call.communicate()
            code = call.returncode
            # check return code.
            if code != 0:
                raise del_error
        except:
            raise del_error
