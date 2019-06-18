import platform
import asyncio
import shlex
import re

from ..backend import KeyringBackend
from ..errors import PasswordSetError
from ..errors import PasswordDeleteError
from ..errors import KeyringLocked
from ..errors import KeyringError
from ..util import properties

try:
    from . import _OS_X_API as api
except Exception:
    pass


class Keyring(KeyringBackend):
    """macOS Keychain"""

    keychain = None
    "Pathname to keychain filename, overriding default keychain."

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        """
        Preferred for all macOS environments.
        """
        if platform.system() != 'Darwin':
            raise RuntimeError("macOS required")
        return 5

    def set_password(self, service, username, password):
        if username is None:
            username = ''

        try:
            api.set_generic_password(self.keychain, service, username, password)
        except api.KeychainDenied as e:
            raise KeyringLocked("Can't store password on keychain: " "{}".format(e))
        except api.Error as e:
            raise PasswordSetError("Can't store password on keychain: " "{}".format(e))

    def get_password(self, service, username):
        creds={}
        if (not username):
            prompt = "find-generic-password"
            
            if (service.find(".com")>=0):
                prompt = "find-internet-password"
            
            output = execute(
                    'security 2>&1 '+prompt+' -g -s '+service,
                    lambda x: "",
                    lambda x: "",
                    ignore_exit_codes=True
                )

            find_passwd = re.compile('password: "([^"]+)"').search
            find_user = re.compile('"acct"<blob>="([^"]+)"').search
            creds['username'] = find_key(find_user, output)
            creds['password'] = find_key(find_passwd, output)

        else:
            try:
                if (service.find(".com")):
                    creds['password'] = api.find_internet_password(self.keychain, service, username)
                else:
                    creds['password'] = api.find_generic_password(self.keychain, service, username)
                creds['username'] = username
            except api.NotFound:
                pass
            except api.KeychainDenied as e:
                raise KeyringLocked("Can't get password from keychain: " "{}".format(e))
            except api.Error as e:
                raise KeyringError("Can't get password from keychain: " "{}".format(e))

        return creds

    def delete_password(self, service, username):
        if username is None:
            username = ''

        try:
            return api.delete_generic_password(self.keychain, service, username)
        except api.Error as e:
            raise PasswordDeleteError(
                "Can't delete password in keychain: " "{}".format(e)
            )
            
            
# added functions coppied from local-pipeline-utils common.py 
async def _read_stream(stream, cb):
    full_output = ''
    buffered_chunk = []
    while True:
        chunk = await stream.read(64 * 1024)
        if chunk:
            decoded_chunk = chunk.decode('utf-8')
            full_output += decoded_chunk
            if '\n' in decoded_chunk or '\r' in decoded_chunk:
                write_chunk = b''.join(buffered_chunk) + chunk
                write_string = write_chunk.decode('utf-8')
                for l1 in write_string.split('\n'):
                    if not l1:
                        continue
                    for l2 in l1.split('\r'):
                        if l2:
                            cb(l2.encode())
                buffered_chunk.clear()
            else:
                buffered_chunk.append(chunk)
        else:
            break
    cb(b''.join(buffered_chunk))
    return full_output
 
 
async def _stream_subprocess(cmd, stdout_cb, stderr_cb, env=None):
    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
    )
    (stdout, stderr) = await asyncio.gather(
        _read_stream(process.stdout, stdout_cb),
        _read_stream(process.stderr, stderr_cb)
    )
    exit_code = await process.wait()
    return (stdout, stderr, exit_code)
 
 
def sub_exec(cmd, stdout_cb, stderr_cb, env=None, ignore_exit_codes=False):
    if asyncio.get_event_loop().is_closed():
        asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    (stdout, stderr, exit_code) = loop.run_until_complete(
        _stream_subprocess(
            cmd,
            stdout_cb,
            stderr_cb,
            env=env
        ))
    if not ignore_exit_codes and exit_code != 0:
        raise Exception('Non-zero return code')
    loop.close()
    return stdout
 
 
def execute(cmds, stdout_cb, stderr_cb, env=None, ignore_exit_codes=False, print_commands=False):
    # if print_commands:
    #     cmds = add_echo_commands(cmds)
    command = shlex.split(f"bash -c ")
    command.append(f'set -e; {cmds}')
    output = sub_exec(command, stdout_cb, stderr_cb,
                      env=env, ignore_exit_codes=ignore_exit_codes)
    return output
 
def find_key(fn, out):
    match = fn(out)
    return match and match.group(1)
