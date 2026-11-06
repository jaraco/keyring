import hashlib
import json
import logging
import os
import tempfile
import uuid
from pathlib import Path

from jaraco.context import ExceptionTrap

from ..backend import KeyringBackend
from ..compat import properties
from ..credentials import SimpleCredential
from ..errors import KeyringError, PasswordDeleteError

try:
    import jeepney
    from jeepney import DBusAddress, MatchRule, new_method_call
    from jeepney.io.blocking import open_dbus_connection
except ImportError:
    pass

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    pass

log = logging.getLogger(__name__)

PORTAL_BUS_NAME = "org.freedesktop.portal.Desktop"
PORTAL_OBJECT_PATH = "/org/freedesktop/portal/desktop"
PORTAL_INTERFACE = "org.freedesktop.portal.Secret"


class Keyring(KeyringBackend):
    """
    Keyring backend that integrates with the XDG Desktop Portal Secret service.

    Provides isolated credential storage for sandboxed applications (e.g. Flatpak)
    by requesting a master encryption key from org.freedesktop.portal.Secret and storing
    passwords encrypted with AES-256-GCM in the application's XDG_DATA_HOME.
    """

    def __init__(self, storage_path: Path | None = None) -> None:
        if storage_path is not None:
            self._storage_path = Path(storage_path)
        else:
            xdg_data = os.environ.get("XDG_DATA_HOME")
            if not xdg_data:
                raise RuntimeError(
                    "XDG_DATA_HOME environment variable is required for PortalKeyring "
                    "when storage_path is not explicitly provided"
                )
            self._storage_path = Path(xdg_data) / "keyring.enc"

        self._cached_master_key: bytes | None = None

    @properties.classproperty
    def priority(cls) -> float:
        """
        Priority of this backend.

        Returns 6.0 when running in a sandboxed environment with active portal,
        taking precedence over unconfined SecretService (priority 5).
        Raises RuntimeError otherwise.
        """
        if not os.environ.get("XDG_DATA_HOME"):
            raise RuntimeError(
                "XDG_DATA_HOME environment variable required (sandboxed environment)"
            )

        with ExceptionTrap() as exc:
            jeepney.__name__  # noqa: B018
        if exc:
            raise RuntimeError("jeepney package is required for PortalKeyring")

        with ExceptionTrap() as exc:
            AESGCM.__name__  # noqa: B018
        if exc:
            raise RuntimeError("cryptography package is required for PortalKeyring")

        try:
            with open_dbus_connection(bus="SESSION", enable_fds=True) as conn:
                if not cls._ping_portal(conn):
                    raise RuntimeError(
                        "org.freedesktop.portal.Secret is not responding"
                    )
        except Exception as exc:
            raise RuntimeError(
                f"Unable to access Desktop Portal Secret service: {exc}"
            ) from exc

        return 6.0

    @classmethod
    def _ping_portal(cls, connection, timeout: float = 2.0) -> bool:
        """Pings the desktop portal interface via D-Bus Peer ping."""
        peer_addr = DBusAddress(
            PORTAL_OBJECT_PATH,
            bus_name=PORTAL_BUS_NAME,
            interface="org.freedesktop.DBus.Peer",
        )
        msg = new_method_call(peer_addr, "Ping")
        reply = connection.send_and_get_reply(msg, timeout=timeout)
        msg_type = getattr(
            reply.header.message_type, "value", reply.header.message_type
        )
        return bool(msg_type == 2)  # Method return (MessageType.method_return)

    def _call_retrieve_secret(self, connection, write_fd: int) -> None:
        """Invokes RetrieveSecret on the portal interface and waits for the Response signal."""
        token = f"k_{uuid.uuid4().hex[:12]}"
        unique_name = str(getattr(connection, "unique_name", ":1.0"))
        sender = unique_name.lstrip(":").replace(".", "_")
        expected_path = f"/org/freedesktop/portal/desktop/request/{sender}/{token}"

        rule = MatchRule(
            type="signal",
            interface="org.freedesktop.portal.Request",
            member="Response",
            path=expected_path,
        )

        portal_addr = DBusAddress(
            PORTAL_OBJECT_PATH,
            bus_name=PORTAL_BUS_NAME,
            interface=PORTAL_INTERFACE,
        )
        msg = new_method_call(
            portal_addr,
            "RetrieveSecret",
            "ha{sv}",
            (write_fd, {"handle_token": ("s", token)}),
        )

        with connection.filter(rule) as matches:
            reply = connection.send_and_get_reply(msg, timeout=10.0)
            msg_type = getattr(
                reply.header.message_type, "value", reply.header.message_type
            )
            if msg_type != 2:
                raise KeyringError(
                    f"XDG Desktop Portal RetrieveSecret rejected request: {getattr(reply, 'body', None)}"
                )

            # Close local write descriptor so only the portal holds it open
            try:
                os.close(write_fd)
            except OSError:
                pass

            sig = connection.recv_until_filtered(matches, timeout=None)

            response_code = sig.body[0] if sig.body and len(sig.body) > 0 else 2
            if response_code != 0:
                raise KeyringError(
                    f"XDG Desktop Portal Secret request failed with response code {response_code}"
                )

    def get_master_key(self) -> bytes:
        """Retrieves and caches the 32-byte master key from the portal."""
        if self._cached_master_key is not None:
            return self._cached_master_key

        read_fd, write_fd = os.pipe()
        try:
            with open_dbus_connection(bus="SESSION", enable_fds=True) as conn:
                self._call_retrieve_secret(conn, write_fd)
        finally:
            try:
                os.close(write_fd)
            except OSError:
                pass

        try:
            raw_secret = os.read(read_fd, 1024)
        except OSError as exc:
            raise KeyringError(f"Error reading secret from portal pipe: {exc}") from exc
        finally:
            try:
                os.close(read_fd)
            except OSError:
                pass

        if not raw_secret:
            raise KeyringError("Empty secret returned from XDG Desktop Portal")

        if len(raw_secret) == 32:
            master_key = raw_secret
        else:
            master_key = hashlib.sha256(raw_secret).digest()

        self._cached_master_key = master_key
        return master_key

    def _load_storage(self) -> dict[str, str]:
        """Reads and decrypts the credentials mapping from disk."""
        if not self._storage_path.exists():
            return {}

        try:
            data = self._storage_path.read_bytes()
            if len(data) < 28:  # 12 bytes nonce + 16 bytes auth tag minimum
                return {}

            nonce = data[:12]
            ciphertext = data[12:]
            key = self.get_master_key()
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            return json.loads(decrypted_bytes.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not decrypt keyring store: %s", exc)
            return {}

    def _save_storage(self, mapping: dict[str, str]) -> None:
        """Encrypts and atomically writes the credentials mapping to disk."""
        key = self.get_master_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        payload = json.dumps(mapping).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, payload, associated_data=None)

        self._storage_path.parent.mkdir(parents=True, exist_ok=True)

        temp_dir = self._storage_path.parent
        with tempfile.NamedTemporaryFile(dir=temp_dir, delete=False) as tf:
            tf.write(nonce + ciphertext)
            temp_path = Path(tf.name)

        os.replace(temp_path, self._storage_path)

    def get_password(self, service: str, username: str) -> str | None:
        """Gets password for the username on service."""
        storage = self._load_storage()
        return storage.get(f"{service}:{username}")

    def set_password(self, service: str, username: str, password: str) -> None:
        """Sets password for the username on service."""
        storage = self._load_storage()
        storage[f"{service}:{username}"] = password
        self._save_storage(storage)

    def delete_password(self, service: str, username: str) -> None:
        """Deletes password for the username on service."""
        storage = self._load_storage()
        key = f"{service}:{username}"
        if key not in storage:
            raise PasswordDeleteError("No such password!")
        del storage[key]
        self._save_storage(storage)

    def get_credential(
        self, service: str, username: str | None
    ) -> SimpleCredential | None:
        """Gets credential for a service and username."""
        if not username:
            return None
        password = self.get_password(service, username)
        if password is None:
            return None
        return SimpleCredential(username, password)


PortalKeyring = Keyring
