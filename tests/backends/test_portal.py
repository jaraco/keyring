import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from keyring.backends import portal
from keyring.errors import KeyringError, PasswordDeleteError
from keyring.testing.backend import BackendBasicTests
from keyring.testing.util import NoNoneDictMutator

MOCK_MASTER_KEY = b"01234567890123456789012345678901"


class TestPortalKeyring(BackendBasicTests):
    __test__ = True

    def init_keyring(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_storage = Path(self.temp_dir) / "test_keyring.enc"
        backend = portal.Keyring(storage_path=self.temp_storage)
        backend._cached_master_key = MOCK_MASTER_KEY
        return backend

    def cleanup(self):
        super().cleanup()
        if hasattr(self, "temp_dir") and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)


class TestUnits:
    def test_priority_no_xdg_data_home_raises(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(
                RuntimeError, match="XDG_DATA_HOME environment variable required"
            ),
        ):
            _ = portal.Keyring.priority

    def test_priority_no_jeepney_raises(self, tmp_path):
        with (
            patch.dict(os.environ, {"XDG_DATA_HOME": str(tmp_path)}),
            NoNoneDictMutator(portal.__dict__, jeepney=None),
            pytest.raises(RuntimeError, match="jeepney package is required"),
        ):
            _ = portal.Keyring.priority

    def test_priority_no_cryptography_raises(self, tmp_path):
        with (
            patch.dict(os.environ, {"XDG_DATA_HOME": str(tmp_path)}),
            NoNoneDictMutator(portal.__dict__, AESGCM=None),
            pytest.raises(RuntimeError, match="cryptography package is required"),
        ):
            _ = portal.Keyring.priority

    def test_priority_ping_failure_raises(self, tmp_path):
        mock_conn = MagicMock()
        with (
            patch.dict(os.environ, {"XDG_DATA_HOME": str(tmp_path)}),
            patch(
                "keyring.backends.portal.open_dbus_connection", return_value=mock_conn
            ),
            patch.object(portal.Keyring, "_ping_portal", return_value=False),
            pytest.raises(RuntimeError, match="not responding"),
        ):
            _ = portal.Keyring.priority

    def test_priority_connection_error_raises(self, tmp_path):
        with (
            patch.dict(os.environ, {"XDG_DATA_HOME": str(tmp_path)}),
            patch(
                "keyring.backends.portal.open_dbus_connection",
                side_effect=Exception("D-Bus down"),
            ),
            pytest.raises(RuntimeError, match="Unable to access"),
        ):
            _ = portal.Keyring.priority

    def test_priority_success(self, tmp_path):
        mock_conn = MagicMock()
        with (
            patch.dict(os.environ, {"XDG_DATA_HOME": str(tmp_path)}),
            patch(
                "keyring.backends.portal.open_dbus_connection", return_value=mock_conn
            ),
            patch.object(portal.Keyring, "_ping_portal", return_value=True),
        ):
            assert portal.Keyring.priority == 6.0

    def test_ping_portal(self):
        from jeepney.low_level import MessageType

        mock_conn = MagicMock()
        mock_reply = MagicMock()
        mock_reply.header.message_type = MessageType.method_return
        mock_conn.send_and_get_reply.return_value = mock_reply
        assert portal.Keyring._ping_portal(mock_conn) is True

        mock_reply.header.message_type = 2
        assert portal.Keyring._ping_portal(mock_conn) is True

        mock_reply.header.message_type = MessageType.error
        assert portal.Keyring._ping_portal(mock_conn) is False

        mock_reply.header.message_type = 3
        assert portal.Keyring._ping_portal(mock_conn) is False

    def test_call_retrieve_secret_success(self, tmp_path):
        mock_conn = MagicMock()
        mock_conn.unique_name = ":1.100"
        mock_reply = MagicMock()
        mock_reply.header.message_type = 2
        mock_conn.send_and_get_reply.return_value = mock_reply

        mock_sig = MagicMock()
        mock_sig.body = (0, {"token": "some_token"})
        mock_conn.recv_until_filtered.return_value = mock_sig

        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        backend._call_retrieve_secret(mock_conn, 123)
        mock_conn.send_and_get_reply.assert_called_once()
        mock_conn.recv_until_filtered.assert_called_once_with(
            mock_conn.filter.return_value.__enter__.return_value, timeout=None
        )

    def test_call_retrieve_secret_rejected(self, tmp_path):
        mock_conn = MagicMock()
        mock_conn.unique_name = ":1.100"
        mock_reply = MagicMock()
        mock_reply.header.message_type = 3  # Error message
        mock_reply.body = ("org.freedesktop.DBus.Error.Failed",)
        mock_conn.send_and_get_reply.return_value = mock_reply

        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        with pytest.raises(KeyringError, match="rejected request"):
            backend._call_retrieve_secret(mock_conn, 123)

    def test_call_retrieve_secret_user_cancelled(self, tmp_path):
        mock_conn = MagicMock()
        mock_conn.unique_name = ":1.100"
        mock_reply = MagicMock()
        mock_reply.header.message_type = 2
        mock_conn.send_and_get_reply.return_value = mock_reply

        mock_sig = MagicMock()
        mock_sig.body = (1, {})  # User cancelled prompt
        mock_conn.recv_until_filtered.return_value = mock_sig

        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        with pytest.raises(KeyringError, match="failed with response code 1"):
            backend._call_retrieve_secret(mock_conn, 123)

    def test_call_retrieve_secret_response_code_error(self, tmp_path):
        mock_conn = MagicMock()
        mock_conn.unique_name = ":1.100"
        mock_reply = MagicMock()
        mock_reply.header.message_type = 2
        mock_conn.send_and_get_reply.return_value = mock_reply

        mock_sig = MagicMock()
        mock_sig.body = (2, {})  # Error response
        mock_conn.recv_until_filtered.return_value = mock_sig

        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        with pytest.raises(KeyringError, match="failed with response code 2"):
            backend._call_retrieve_secret(mock_conn, 123)

    def test_init_raises_without_xdg_data_home_when_no_storage_path(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(
                RuntimeError, match="XDG_DATA_HOME environment variable is required"
            ),
        ):
            portal.Keyring()

    def test_init_with_xdg_data_home(self, tmp_path):
        with patch.dict(os.environ, {"XDG_DATA_HOME": str(tmp_path)}):
            backend = portal.Keyring()
            assert backend._storage_path == tmp_path / "keyring.enc"

    def test_retrieve_master_key_dbus(self, tmp_path):
        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        r, w = os.pipe()
        os.write(w, MOCK_MASTER_KEY)
        os.close(w)

        mock_conn = MagicMock()
        with (
            patch("os.pipe", return_value=(r, 999)),
            patch("os.close"),
            patch(
                "keyring.backends.portal.open_dbus_connection", return_value=mock_conn
            ),
            patch.object(backend, "_call_retrieve_secret"),
        ):
            key = backend.get_master_key()
            assert key == MOCK_MASTER_KEY
            assert backend.get_master_key() == MOCK_MASTER_KEY

    def test_retrieve_master_key_short_hashes(self, tmp_path):
        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        r, w = os.pipe()
        os.write(w, b"short")
        os.close(w)

        mock_conn = MagicMock()
        with (
            patch("os.pipe", return_value=(r, 999)),
            patch("os.close"),
            patch(
                "keyring.backends.portal.open_dbus_connection", return_value=mock_conn
            ),
            patch.object(backend, "_call_retrieve_secret"),
        ):
            key = backend.get_master_key()
            assert key == hashlib.sha256(b"short").digest()

    def test_retrieve_master_key_empty_raises(self, tmp_path):
        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        r, w = os.pipe()
        os.close(w)

        mock_conn = MagicMock()
        with (
            patch("os.pipe", return_value=(r, 999)),
            patch("os.close"),
            patch("os.read", return_value=b""),
            patch(
                "keyring.backends.portal.open_dbus_connection", return_value=mock_conn
            ),
            patch.object(backend, "_call_retrieve_secret"),
            pytest.raises(KeyringError),
        ):
            backend.get_master_key()

    def test_retrieve_master_key_read_oserror(self, tmp_path):
        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        r, w = os.pipe()
        os.write(w, b"data")
        mock_conn = MagicMock()
        with (
            patch("os.pipe", return_value=(r, w)),
            patch("os.read", side_effect=OSError("pipe read error")),
            patch(
                "keyring.backends.portal.open_dbus_connection", return_value=mock_conn
            ),
            patch.object(backend, "_call_retrieve_secret"),
            pytest.raises(KeyringError, match="Error reading secret from portal pipe"),
        ):
            backend.get_master_key()
        try:
            os.close(r)
            os.close(w)
        except OSError:
            pass

    def test_retrieve_master_key_oserrors_handled(self, tmp_path):
        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        r, w = os.pipe()
        os.write(w, MOCK_MASTER_KEY)
        os.close(w)

        mock_conn = MagicMock()
        with (
            patch("os.pipe", return_value=(r, 999)),
            patch("os.close", side_effect=OSError("close error")),
            patch(
                "keyring.backends.portal.open_dbus_connection", return_value=mock_conn
            ),
            patch.object(backend, "_call_retrieve_secret"),
        ):
            assert backend.get_master_key() == MOCK_MASTER_KEY

    def test_corrupt_storage_file(self, tmp_path):
        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        backend._cached_master_key = MOCK_MASTER_KEY
        (tmp_path / "k.enc").write_bytes(b"corrupt" * 5)
        assert backend.get_password("service", "user") is None

    def test_short_storage_file(self, tmp_path):
        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        backend._cached_master_key = MOCK_MASTER_KEY
        (tmp_path / "k.enc").write_bytes(b"short")
        assert backend.get_password("service", "user") is None

    def test_delete_nonexistent_raises(self, tmp_path):
        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        backend._cached_master_key = MOCK_MASTER_KEY
        with pytest.raises(PasswordDeleteError):
            backend.delete_password("service", "nonexistent")

    def test_get_credential(self, tmp_path):
        backend = portal.Keyring(storage_path=tmp_path / "k.enc")
        backend._cached_master_key = MOCK_MASTER_KEY
        assert backend.get_credential("service", None) is None
        assert backend.get_credential("service", "") is None

        backend.set_password("service", "user", "secret")
        cred = backend.get_credential("service", "user")
        assert cred is not None
        assert cred.username == "user"
        assert cred.password == "secret"
