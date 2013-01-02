# -*- coding: utf-8 -*-
"""
test_backend.py

Test case for keyring basic function

created by Kang Zhang 2009-07-14
"""
from __future__ import with_statement

import base64
import codecs
import cPickle
import os
import random
import string
import sys
import tempfile

from .py30compat import unittest
from .util import ImportKiller, Environ

import keyring.backend
from keyring.util import escape

from keyring.tests import mocks

ALPHABET = string.ascii_letters + string.digits
DIFFICULT_CHARS = string.whitespace + string.punctuation
UNICODE_CHARS = escape.u("""κόσμεНа берегу пустынных волнSîne klâwen durh die
wolken sint geslagen, er stîget ûf mit grôzer kraft""")

def random_string(k, source = ALPHABET):
    """Generate a random string with length <i>k</i>
    """
    result = ''
    for i in range(0, k):
        result += random.choice(source)
    return result


def is_dbus_supported():
    try:
        __import__('dbus')
    except ImportError:
        return False
    return 'DISPLAY' in os.environ

def is_gdata_supported():
    try:
        __import__('gdata.service')
    except ImportError:
        return False
    return True

class BackendBasicTests(object):
    """Test for the keyring's basic funtions. password_set and password_get
    """

    def setUp(self):
        self.keyring = self.init_keyring()
        self.credentials_created = set()

    def set_password(self, service, username, password):
        # set the password and save the result so the test runner can clean
        #  up after if necessary.
        self.keyring.set_password(service, username, password)
        self.credentials_created.add((service, username))

    def check_set_get(self, service, username, password):
        keyring = self.keyring

        # for the non-existent password
        self.assertEqual(keyring.get_password(service, username), None)

        # common usage
        self.set_password(service, username, password)
        self.assertEqual(keyring.get_password(service, username), password)

        # for the empty password
        self.set_password(service, username, "")
        self.assertEqual(keyring.get_password(service, username), "")

    def test_password_set_get(self):
        password = random_string(20)
        username = random_string(20)
        service = random_string(20)
        self.check_set_get(service, username, password)

    def test_difficult_chars(self):
        password = random_string(20, DIFFICULT_CHARS)
        username = random_string(20, DIFFICULT_CHARS)
        service = random_string(20, DIFFICULT_CHARS)
        self.check_set_get(service, username, password)

    def test_unicode_chars(self):
        password = random_string(20, UNICODE_CHARS)
        username = random_string(20, UNICODE_CHARS)
        service = random_string(20, UNICODE_CHARS)
        self.check_set_get(service, username, password)

    def test_different_user(self):
        """
        Issue #47 reports that WinVault isn't storing passwords for
        multiple users. This test exercises that test for each of the
        backends.
        """

        keyring = self.keyring
        self.set_password('service1', 'user1', 'password1')
        self.set_password('service1', 'user2', 'password2')
        self.assertEqual(keyring.get_password('service1', 'user1'),
            'password1')
        self.assertEqual(keyring.get_password('service1', 'user2'),
            'password2')
        self.set_password('service2', 'user3', 'password3')
        self.assertEqual(keyring.get_password('service1', 'user1'),
            'password1')

class FileKeyringTests(BackendBasicTests):

    def setUp(self):
        super(FileKeyringTests, self).setUp()
        self.keyring = self.init_keyring()
        self.keyring.file_path = self.tmp_keyring_file = tempfile.mktemp()

    def tearDown(self):
        try:
            os.unlink(self.tmp_keyring_file)
        except (OSError,):
            e = sys.exc_info()[1]
            if e.errno != 2: # No such file or directory
                raise

    def test_encrypt_decrypt(self):
        password = random_string(20)
        # keyring.encrypt expects bytes
        password = password.encode('utf-8')
        encrypted = self.keyring.encrypt(password)

        self.assertEqual(password, self.keyring.decrypt(encrypted))


class UncryptedFileKeyringTestCase(FileKeyringTests, unittest.TestCase):

    def init_keyring(self):
        return keyring.backend.UncryptedFileKeyring()

    @unittest.skipIf(sys.platform == 'win32',
        "Group/World permissions aren't meaningful on Windows")
    def test_keyring_not_created_world_writable(self):
        """
        Ensure that when keyring creates the file that it's not overly-
        permissive.
        """
        self.keyring.set_password('system', 'user', 'password')

        self.assertTrue(os.path.exists(self.keyring.file_path))
        group_other_perms = os.stat(self.keyring.file_path).st_mode & 0077
        self.assertEqual(group_other_perms, 0)

@unittest.skipUnless(is_dbus_supported(),
    "DBus needed for SecretServiceKeyring")
class SecretServiceKeyringTestCase(BackendBasicTests, unittest.TestCase):
    __test__ = True

    def environ(self):
        return dict(DISPLAY='1',
                    DBUS_SESSION_BUS_ADDRESS='1')

    def init_keyring(self):
        print >> sys.stderr, "Testing SecretServiceKeyring, following password prompts are for this keyring"
        return keyring.backend.SecretServiceKeyring()

    def test_supported_no_module(self):
        with ImportKiller('dbus'):
            with Environ(**self.environ()):
                self.assertEqual(-1, self.keyring.supported())


def init_google_docs_keyring(client, can_create=True,
                             input_getter=raw_input):
    credentials = keyring.backend.BaseCredential('foo', 'bar')
    return keyring.backend.GoogleDocsKeyring(credentials,
                                             'test_src',
                                             keyring.backend.NullCrypter(),
                                             client=client,
                                             can_create=can_create,
                                             input_getter=input_getter
                                            )

@unittest.skipUnless(is_gdata_supported(),
                     "Need Google Docs (gdata)")
class GoogleDocsKeyringTestCase(BackendBasicTests, unittest.TestCase):
    """Run all the standard tests on a new keyring"""

    def init_keyring(self):
        client = mocks.MockDocumentService()
        client.SetClientLoginToken('foo')
        return init_google_docs_keyring(client)

@unittest.skipUnless(is_gdata_supported(),
                     "Need Google Docs (gdata)")
class GoogleDocsKeyringInteractionTestCase(unittest.TestCase):
    """Additional tests for Google Doc interactions"""

    def _init_client(self, set_token=True):
        client = mocks.MockDocumentService()
        if set_token:
            client.SetClientLoginToken('interaction')
        return client

    def _init_keyring(self, client):
        self.keyring = init_google_docs_keyring(client)

    def _init_listfeed(self):
        listfeed = mocks.MockListFeed()
        listfeed._entry = [mocks.MockDocumentListEntry(),
                           mocks.MockDocumentListEntry()
                          ]
        return listfeed

    def _encode_data(self, data):
        return base64.urlsafe_b64encode(cPickle.dumps(data))

    def test_handles_auth_failure(self):
        import gdata
        client = self._init_client(set_token=False)
        client._login_err = gdata.service.BadAuthentication
        self._init_keyring(client)
        try:
            google_client = self.keyring.client
            self.assertTrue(False, 'Should throw InitError')
        except keyring.backend.InitError:
            pass

    def test_handles_auth_error(self):
        import gdata
        client = self._init_client(set_token=False)
        client._login_err = gdata.service.Error
        self._init_keyring(client)
        try:
            google_client = self.keyring.client
            self.assertTrue(False, 'Should throw InitError')
        except keyring.backend.InitError:
            pass

    def test_handles_login_captcha(self):
        import gdata
        client = self._init_client(set_token=False)
        client._login_err = gdata.service.CaptchaRequired
        client.captcha_url = 'a_captcha_url'
        client.captcha_token = 'token'
        self.get_input_called = False
        def _get_input(prompt):
            self.get_input_called = True
            delattr(client, '_login_err')
            return 'Foo'
        self.keyring = init_google_docs_keyring(client, input_getter=_get_input)
        google_client = self.keyring.client
        self.assertTrue(self.get_input_called, 'Should have got input')

    def test_retrieves_existing_keyring_with_and_without_bom(self):
        client = self._init_client()
        dummy_entries = dict(section1=dict(user1='pwd1'))
        no_utf8_bom_entries = self._encode_data(dummy_entries)
        client._request_response = dict(status=200, data=no_utf8_bom_entries)
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        self.assertEqual(self.keyring.get_password('section1', 'user1'), 'pwd1')

        utf8_bom_entries = codecs.BOM_UTF8 + no_utf8_bom_entries
        client._request_response = dict(status=200, data=utf8_bom_entries)
        self._init_keyring(client)
        self.assertEqual(self.keyring.get_password('section1', 'user1'), 'pwd1')

    def test_handles_retrieve_failure(self):
        import gdata
        client = self._init_client()
        client._listfeed = self._init_listfeed()
        client._request_response = dict(status=400,
                                        reason='Data centre explosion')
        self._init_keyring(client)
        try:
            self.keyring.get_password('any', 'thing')
            self.assertTrue(False, 'Should throw InitError')
        except keyring.backend.InitError:
            pass

    def test_handles_corrupt_retrieve(self):
        client = self._init_client()
        dummy_entries = dict(section1=dict(user1='pwd1'))
        client._request_response = dict(status=200, data='broken' + self._encode_data(dummy_entries))
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        try:
            self.keyring.get_password('any', 'thing')
            self.assertTrue(False, 'Should throw InitError')
        except keyring.backend.InitError:
            pass

    def test_no_create_if_requested(self):
        client = self._init_client()
        self.keyring = init_google_docs_keyring(client, can_create=False)
        try:
            self.keyring.get_password('any', 'thing')
            self.assertTrue(False, 'Should throw InitError')
        except keyring.backend.InitError:
            pass

    def test_no_set_if_create_folder_fails_on_new_keyring(self):
        import gdata
        client = self._init_client()
        client._create_folder_err = gdata.service.RequestError
        self._init_keyring(client)
        self.assertEqual(self.keyring.get_password('service-a', 'user-A'), None,
                        'No password should be set in new keyring')
        try:
            self.keyring.set_password('service-a', 'user-A', 'password-A')
            self.assertTrue(False, 'Should throw PasswordSetError')
        except keyring.backend.PasswordSetError:
            pass
        self.assertEqual(self.keyring.get_password('service-a', 'user-A'), None,
                        'No password should be set after write fail')

    def test_no_set_if_write_fails_on_new_keyring(self):
        import gdata
        client = self._init_client()
        client._upload_err = gdata.service.RequestError
        self._init_keyring(client)
        self.assertEqual(self.keyring.get_password('service-a', 'user-A'), None,
                        'No password should be set in new keyring')
        try:
            self.keyring.set_password('service-a', 'user-A', 'password-A')
            self.assertTrue(False, 'Should throw PasswordSetError')
        except keyring.backend.PasswordSetError:
            pass
        self.assertEqual(self.keyring.get_password('service-a', 'user-A'), None,
                        'No password should be set after write fail')

    def test_no_set_if_write_fails_on_existing_keyring(self):
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionB=dict(user9='pwd9'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._put_err = gdata.service.RequestError
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        self.assertEqual(self.keyring.get_password('sectionB', 'user9'), 'pwd9',
                        'Correct password should be set in existing keyring')
        try:
            self.keyring.set_password('sectionB', 'user9', 'Not the same pwd')
            self.assertTrue(False, 'Should throw PasswordSetError')
        except keyring.backend.PasswordSetError:
            pass
        self.assertEqual(self.keyring.get_password('sectionB', 'user9'), 'pwd9',
                        'Password should be unchanged after write fail')

    def test_writes_correct_data_to_google_docs(self):
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionWriteChk=dict(userWriteChk='pwd'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        self.keyring.set_password('sectionWriteChk',
                                  'userWritechk',
                                  'new_pwd')
        self.assertIsNotNone(client._put_data, 'Should have written data')
        self.assertEquals(
            'new_pwd',
            client._put_data.get('sectionWriteChk').get('userWritechk'),
            'Did not write updated password!')

    def test_handles_write_conflict_on_different_service(self):
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionWriteConflictA=dict(
            userwriteConflictA='pwdwriteConflictA'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._put_err = [(gdata.service.RequestError,
                               {'status': '406',
                                'reason': 'Conflict'}),]
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        self.assertEqual(
            self.keyring.get_password('sectionWriteConflictA',
                                      'userwriteConflictA'),
            'pwdwriteConflictA',
            'Correct password should be set in existing keyring')
        dummy_entries['diffSection'] = dict(foo='bar')
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        new_pwd = 'Not the same pwd'
        self.keyring.set_password('sectionWriteConflictA',
                                  'userwriteConflictA',
                                  new_pwd)

        self.assertEquals(self.keyring.get_password('sectionWriteConflictA',
                                                    'userwriteConflictA'),
                          new_pwd
        )
        self.assertEqual(1, client._put_count,
                         'Write not called after conflict resolution')

    def test_handles_write_conflict_on_same_service_and_username(self):
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionWriteConflictB=dict(
            userwriteConflictB='pwdwriteConflictB'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._put_err = (gdata.service.RequestError,
                               {'status': '406',
                                'reason': 'Conflict'})
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        self.assertEqual(
            self.keyring.get_password('sectionWriteConflictB',
                                      'userwriteConflictB'),
            'pwdwriteConflictB',
            'Correct password should be set in existing keyring')
        conflicting_dummy_entries = dict(sectionWriteConflictB=dict(
            userwriteConflictB='pwdwriteConflictC'))
        client._request_response = dict(status=200, data=self._encode_data(conflicting_dummy_entries))
        try:
            self.keyring.set_password('sectionWriteConflictB',
                                      'userwriteConflictB',
                                      'new_pwd')
            self.assertTrue(False, 'Should throw PasswordSetError')
        except keyring.backend.PasswordSetError:
            pass

    def test_handles_write_conflict_with_identical_change(self):
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionWriteConflictC=dict(
            userwriteConflictC='pwdwriteConflictC'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._put_err = [(gdata.service.RequestError,
                               {'status': '406',
                                 'reason': 'Conflict'}),]
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        self.assertEqual(
            self.keyring.get_password('sectionWriteConflictC',
                                      'userwriteConflictC'),
            'pwdwriteConflictC',
            'Correct password should be set in existing keyring')
        new_pwd = 'Not the same pwd'
        conflicting_dummy_entries = dict(sectionWriteConflictC=dict(
            userwriteConflictC=new_pwd))
        client._request_response = dict(status=200, data=self._encode_data(conflicting_dummy_entries))
        self.keyring.set_password('sectionWriteConflictC',
                                  'userwriteConflictC',
                                  new_pwd)
        self.assertEquals(self.keyring.get_password('sectionWriteConflictC',
                                                    'userwriteConflictC'),
                          new_pwd
        )

    def test_handles_broken_google_put_when_non_owner_update_fails(self):
        """Google Docs has a bug when putting to a non-owner
           see  GoogleDocsKeyring._save_keyring()
        """
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionBrokenPut=dict(
            userBrokenPut='pwdBrokenPut'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._put_err = [(
            gdata.service.RequestError,
                { 'status': '400',
                  'body': 'Sorry, there was an error saving the file. Please try again.',
                  'reason': 'Bad Request'}),]
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        new_pwd = 'newPwdBrokenPut'
        correct_read_entries = dict(sectionBrokenPut=dict(
            userBrokenPut='pwdBrokenPut'))
        client._request_response = dict(status=200,
                                        data=self._encode_data(correct_read_entries))
        try:
            self.keyring.set_password('sectionBrokenPut',
                                      'userBrokenPut',
                                      new_pwd)
            self.assertTrue(False, 'Should throw PasswordSetError')
        except keyring.backend.PasswordSetError:
            pass

    def test_handles_broken_google_put_when_non_owner_update(self):
        """Google Docs has a bug when putting to a non-owner
           see  GoogleDocsKeyring._save_keyring()
        """
        import gdata
        client = self._init_client()
        dummy_entries = dict(sectionBrokenPut=dict(
            userBrokenPut='pwdBrokenPut'))
        client._request_response = dict(status=200, data=self._encode_data(dummy_entries))
        client._put_err = [(
            gdata.service.RequestError,
                { 'status': '400',
                  'body': 'Sorry, there was an error saving the file. Please try again.',
                  'reason': 'Bad Request'}),]
        client._listfeed = self._init_listfeed()
        self._init_keyring(client)
        new_pwd = 'newPwdBrokenPut'
        correct_read_entries = dict(sectionBrokenPut=dict(
            userBrokenPut=new_pwd))
        client._request_response = dict(status=200,
                                        data=self._encode_data(correct_read_entries))
        self.keyring.set_password('sectionBrokenPut',
                                  'userBrokenPut',
                                  new_pwd)
        self.assertEquals(self.keyring.get_password('sectionBrokenPut',
                                                    'userBrokenPut'),
                          new_pwd)

    def test_uses_existing_folder(self):
        import gdata
        client = self._init_client()
        # should not happen
        client._create_folder_err = gdata.service.RequestError

        self._init_keyring(client)
        self.assertEqual(self.keyring.get_password('service-a', 'user-A'), None,
                         'No password should be set in new keyring')
        client._listfeed = self._init_listfeed()
        self.keyring.set_password('service-a', 'user-A', 'password-A')
        self.assertIsNotNone(client._upload_data, 'Should have written data')
        self.assertEqual(self.keyring.get_password('service-a', 'user-A'),
                         'password-A',
                         'Correct password should be set')


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(SecretServiceKeyringTestCase))
    suite.addTest(unittest.makeSuite(UncryptedFileKeyringTestCase))
    suite.addTest(unittest.makeSuite(GoogleDocsKeyringTestCase))
    suite.addTest(unittest.makeSuite(GoogleDocsKeyringInteractionTestCase))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest="test_suite")
