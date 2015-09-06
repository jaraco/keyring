# -*- coding: utf-8 -*-


from __future__ import with_statement

import base64
import abc
import boto3
import uuid

from ..errors import PasswordDeleteError, PasswordGetError, InitError
from ..backend import KeyringBackend
from ..util.escape import escape as escape_for_s3


def supported():
    """Returns True if the S3 backed is supported on this system"""
    try:
        list(boto3.resource('s3').buckets.all())
        return True
    except:
        return False


class S3Backed(object):
    def __init__(self):
        """Creates a S3 bucket for the backend if one does not exist already"""
        self.__s3 = None
        self.__bucket = None

    @property
    def bucket(self):
        if self.__bucket is None:
            self.__bucket = self._find_bucket()
        return self.__bucket

    @property
    def s3(self):
        if self.__s3 is None:
            self.__s3 = boto3.resource('s3')
        return self.__s3

    def _find_bucket(self):
        """Finds the backend S3 bucket. The backend bucket must be called
        keyring-[UUID].
        """
        bucket = [b for b in self.s3.buckets.all()
                  if b.name.find('keyring-') == 0]
        if len(bucket) == 0:
            bucket_name = "keyring-{}".format(uuid.uuid4())
            bucket = self.s3.Bucket(bucket_name)
            bucket.create(ACL='private')
        elif len(bucket) > 1:
            msg = ("Can't tell which of these buckets to use for the keyring: "
                   "{buckets}").format([b.name for b in bucket])
            raise InitError(msg)
        else:
            bucket = bucket[0]
        return bucket


class BaseKeyring(S3Backed, KeyringBackend):
    """
    BaseS3Keyring is a S3-based implementation of keyring.
    This keyring stores the password directly in S3 and provides methods
    which may be overridden by subclasses to support
    encryption and decryption. The encrypted payload is stored in base64
    format.
    """

    @abc.abstractmethod
    def encrypt(self, password):
        """
        Given a password (byte string), return an encrypted byte string.
        """

    @abc.abstractmethod
    def decrypt(self, password_encrypted):
        """
        Given a password encrypted by a previous call to `encrypt`, return
        the original byte string.
        """

    def get_password(self, service, username):
        """Read the password from the S3 bucket.
        """
        service = escape_for_s3(service)
        username = escape_for_s3(username)

        # Read the password from S3
        prefix = "{}/{}/secret.b64".format(service, username)
        values = list(self.bucket.objects.filter(Prefix=prefix))
        if len(values) == 0:
            # service/username not found
            return
        if len(values) > 1:
            msg = "Ambiguous prefix {prefix} in bucket {bucket}.".format(
                prefix=prefix, bucket=self.bucket.name)
            raise PasswordGetError(msg)
        pwd_base64 = values[0].get()['Body'].read()
        encrypted_pwd = base64.decodestring(pwd_base64)
        return self.decrypt(encrypted_pwd).decode('utf-8')

    def set_password(self, service, username, password):
        """Write the password in the S3 bucket.
        """
        service = escape_for_s3(service)
        username = escape_for_s3(username)

        # encrypt and base64-encode the password
        pwd_encrypted = self.encrypt(password.encode('utf-8'))
        pwd_base64 = base64.encodestring(pwd_encrypted).decode()

        # Save in S3
        keyname = "{}/{}/secret.b64".format(service, username)
        self.bucket.Object(keyname).put(ACL='private', Body=pwd_base64)

    def delete_password(self, service, username):
        """Delete the password for the username of the service.
        """
        service = escape_for_s3(service)
        username = escape_for_s3(username)
        prefix = "{}/{}/secret.b64".format(service, username)
        objects = list(self.bucket.objects.filter(Prefix=prefix))
        if len(objects) == 0:
            msg = ("Password for service {service} and username {username} "
                   "not found.").format(service=service, username=username)
            raise PasswordDeleteError(msg)
        elif len(objects) > 1:
            msg = ("Multiple objects in bucket {bucket} match the prefix "
                   "{prefix}.").format(bucket=self.bucket.name,
                                       prefix=prefix)
        else:
            objects[0].delete()


class PlaintextKeyring(BaseKeyring):
    """Simple S3 Keyring with no encryption"""

    priority = .5
    "Applicable for all platforms, but not recommended"

    def encrypt(self, password):
        """Directly return the password itself.
        """
        return password

    def decrypt(self, password_encrypted):
        """Directly return encrypted password.
        """
        return password_encrypted
