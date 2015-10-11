# -*- coding: utf-8 -*-


import os
import base64
import boto3
import uuid
import configparser

from ..errors import (PasswordDeleteError, PasswordGetError, InitError,
                      ConfigError)
from ..backend import KeyringBackend
from ..util.escape import escape as escape_for_s3


AWS_CONFIG_FILE = os.path.join(os.path.expanduser('~'), '.aws', 'config')


def supported():
    """Returns True if the S3 backed is supported on this system"""
    try:
        list(boto3.resource('s3').buckets.all())
        return True
    except:
        return False


class S3Backed(object):
    def __init__(self, kms_key_id=None, region=None, profile=None):
        """Creates a S3 bucket for the backend if one does not exist already"""
        self.__s3 = None
        self.__bucket = None
        self.__namespace = None
        self.__region = region
        self.__profile = profile
        self.__kms_key_id = kms_key_id

    @property
    def kms_key_id(self):
        if self.__kms_key_id is None:
            self.__kms_key_id = os.environ.get('AWS_KMS_KEY_ID') or \
                self._get_profile_default(self.profile, 'kms_key_id')
        return self.__kms_key_id

    @property
    def bucket(self):
        if self.__bucket is None:
            self.__bucket = self._find_bucket()
        return self.__bucket

    @property
    def region(self):
        if self.__region is None:
            self.__region = os.environ.get('AWS_DEFAULT_REGION') or \
                self._get_profile_default(self.profile, 'region')
        return self.__region

    @property
    def profile(self):
        if self.__profile is None:
            self.__profile = os.environ.get('AWS_PROFILE') or 'default'
        return self.__profile

    @property
    def name(self):
        return self.bucket.name.split('keyring-')[1]

    @property
    def s3(self):
        if self.__s3 is None:
            self.__s3 = boto3.resource('s3')
        return self.__s3

    @property
    def config(self):
        cfg = configparser.ConfigParser()
        cfg.read(AWS_CONFIG_FILE)
        return cfg

    @property
    def namespace(self):
        """Namespaces allow you to have multiple keyrings backed by the same
        S3 bucket by separating them with different S3 prefixes. Different
        access permissions can then be given to different prefixes so that
        only the right IAM roles/users/groups have access to a keychain
        namespace"""
        if self.__namespace is None:
            self.__namespace = escape_for_s3(
                os.environ.get('S3_KEYRING_NAMESPACE', 'default'))
        return self.__namespace

    def _find_bucket(self):
        """Finds the backend S3 bucket. The backend bucket must be called
        keyring-[UUID].
        """
        bucket = [b for b in self.s3.buckets.all()
                  if b.name.find('keyring-') == 0]
        if len(bucket) == 0:
            bucket_name = "keyring-{}".format(uuid.uuid4())
            bucket = self.s3.Bucket(bucket_name)
            bucket.create(ACL='private',
                          CreateBucketConfiguration={
                              'LocationConstraint': self.region})
        elif len(bucket) > 1:
            msg = ("Can't tell which of these buckets to use for the keyring: "
                   "{buckets}").format([b.name for b in bucket])
            raise InitError(msg)
        else:
            bucket = bucket[0]
        return bucket

    def _get_profile_default(self, profile, option):
        """Gets a default option value for a given AWS profile"""
        if profile not in self.config:
            profile = 'default'

        if option not in self.config[profile]:
            raise ConfigError("No default for option {} in profile {}".format(
                option, profile))

        return self.config[profile][option]


class S3Keyring(S3Backed, KeyringBackend):
    """
    BaseS3Keyring is a S3-based implementation of keyring.
    This keyring stores the password directly in S3 and provides methods
    which may be overridden by subclasses to support
    encryption and decryption. The encrypted payload is stored in base64
    format.
    """

    def _get_s3_key(self, service, username):
        """The S3 key where the secret will be stored"""
        return "{}/{}/{}/secret.b64".format(self.namespace, service, username)

    def get_password(self, service, username):
        """Read the password from the S3 bucket.
        """
        service = escape_for_s3(service)
        username = escape_for_s3(username)

        # Read the password from S3
        prefix = self._get_s3_key(service, username)
        values = list(self.bucket.objects.filter(Prefix=prefix))
        if len(values) == 0:
            # service/username not found
            return
        if len(values) > 1:
            msg = "Ambiguous prefix {prefix} in bucket {bucket}.".format(
                prefix=prefix, bucket=self.bucket.name)
            raise PasswordGetError(msg)
        pwd_base64 = values[0].get()['Body'].read()
        pwd = base64.decodestring(pwd_base64)
        return pwd.decode('utf-8')

    def set_password(self, service, username, password):
        """Write the password in the S3 bucket.
        """
        service = escape_for_s3(service)
        username = escape_for_s3(username)

        pwd_base64 = base64.encodestring(password.encode('utf-8')).decode()

        # Save in S3 using both server and client side encryption
        keyname = self._get_s3_key(service, username)
        self.bucket.Object(keyname).put(ACL='private', Body=pwd_base64,
                                        ServerSideEncryption='aws:kms',
                                        SSEKMSKeyId=self.kms_key_id)

    def delete_password(self, service, username):
        """Delete the password for the username of the service.
        """
        service = escape_for_s3(service)
        username = escape_for_s3(username)
        prefix = self._get_s3_key(service, username)
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
