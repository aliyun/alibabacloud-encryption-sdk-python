from threading import Lock
import time

import attr
import six

from aliyun_encryption_sdk.ckm import EncryptionMaterial, DecryptionMaterial


@attr.s(hash=False)
class MaterialsCacheEntry(object):
    cache_key = attr.ib(validator=attr.validators.instance_of(bytes))
    material = attr.ib(validator=attr.validators.instance_of((EncryptionMaterial, DecryptionMaterial)))
    survival_time = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    encrypted_bytes = attr.ib(default=0, validator=attr.validators.instance_of(six.integer_types))
    encrypted_messages = attr.ib(default=0, validator=attr.validators.instance_of(six.integer_types))

    def __attrs_post_init__(self):
        self.creation_time = time.time()
        self._lock = Lock()

    @property
    def is_expired(self):
        age = time.time() - self.creation_time
        return age > self.survival_time

    def add_encrypted_usage_info(self, encrypted_bytes):
        with self._lock:
            self.encrypted_messages = self.encrypted_messages + 1
            self.encrypted_bytes = self.encrypted_bytes + encrypted_bytes
