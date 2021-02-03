import base64
import struct

import attr
import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from aliyun_encryption_sdk.cache.base import DataKeyCache
from aliyun_encryption_sdk.ckm import EncryptionMaterial, DecryptionMaterial
from aliyun_encryption_sdk.ckm.base import CryptoKeyManager
from aliyun_encryption_sdk.constants import SDK_VERSION
from aliyun_encryption_sdk.model import serialize_context

MAX_TIME = 60
MAX_BYTE = 9223372036854775807  # 2 ** 63 - 1
MAX_MESSAGE = 9223372036854775807  # 2 ** 63 - 1


@attr.s(hash=False)
class CachingCryptoKeyManager(CryptoKeyManager):
    cache = attr.ib(validator=attr.validators.instance_of(DataKeyCache))
    max_survival_time = attr.ib(default=MAX_TIME, validator=attr.validators.instance_of(six.integer_types))
    max_encryption_bytes = attr.ib(default=MAX_BYTE, validator=attr.validators.instance_of(six.integer_types))
    max_encryption_messages = attr.ib(default=MAX_MESSAGE, validator=attr.validators.instance_of(six.integer_types))

    def __attrs_post_init__(self):
        if self.max_survival_time < 0:
            raise ValueError("'max_survival_time' cannot be less than 0")

        if self.max_encryption_bytes < 0:
            raise ValueError("'max_encryption_bytes' cannot be less than 0")

        if self.max_encryption_messages < 0:
            raise ValueError("'max_encryption_messages' cannot be less than 0")

    def get_encrypt_dataKey_material(self, provider, encryption_context, plaintext_size):
        encryption_material = EncryptionMaterial(
            version=SDK_VERSION,
            encryption_context=encryption_context,
            algorithm=provider.algorithm,
        )

        if plaintext_size < 0 or plaintext_size > MAX_BYTE:
            return provider.encrypt_data_key(encryption_material)

        cache_key = self._get_encrypt_cache_key(provider.algorithm, encryption_context)
        cache_entry = self.cache.get_encrypt_entry(cache_key, plaintext_size)
        if cache_entry:
            if not self._is_exceed_max_limit(cache_entry):
                return cache_entry.material
            self.cache.remove(cache_entry)

        material = provider.encrypt_data_key(encryption_material)
        self.cache.put_encrypt_entry(cache_key, plaintext_size, material, self.max_survival_time)
        return material

    def get_decrypt_dataKey_material(self, provider, encryption_context, encrypted_data_keys):
        decryption_material = DecryptionMaterial(
            encryption_context=encryption_context,
            algorithm=provider.algorithm,
        )

        cache_key = self._get_decrypt_cache_key(provider.algorithm, encryption_context, encrypted_data_keys)
        cache_entry = self.cache.get_decrypt_entry(cache_key)
        if cache_entry:
            return cache_entry.material

        material = provider.decrypt_data_key(decryption_material, encrypted_data_keys)
        if not material:
            raise Exception("Failed to get dataKey from encrypted_data_keys")
        self.cache.put_decrypt_entry(cache_key, material, self.max_survival_time)
        return material

    def _get_encrypt_cache_key(self, algorithm, encryption_context):
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        self._digest_algorithm(digest, algorithm)
        self._digest_context(digest, encryption_context)
        result = digest.finalize()
        return base64.b64encode(result)

    def _get_decrypt_cache_key(self, algorithm, encryption_context, encrypted_data_keys):
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        self._digest_algorithm(digest, algorithm)
        self._digest_context(digest, encryption_context)
        self._digest_encrypted_data_keys(digest, encrypted_data_keys)
        result = digest.finalize()
        return base64.b64encode(result)

    def _is_exceed_max_limit(self, entry):
        return entry.encrypted_bytes > self.max_encryption_bytes \
               or entry.encrypted_messages > self.max_encryption_messages

    @staticmethod
    def _digest_algorithm(digest, algorithm):
        if not algorithm:
            digest.update(b"\x00")
        else:
            digest.update(b"\x01" + algorithm.id_to_byte())

    @staticmethod
    def _digest_context(digest, encryption_context):
        if len(encryption_context) == 0:
            digest.update(b"\x00")
        else:
            digest.update(b"\x01")
            digest.update(serialize_context(encryption_context))

    @staticmethod
    def _digest_encrypted_data_keys(digest, encrypted_data_keys):
        if len(encrypted_data_keys) == 0:
            digest.update(b"\x00")
        else:
            digest.update(b"\x01")
            digest.update(struct.pack(">B", len(encrypted_data_keys)))
            encrypted_data_key_list = list(encrypted_data_keys)
            encrypted_data_key_list.sort(key=lambda item: item.key_arn)
            for data_key in encrypted_data_key_list:
                digest.update(data_key.key_arn)
                digest.update(data_key.encrypted_data_key)