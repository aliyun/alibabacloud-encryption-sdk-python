import base64
import abc
import six

from aliyun_encryption_sdk import to_bytes, to_str
from aliyun_encryption_sdk.handle.format import FormatHandler, Asn1FormatHandler
from aliyun_encryption_sdk.model import Algorithm
from aliyun_encryption_sdk.provider import str_to_cmk, EncryptedDataKey
from aliyun_encryption_sdk.kms.kms import AliyunKms


@six.add_metaclass(abc.ABCMeta)
class BaseDataKeyProvider(object):

    def __init__(self, key_arn, kms=None, format_handle=Asn1FormatHandler(),
                 algorithm=Algorithm.AES_GCM_NOPADDING_256, keys=None):
        if keys is None:
            keys = set()
        if not isinstance(key_arn, six.string_types):
            raise TypeError("'key_arn' must be str type")
        if kms is not None and not isinstance(kms, AliyunKms):
            raise TypeError("'kms' must be AliyunKms type")
        if not isinstance(format_handle, FormatHandler):
            raise TypeError("'format_handle' must be FormatHandler type")
        if not isinstance(algorithm, Algorithm):
            raise TypeError("'algorithm' must be Algorithm type")
        if not isinstance(keys, (set, list)):
            raise TypeError("'keys' must be set or list type")

        self.key = str_to_cmk(key_arn)
        self._kms = kms
        self._format_handle = format_handle
        self._algorithm = algorithm
        self._keys = set()
        self.add_multi_cmk_id(keys)

    def add_multi_cmk_id(self, key_arns):
        if len(key_arns) == 0:
            return
        if self.key.key_arn in key_arns:
            key_arns.remove(self.key.key_arn)
        for key_arn in key_arns:
            self._keys.add(str_to_cmk(key_arn))

    @property
    def kms(self):
        return self._kms

    @kms.setter
    def kms(self, kms):
        if not isinstance(kms, AliyunKms):
            raise TypeError("'kms' must be of type AliyunKms")
        if self._kms is None:
            self._kms = kms

    @property
    def format_handle(self):
        return self._format_handle

    @format_handle.setter
    def format_handle(self, format_handle):
        if not isinstance(format_handle, FormatHandler):
            raise TypeError("'format_handle' must be of type FormatHandler")
        self._format_handle = format_handle

    @property
    def algorithm(self):
        return self._algorithm

    @algorithm.setter
    def algorithm(self, algorithm):
        if not isinstance(algorithm, Algorithm):
            raise TypeError("'algorithm' must be of type Algorithm")
        self._algorithm = algorithm

    @abc.abstractmethod
    def process_cipher_material(self, cipher_material):
        pass

    @abc.abstractmethod
    def get_cipher_material(self, cipher_text):
        pass

    def encrypt_data_key(self, encryption_material):
        encrypted_data_keys = set()
        plaintext_data_key, encrypted_data_key = self._kms.generate_data_key(
            self.key, self._algorithm, encryption_material.encryption_context
        )

        data_key = EncryptedDataKey(
            to_bytes(self.key.key_arn),
            to_bytes(encrypted_data_key)
        )
        encrypted_data_keys.add(data_key)
        for key in self._keys:
            if key.isCommonRegion(self.key):
                encrypted_data_keys.add(self._kms.reEncrypt_data_key(
                    key, data_key, encryption_material.encryption_context
                ))
            else:
                encrypted_data_keys.add(self._kms.encrypt_data_key(
                    key, plaintext_data_key, encryption_material.encryption_context
                ))
        encryption_material.encrypted_data_keys = encrypted_data_keys
        encryption_material.plaintext_data_key = base64.b64decode(plaintext_data_key)
        return encryption_material

    def decrypt_data_key(self, decryption_material, encrypted_data_keys):
        key_ids = self._keys.copy()
        key_ids.add(self.key)
        for encrypted_data_key in encrypted_data_keys:
            if str_to_cmk(to_str(encrypted_data_key.key_arn)) in key_ids:
                try:
                    plaintext_data_key = self._kms.decrypt_data_key(
                        encrypted_data_key, decryption_material.encryption_context
                    )
                    decryption_material.plaintext_data_key = base64.b64decode(plaintext_data_key)
                    return decryption_material
                except Exception:
                    continue
        return None
