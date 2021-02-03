import codecs
import os
import struct
from enum import Enum

from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
import attr
import six

from aliyun_encryption_sdk import to_bytes
from aliyun_encryption_sdk.constants import SDK_VERSION, ENCODING


class Padding(Enum):
    NOPADDING = 0
    PKCS5PADDING = 1

    def padding(self, data, block_size):
        if self.value == 0:
            return data
        elif self.value == 1:
            padder = padding.PKCS7(block_size * 8).padder()
            padded_data = padder.update(data)
            padded_data += padder.finalize()
            return padded_data

    def un_padding(self, data, block_size):
        if self.value == 0:
            return data
        elif self.value == 1:
            unpadder = padding.PKCS7(block_size * 8).unpadder()
            un_padded_data = unpadder.update(data)
            un_padded_data += unpadder.finalize()
            return un_padded_data


class Algorithm(Enum):
    __find_dict__ = {}

    AES_GCM_NOPADDING_128 = (algorithms.AES, modes.GCM, Padding.NOPADDING, "AES_128", 16, 12, 16, 16, 1, True)
    AES_GCM_NOPADDING_256 = (algorithms.AES, modes.GCM, Padding.NOPADDING, "AES_256", 32, 12, 16, 16, 2, True)
    AES_CBC_NOPADDING_128 = (algorithms.AES, modes.CBC, Padding.NOPADDING, "AES_128", 16, 16, 0, 16, 3, False)
    AES_CBC_NOPADDING_256 = (algorithms.AES, modes.CBC, Padding.NOPADDING, "AES_256", 32, 16, 0, 16, 4, False)
    AES_CBC_PKCS5_128 = (algorithms.AES, modes.CBC, Padding.PKCS5PADDING, "AES_128", 16, 16, 0, 16, 5, False)
    AES_CBC_PKCS5_256 = (algorithms.AES, modes.CBC, Padding.PKCS5PADDING, "AES_256", 32, 16, 0, 16, 6, False)
    AES_CTR_NOPADDING_128 = (algorithms.AES, modes.CTR, Padding.NOPADDING, "AES_128", 16, 16, 0, 16, 7, False)
    AES_CTR_NOPADDING_256 = (algorithms.AES, modes.CTR, Padding.NOPADDING, "AES_256", 32, 16, 0, 16, 8, False)

    def __init__(self, cipher_algorithm, mode, pad, crypto_name, key_len, iv_len, tag_len, block_size, algorithm_id, with_aad):
        self.cipher_algorithm = cipher_algorithm
        self.mode = mode
        self.pad = pad
        self.crypto_name = crypto_name
        self.key_len = key_len
        self.iv_len = iv_len
        self.tag_len = tag_len
        self.block_size = block_size
        self.algorithm_id = algorithm_id
        self.with_aad = with_aad
        self.__find_dict__[algorithm_id] = self

    def init_mode_iv(self, iv, tag):
        if tag:
            return self.mode(iv, tag)
        else:
            return self.mode(iv)

    def padding_data(self, data):
        return self.pad.padding(data, self.block_size)

    def un_padding_data(self, data):
        return self.pad.un_padding(data, self.block_size)

    def id_to_byte(self):
        b = bytearray()
        b.extend(struct.pack(">B", self.algorithm_id))
        return bytes(b)

    @classmethod
    def get_algorithm_by_id(cls, algorithm_id):
        return cls.__find_dict__[algorithm_id]


class SignatureAlgorithm(Enum):
    RSA_PSS_SHA_256 = ("RSA_2048", "RSA_PSS_SHA_256", hashes.SHA256)
    RSA_PKCS1_SHA_256 = ("RSA_2048", "RSA_PKCS1_SHA_256", hashes.SHA256)
    ECDSA_P256_SHA_256 = ("EC_P256", "ECDSA_SHA_256", hashes.SHA256)
    ECDSA_P256K_SHA_256 = ("EC_P256K", "ECDSA_SHA_256", hashes.SHA256)

    def __init__(self, key_spec, algorithm_name, digest_algorithm):
        self.key_spec = key_spec
        self.algorithm_name = algorithm_name
        self.digest_algorithm = digest_algorithm


class ContentType(Enum):
    MESSAGE = 0
    DIGEST = 1


@attr.s(hash=False)
class CipherHeader(object):
    HEADER_IV_LEN = 12

    _encryption_context_bytes = None
    algorithm = attr.ib(validator=attr.validators.instance_of(Algorithm))
    encryption_context = attr.ib(validator=attr.validators.instance_of(dict))
    encrypted_data_keys = attr.ib(validator=attr.validators.instance_of(set))
    version = attr.ib(default=SDK_VERSION, validator=attr.validators.instance_of(six.integer_types))
    header_iv = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))
    header_auth_tag = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))

    @property
    def encryption_context_bytes(self):
        if not self._encryption_context_bytes:
            self._encryption_context_bytes = serialize_context(self.encryption_context)
        return self._encryption_context_bytes

    def calculate_header_auth_tag(self, plaintext_data_key):
        header_iv = os.urandom(self.HEADER_IV_LEN)
        header_auth_tag = self._header_gcm_encrypt(plaintext_data_key, header_iv)
        self.header_iv = header_iv
        self.header_auth_tag = header_auth_tag

    def verify_header_auth_tag(self, plaintext_data_key):
        header_iv = self.header_iv
        header_auth_tag = self._header_gcm_encrypt(plaintext_data_key, header_iv)
        if self.header_auth_tag == header_auth_tag:
            return True
        return False

    def _header_gcm_encrypt(self, plaintext_data_key, header_iv):
        auth_field_bytes = self._serialize_authenticated_fields()
        encryptor = Cipher(
            algorithms.AES(plaintext_data_key),
            modes.GCM(header_iv),
        ).encryptor()
        encryptor.authenticate_additional_data(auth_field_bytes)
        encryptor.update(b"") + encryptor.finalize()
        return encryptor.tag

    def _serialize_authenticated_fields(self):
        serialize_auth_field = bytearray()
        serialize_auth_field.extend(
            struct.pack(
                ">3I{}s".format(len(self.encryption_context_bytes)),
                self.version, self.algorithm.algorithm_id,
                len(self.encryption_context), self.encryption_context_bytes
            )
        )
        serialize_auth_field.extend(struct.pack(">I", len(self.encrypted_data_keys)))
        encrypted_data_key_list = list(self.encrypted_data_keys)
        encrypted_data_key_list.sort(key=lambda item: item.key_arn)
        serialized_data_keys = bytearray()
        for data_key in encrypted_data_key_list:
            b = data_key.serialize()
            serialized_data_keys.extend(b)
        serialize_auth_field.extend(serialized_data_keys)
        return bytes(serialize_auth_field)


@attr.s(hash=False)
class CipherBody(object):
    iv = attr.ib(validator=attr.validators.instance_of(bytes))
    cipher_text = attr.ib(validator=attr.validators.instance_of(bytes))
    auth_tag = attr.ib(default=bytes(), validator=attr.validators.optional(attr.validators.instance_of(bytes)))


@attr.s(hash=False)
class CipherMaterial(object):
    cipher_header = attr.ib(validator=attr.validators.instance_of(CipherHeader))
    cipher_body = attr.ib(validator=attr.validators.instance_of(CipherBody))


def serialize_context(context):
    dict_size = len(context)
    if dict_size == 0:
        return bytes()

    serialized_context = bytearray()
    serialized_context.extend(struct.pack(">I", dict_size))
    context_temp = []
    for key, value in context.items():
        try:
            if isinstance(key, bytes):
                key = codecs.decode(key)
            if isinstance(value, bytes):
                value = codecs.decode(value)
            context_temp.append(
                (to_bytes(key), to_bytes(value))
            )
        except Exception:
            raise Exception("Cannot encode encryption context using {}".format(ENCODING))

    for key, value in sorted(context_temp, key=lambda x: x[0]):
        serialized_context.extend(
            struct.pack(
                ">I{key_len}sI{value_len}s".format(key_len=len(key), value_len=len(value)),
                len(key), key, len(value), value
            )
        )
    return bytes(serialized_context)
