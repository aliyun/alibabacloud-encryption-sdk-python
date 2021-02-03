import abc
import os
import six

from aliyun_encryption_sdk.model import CipherHeader, CipherBody, CipherMaterial
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher


class Encryptor(object):
    def __init__(self, algorithm, key_spec, iv=None, content_aad=None):
        self._key_spec = key_spec
        self._cipher = Cipher(
            algorithm.cipher_algorithm(key_spec), algorithm.init_mode_iv(iv, None), default_backend()
        ).encryptor()
        if algorithm.with_aad:
            self._cipher.authenticate_additional_data(content_aad)

    def update(self, plain_text):
        return self._cipher.update(plain_text)

    def finalize(self):
        return self._cipher.finalize()

    @property
    def tag(self):
        if hasattr(self._cipher, 'tag'):
            return self._cipher.tag
        else:
            return bytes()


class Decryptor(object):
    def __init__(self, algorithm, key_spec, iv, content_aad, tag):
        self._key_spec = key_spec
        self._cipher = Cipher(
            algorithm.cipher_algorithm(key_spec), algorithm.init_mode_iv(iv, tag), default_backend()
        ).decryptor()
        if algorithm.with_aad:
            self._cipher.authenticate_additional_data(content_aad)

    def update(self, cipher_text):
        return self._cipher.update(cipher_text)

    def finalize(self):
        return self._cipher.finalize()


@six.add_metaclass(abc.ABCMeta)
class EncryptHandler(object):

    @abc.abstractmethod
    def encrypt(self, plain_text, encryption_material):
        pass

    @abc.abstractmethod
    def decrypt(self, cipher_material, decryption_material):
        pass


class DefaultEncryptHandler(EncryptHandler):
    def encrypt(self, plain_text, encryption_material):
        algorithm = encryption_material.algorithm
        cipher_header = CipherHeader(
            algorithm=algorithm,
            encryption_context=encryption_material.encryption_context,
            encrypted_data_keys=encryption_material.encrypted_data_keys,
            version=encryption_material.version
        )
        iv = os.urandom(algorithm.iv_len)
        encryptor = Encryptor(
            algorithm, encryption_material.plaintext_data_key,
            iv, cipher_header.encryption_context_bytes
        )
        cipher_header.calculate_header_auth_tag(encryption_material.plaintext_data_key)

        padding_plain_text = algorithm.padding_data(plain_text)
        cipher_text = encryptor.update(padding_plain_text) + encryptor.finalize()
        cipher_body = CipherBody(iv, cipher_text, encryptor.tag)
        return CipherMaterial(cipher_header, cipher_body)

    def decrypt(self, cipher_material, decryption_material):
        if not cipher_material.cipher_header.verify_header_auth_tag(decryption_material.plaintext_data_key):
            raise Exception("header authTag verify failed")
        decryptor = Decryptor(
            decryption_material.algorithm, decryption_material.plaintext_data_key,
            cipher_material.cipher_body.iv, cipher_material.cipher_header.encryption_context_bytes,
            cipher_material.cipher_body.auth_tag
        )
        plain_text = decryptor.update(cipher_material.cipher_body.cipher_text) + decryptor.finalize()
        return decryption_material.algorithm.un_padding_data(plain_text)
