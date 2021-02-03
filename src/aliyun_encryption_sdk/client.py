import base64
import attr

from aliyun_encryption_sdk.ckm.base import CryptoKeyManager
from aliyun_encryption_sdk.ckm.default import DefaultCryptoKeyManager
from aliyun_encryption_sdk.handle.encryption import DefaultEncryptHandler, EncryptHandler
from aliyun_encryption_sdk.kms import AliyunConfig
from aliyun_encryption_sdk.kms.kms import AliyunKms


@attr.s(hash=False)
class AliyunCrypto(object):
    config = attr.ib(validator=attr.validators.instance_of(AliyunConfig))
    crypto_key_manager = attr.ib(
        default=DefaultCryptoKeyManager(),
        validator=attr.validators.instance_of(CryptoKeyManager)
    )
    encrypt_handler = attr.ib(
        default=DefaultEncryptHandler(),
        validator=attr.validators.instance_of(EncryptHandler)
    )

    def encrypt(self, key_provider, plain_text, encryption_context=None):
        if encryption_context is None:
            encryption_context = {}
        key_provider.kms = AliyunKms(self.config)
        encryption_material = self.crypto_key_manager.get_encrypt_dataKey_material(
            key_provider, encryption_context, len(plain_text)
        )
        cipher_material = self.encrypt_handler.encrypt(plain_text, encryption_material)
        crypto_result = key_provider.process_cipher_material(cipher_material)
        return crypto_result, cipher_material

    def decrypt(self, key_provider, cipher_text):
        key_provider.kms = AliyunKms(self.config)
        cipher_material = key_provider.get_cipher_material(cipher_text)
        cipher_header = cipher_material.cipher_header
        key_provider.algorithm = cipher_header.algorithm
        decryption_material = self.crypto_key_manager.get_decrypt_dataKey_material(
            key_provider, cipher_header.encryption_context, cipher_header.encrypted_data_keys
        )
        crypto_result = self.encrypt_handler.decrypt(cipher_material, decryption_material)
        return crypto_result, cipher_material

    def sign(self, sign_provider, content, content_type):
        sign_provider.kms = AliyunKms(self.config)
        signature_material = self.crypto_key_manager.get_signature_material(sign_provider, content, content_type)
        return base64.b64decode(signature_material.signed_value)

    def verify(self, sign_provider, content, signed_value, content_type):
        sign_provider.kms = AliyunKms(self.config)
        verify_material = self.crypto_key_manager.get_verify_material(sign_provider, content, signed_value, content_type)
        return verify_material.verify_value
