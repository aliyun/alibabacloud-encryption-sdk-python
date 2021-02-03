from aliyun_encryption_sdk.ckm import EncryptionMaterial, DecryptionMaterial
from aliyun_encryption_sdk.ckm.base import CryptoKeyManager
from aliyun_encryption_sdk.constants import SDK_VERSION


class DefaultCryptoKeyManager(CryptoKeyManager):

    def get_encrypt_dataKey_material(self, provider, encryption_context, plaintext_size):
        encryption_material = EncryptionMaterial(
            version=SDK_VERSION,
            encryption_context=encryption_context,
            algorithm=provider.algorithm,
        )
        return provider.encrypt_data_key(encryption_material)

    def get_decrypt_dataKey_material(self, provider, encryption_context, encrypted_data_keys):
        decryption_material = DecryptionMaterial(
            encryption_context=encryption_context,
            algorithm=provider.algorithm,
        )
        return provider.decrypt_data_key(decryption_material, encrypted_data_keys)