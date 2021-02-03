from aliyun_encryption_sdk.provider.base import BaseDataKeyProvider


class DefaultDataKeyProvider(BaseDataKeyProvider):

    def process_cipher_material(self, cipher_material):
        return self.format_handle.serialize(cipher_material)

    def get_cipher_material(self, cipher_text):
        return self.format_handle.deserialize(cipher_text)