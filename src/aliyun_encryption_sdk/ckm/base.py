import abc
import six

from aliyun_encryption_sdk.ckm import SignatureMaterial, VerifyMaterial
from aliyun_encryption_sdk.model import ContentType


@six.add_metaclass(abc.ABCMeta)
class CryptoKeyManager(object):

    @abc.abstractmethod
    def get_encrypt_dataKey_material(self, provider, encryption_context, plaintext_size):
        pass

    @abc.abstractmethod
    def get_decrypt_dataKey_material(self, provider, encryption_context, encrypted_data_keys):
        pass

    @staticmethod
    def get_signature_material(provider, content, content_type):
        signature_material = SignatureMaterial(
            signature_algorithm=provider.signature_algorithm
        )
        if content_type is ContentType.DIGEST:
            signature_material.digest = content
        else:
            signature_material.message = content
        return provider.sign_data(signature_material)

    @staticmethod
    def get_verify_material(provider, content, signed_value, content_type):
        verify_material = VerifyMaterial(
            signed_value=signed_value,
            signature_algorithm=provider.signature_algorithm
        )
        if content_type is ContentType.DIGEST:
            verify_material.digest = content
        else:
            verify_material.message = content
        return provider.verify_data(verify_material)
