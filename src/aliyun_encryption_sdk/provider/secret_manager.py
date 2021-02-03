import base64
import uuid
import six

from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyun_encryption_sdk.ckm import DecryptionMaterial
from aliyun_encryption_sdk.handle.format import Asn1FormatHandler
from aliyun_encryption_sdk.model import CipherMaterial, CipherHeader, Algorithm
from aliyun_encryption_sdk.provider.base import BaseDataKeyProvider


class SecretManagerDataKeyProvider(BaseDataKeyProvider):

    def __init__(self, key_arn, data_key_name, kms=None, format_handle=Asn1FormatHandler(),
                 algorithm=Algorithm.AES_GCM_NOPADDING_256, keys=None):
        super(SecretManagerDataKeyProvider, self).__init__(key_arn, kms, format_handle, algorithm, keys)
        if not isinstance(data_key_name, six.string_types):
            raise TypeError("'data_key_name' must be str type")
        self._data_key_name = data_key_name

    def encrypt_data_key(self, encryption_material):
        cipher_header = self.get_cipher_header()
        if cipher_header:
            return self.get_encryption_material(cipher_header, encryption_material)
        material = super().encrypt_data_key(encryption_material)
        self.store_cipher_header(material)
        return material

    def process_cipher_material(self, cipher_material):
        return self.format_handle.serialize_cipher_body(cipher_material.cipher_body)

    def get_cipher_material(self, cipher_text):
        cipher_body = self.format_handle.deserialize_cipher_body(cipher_text)
        try:
            cipher_header = self.get_cipher_header()
            if not cipher_header:
                raise Exception("Forbidden.ResourceNotFound")
            return CipherMaterial(cipher_header, cipher_body)
        except Exception:
            raise Exception("cannot get dataKey from external")

    def get_cipher_header(self):
        try:
            secret_data, secret_data_type = self.kms.get_secret_value(self.key, self._data_key_name)
            if secret_data_type == 'text':
                cipher_text = base64.b64decode(secret_data)
                return self.format_handle.deserialize_cipher_header(cipher_text)
            else:
                raise Exception('Unprocessed case where secretDataType is binary')
        except Exception as e:
            if isinstance(e, ClientException) and e.error_code == "Forbidden.ResourceNotFound":
                return None
            else:
                raise e

    def get_encryption_material(self, cipher_header, encryption_material):
        decryption_material = DecryptionMaterial(
            encryption_context=cipher_header.encryption_context,
            algorithm=cipher_header.algorithm,
        )
        decryption_material = self.decrypt_data_key(decryption_material, cipher_header.encrypted_data_keys)
        if not decryption_material:
            raise Exception("Failed to get dataKey from 'encrypted_data_keys'")
        encryption_material.plaintext_data_key = decryption_material.plaintext_data_key
        encryption_material.encrypted_data_keys = cipher_header.encrypted_data_keys
        encryption_material.version = cipher_header.version
        encryption_material.algorithm = cipher_header.algorithm
        encryption_material.encryption_context = cipher_header.encryption_context
        return encryption_material

    def store_cipher_header(self, encryption_material):
        cipher_header = CipherHeader(
            algorithm=encryption_material.algorithm,
            encryption_context=encryption_material.encryption_context,
            encrypted_data_keys=encryption_material.encrypted_data_keys,
        )
        cipher_header.calculate_header_auth_tag(encryption_material.plaintext_data_key)
        header_text = self.format_handle.serialize_cipher_header(cipher_header)
        base64_header = base64.b64encode(header_text)
        version_id = uuid.uuid1()
        self.kms.create_secret(self.key, self._data_key_name, version_id, base64_header, 'text')
