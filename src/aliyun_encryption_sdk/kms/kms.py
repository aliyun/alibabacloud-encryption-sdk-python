import time
import attr
import json

from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyun_encryption_sdk import to_bytes, to_str
from aliyunsdkcore.client import AcsClient
from aliyunsdkkms.request.v20160120 import GenerateDataKeyRequest, EncryptRequest, ReEncryptRequest, DecryptRequest, \
    GetSecretValueRequest, CreateSecretRequest, AsymmetricSignRequest, AsymmetricVerifyRequest
from aliyun_encryption_sdk.constants import USER_AGENT
from aliyun_encryption_sdk.kms import AliyunConfig
from aliyun_encryption_sdk.provider import EncryptedDataKey, str_to_cmk


@attr.s(hash=False)
class AliyunKms(object):
    config = attr.ib(validator=attr.validators.instance_of(AliyunConfig))

    def generate_data_key(self, key, algorithm, context):
        request = GenerateDataKeyRequest.GenerateDataKeyRequest()
        request.set_accept_format('JSON')
        request.set_KeyId(key.raw_key_id)
        if algorithm.crypto_name == "SM4_128":
            request.set_NumberOfBytes(16)
        else:
            request.set_KeySpec(algorithm.crypto_name)
        if len(context) != 0:
            request.set_EncryptionContext(json.dumps(context))
        response = self._get_result(request, key)
        return response.get('Plaintext'), response.get('CiphertextBlob')

    def reEncrypt_data_key(self, key, encrypted_data_key, context):
        request = ReEncryptRequest.ReEncryptRequest()
        request.set_accept_format('JSON')
        request.set_CiphertextBlob(to_str(encrypted_data_key.encrypted_data_key))
        if len(context) != 0:
            request.set_SourceEncryptionContext(json.dumps(context))
            request.set_DestinationEncryptionContext(json.dumps(context))
        request.set_DestinationKeyId(key.raw_key_id)
        response = self._get_result(request, key)
        return EncryptedDataKey(
            to_bytes(key.key_arn),
            to_bytes(response.get('CiphertextBlob'))
        )

    def encrypt_data_key(self, key, plaintext_data_key, context):
        request = EncryptRequest.EncryptRequest()
        request.set_accept_format('JSON')
        request.set_KeyId(key.raw_key_id)
        request.set_Plaintext(plaintext_data_key)
        if len(context) != 0:
            request.set_EncryptionContext(json.dumps(context))
        response = self._get_result(request, key)
        return EncryptedDataKey(
            to_bytes(key.key_arn),
            to_bytes(response.get('CiphertextBlob'))
        )

    def decrypt_data_key(self, encrypted_data_key, context):
        request = DecryptRequest.DecryptRequest()
        request.set_accept_format('JSON')
        request.set_CiphertextBlob(to_str(encrypted_data_key.encrypted_data_key))
        if len(context) != 0:
            request.set_EncryptionContext(json.dumps(context))
        response = self._get_result(request, str_to_cmk(to_str(encrypted_data_key.key_arn)))
        return response.get("Plaintext")

    def create_secret(self, key, secret_name, version_id, secret_data, secret_data_type):
        request = CreateSecretRequest.CreateSecretRequest()
        request.set_accept_format('JSON')
        request.set_VersionId(version_id)
        request.set_EncryptionKeyId(key.raw_key_id)
        request.set_SecretName(secret_name)
        request.set_SecretData(secret_data)
        request.set_SecretDataType(secret_data_type)
        self._get_result(request, key)

    def get_secret_value(self, key, secret_name):
        request = GetSecretValueRequest.GetSecretValueRequest()
        request.set_accept_format('JSON')
        request.set_SecretName(secret_name)
        response = self._get_result(request, key)
        return response.get('SecretData'), response.get('SecretDataType')

    def asymmetric_sign(self, key, key_version_id, signature_algorithm, digest):
        request = AsymmetricSignRequest.AsymmetricSignRequest()
        request.set_accept_format('JSON')
        request.set_KeyId(key.raw_key_id)
        request.set_KeyVersionId(key_version_id)
        request.set_Algorithm(signature_algorithm.algorithm_name)
        request.set_Digest(digest)
        response = self._get_result(request, key)
        return response.get('Value')

    def asymmetric_verify(self, key, key_version_id, signature_algorithm, digest, signed_value):
        request = AsymmetricVerifyRequest.AsymmetricVerifyRequest()
        request.set_accept_format('JSON')
        request.set_KeyId(key.raw_key_id)
        request.set_KeyVersionId(key_version_id)
        request.set_Algorithm(signature_algorithm.algorithm_name)
        request.set_Digest(digest)
        request.set_Value(signed_value)
        response = self._get_result(request, key)
        return response.get('Value')

    def _get_result(self, request, key):
        if key is None:
            region = self.config.region
        else:
            if key.region:
                region = key.region
            else:
                region = self.config.region
        if len(region) == 0:
            raise ValueError("region information not obtained")
        client = AcsClient(
            ak=self.config.access_key_id,
            secret=self.config.access_key_secret,
            region_id=region,
            user_agent=USER_AGENT
        )
        for i in range(self.config.max_retries):
            try:
                return json.loads(client.do_action_with_exception(request))
            except Exception as e:
                if isinstance(e, ClientException) and e.error_code in (
                        "Rejected.Throttling", "ServiceUnavailableTemporary", "InternalFailure"):
                    time.sleep(self.config.backoff_strategy.wait_time_exponential(i + 1))
                else:
                    raise e
