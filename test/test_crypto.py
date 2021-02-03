import pytest

from aliyun_encryption_sdk.cache.local import LocalDataKeyMaterialCache
from aliyun_encryption_sdk.ckm.cache import CachingCryptoKeyManager
from aliyun_encryption_sdk.client import AliyunCrypto
from aliyun_encryption_sdk.kms import AliyunConfig
from aliyun_encryption_sdk.model import Algorithm, SignatureAlgorithm, ContentType
from aliyun_encryption_sdk.provider.default import DefaultDataKeyProvider
from aliyun_encryption_sdk.provider.secret_manager import SecretManagerDataKeyProvider
from aliyun_encryption_sdk.provider.signature.base import KmsAsymmetricKeyProvider
from aliyun_encryption_sdk.provider.signature.verifier import PublicKeyVerifier, CertificateVerifier

PLAIN_TEXT = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
PLAIN_TEST_8_BLOCK_SIZE = b""
AES_KEY_ID = "acs:kms:RegionId:UserId:key/CmkId"
RSA_KEY_ID = "acs:kms:RegionId:UserId:key/CmkId"
RSA_KEY_VERSION = "RSA_KEY_VERSION"
SAME_REGION_KEY_IDS = [
    "acs:kms:RegionId:UserId:key/CmkId"
]
MULTI_REGION_KEY_IDS = [
    "acs:kms:RegionId:UserId:key/CmkId",
    "acs:kms:RegionId:UserId:key/CmkId"
]
ENCRYPTION_CONTEXT = {
    "this": "context",
    "can help you": "to confirm",
    "this data": "is your original data"
}
ACCESS_KEY_ID = "AccessKey"
ACCESS_KEY_SECRET = "AccessKeySecret"


def build_aliyun_crypto(cache=False):
    config = AliyunConfig(ACCESS_KEY_ID, ACCESS_KEY_SECRET)
    client = AliyunCrypto(config)
    if cache:
        client.crypto_key_manager = CachingCryptoKeyManager(LocalDataKeyMaterialCache(), 5)
    return client


@pytest.mark.parametrize(
    "algorithm, context", (
            [algorithm, context] for algorithm in Algorithm
            for context in ({}, ENCRYPTION_CONTEXT)
    )
)
def test_encrypt_decrypt(algorithm, context):
    provider = DefaultDataKeyProvider(AES_KEY_ID)
    provider.algorithm = algorithm
    client = build_aliyun_crypto()
    cipher_text, _ = client.encrypt(provider, PLAIN_TEXT, context)
    decrypt_result, _ = client.decrypt(provider, cipher_text)
    assert decrypt_result == PLAIN_TEXT


@pytest.mark.parametrize(
    "algorithm, context, multi_keys",
    (
            [algorithm, context, multi_keys]
            for algorithm in Algorithm
            for context in ({}, ENCRYPTION_CONTEXT)
            for multi_keys in (SAME_REGION_KEY_IDS, MULTI_REGION_KEY_IDS)
    )
)
def test_single_region_multi_key_encrypt_decrypt(algorithm, context, multi_keys):
    provider = DefaultDataKeyProvider(AES_KEY_ID)
    provider.algorithm = algorithm
    provider.add_multi_cmk_id(multi_keys)
    client = build_aliyun_crypto()
    cipher_text, _ = client.encrypt(provider, PLAIN_TEXT, context)
    decrypt_result, _ = client.decrypt(provider, cipher_text)
    assert decrypt_result == PLAIN_TEXT

    for key_id in multi_keys:
        provider = DefaultDataKeyProvider(key_id)
        other_result, _ = client.decrypt(provider, cipher_text)
        assert other_result == PLAIN_TEXT


def test_encrypt_decrypt_with_SecretManagerDataKeyProvider():
    provider = SecretManagerDataKeyProvider(AES_KEY_ID, "test_secret_key")
    client = build_aliyun_crypto()
    cipher_text, _ = client.encrypt(provider, PLAIN_TEXT, {})
    decrypt_result, _ = client.decrypt(provider, cipher_text)
    assert decrypt_result == PLAIN_TEXT


def test_sign_verify_with_kms():
    provider = KmsAsymmetricKeyProvider(RSA_KEY_ID, RSA_KEY_VERSION, SignatureAlgorithm.RSA_PKCS1_SHA_256)
    client = build_aliyun_crypto()
    signed_result = client.sign(provider, PLAIN_TEXT, ContentType.MESSAGE)
    verify_result = client.verify(provider, PLAIN_TEXT, signed_result, ContentType.MESSAGE)
    assert verify_result

    sha256_digest = b'\xfe\xccu\xfe*#\xd8\xea\xfb\xa4R\xee\x0b\x8bkV\xbe\xcc' \
                    b'\xf5"x\xbf\x13\x98\xaa\xdd\xee\xcf\xe0\xea\x0f\xce'
    signed_result = client.sign(provider, sha256_digest, ContentType.DIGEST)
    verify_result = client.verify(provider, sha256_digest, signed_result, ContentType.DIGEST)
    assert verify_result


def test_public_key_verifier():
    provider = KmsAsymmetricKeyProvider(
        key=RSA_KEY_ID,
        key_version_id=RSA_KEY_VERSION,
        signature_algorithm=SignatureAlgorithm.RSA_PKCS1_SHA_256
    )
    client = build_aliyun_crypto()
    signed_result = client.sign(provider, PLAIN_TEXT, ContentType.MESSAGE)

    pem = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvd9" \
          b"+hxVcGf20soetMjSH9FvvirOyuESDIdEjwemXTK8LK5gR16gHhW9TvFncH6aQo5HQUdE" \
          b"/TNOQPcQLs1WT4aAs1NW3QdO1JjVyzmtNMQCd9zVcE0GVkPXOwGx+uJ5ZPcz0sMODPxzKbSKiKan0mQlJOEhzg" \
          b"+LOD5HSjy7vIapasRCju//QOMKvp9kP9QH9gfdP+jOVbPXLOFgZQDgaNaGOsuhYDw14a+PhQj2ylo7W7S6+csOLMu9zfJcgl5KM5Q" \
          b"/ZVpopxEd3ROHVhIBc1PEdpEOkW/X5+J6BS74Wn25jm1YahRYmmrZrIs1v3clLLE3kn4eKKbhWht024CBg8wIDAQAB\n-----END " \
          b"PUBLIC KEY----- "
    verifier = PublicKeyVerifier(SignatureAlgorithm.RSA_PKCS1_SHA_256, pem)
    verify_result = client.verify(verifier, PLAIN_TEXT, signed_result, ContentType.MESSAGE)
    assert verify_result


def test_certificate_verifier():
    provider = KmsAsymmetricKeyProvider(
        key=RSA_KEY_ID,
        key_version_id=RSA_KEY_VERSION,
        signature_algorithm=SignatureAlgorithm.RSA_PKCS1_SHA_256,
    )
    client = build_aliyun_crypto()
    signed_result = client.sign(provider, PLAIN_TEXT, ContentType.MESSAGE)

    cert = b"-----BEGIN CERTIFICATE-----\nMIIDcDCCAlgCFAmA42kBFMk1kAfiKoIAJHwLmDtiMA0GCSqGSIb3DQEBCwUA" \
           b"MHwxCzAJBgNVBAYTAmNuMQswCQYDVQQIDAJ6ajELMAkGA1UEBwwCaHoxDzANBgNVBAoMBmFsaXl1bjEMMAoGA1UEC" \
           b"wwDa21zMRQwEgYDVQQDDAtleGFtcGxlLmNvbTEeMBwGCSqGSIb3DQEJARYPYWJjQGV4YW1wbGUuY29tMB4XDTIwMD" \
           b"cxNDA2MzUyNloXDTIxMDcxNDA2MzUyNlowbTELMAkGA1UEBhMCQ04xJTAjBgNVBAMMHGVuY3J5cHRpb24tc2RrLXJ" \
           b"zYS1jZXJ0LXRlc3QxCzAJBgNVBAcMAmh6MQswCQYDVQQIDAJ6ajEPMA0GA1UECgwGYWxpeXVuMQwwCgYDVQQLDANr" \
           b"bXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9336HFVwZ/bSyh60yNIf0W++Ks7K4RIMh0SPB6ZdMr" \
           b"wsrmBHXqAeFb1O8WdwfppCjkdBR0T9M05A9xAuzVZPhoCzU1bdB07UmNXLOa00xAJ33NVwTQZWQ9c7AbH64nlk9zP" \
           b"Sww4M/HMptIqIpqfSZCUk4SHOD4s4PkdKPLu8hqlqxEKO7/9A4wq+n2Q/1Af2B90/6M5Vs9cs4WBlAOBo1oY6y6Fg" \
           b"PDXhr4+FCPbKWjtbtLr5yw4sy73N8lyCXkozlD9lWminER3dE4dWEgFzU8R2kQ6Rb9fn4noFLvhafbmObVhqFFiaa" \
           b"tmsizW/dyUssTeSfh4opuFaG3TbgIGDzAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGf9+aZXoWgfkRN4/l4C0bKsd" \
           b"KR2oZk97gZbE95gcGONOGNSIk0NanJcAYVg+z7zTh61Y+ncx8u6JZ7KRL5rkouwkNmh6X/jXHHEXlQ4XItiY5NMOI" \
           b"eCQgeuFsnrTCpQ+4/nMJbEL4CtUmHt76T4cMFQjcbtMtRpckHc9/o74P0+trA/qYxmYjMYrkL0iUar6OcP9QnjaIe" \
           b"CUGogtdcCe6p59rkO/kEHfGs2NgC/KjxKGpNMq/hBVgx0IgsIU25ZtKLox1Imcb8TPHThn6ooQNkUI3DlwVN077C1" \
           b"9ZvnUD1/IIwh5nn10Cuf6WfRgfb813IMppKt7S7o3JIZUkNSukM=\n-----END CERTIFICATE-----"
    verifier = CertificateVerifier(cert)
    verify_result = client.verify(verifier, PLAIN_TEXT, signed_result, ContentType.MESSAGE)
    assert verify_result
