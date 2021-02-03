# -*- coding: UTF-8 -*-

import hashlib
import os

from aliyun_encryption_sdk.cache.local import LocalDataKeyMaterialCache
from aliyun_encryption_sdk.ckm.cache import CachingCryptoKeyManager
from aliyun_encryption_sdk.client import AliyunCrypto
from aliyun_encryption_sdk.kms import AliyunConfig
from aliyun_encryption_sdk.model import SignatureAlgorithm, ContentType
from aliyun_encryption_sdk.provider.signature.base import KmsAsymmetricKeyProvider
from aliyun_encryption_sdk.provider.signature.verifier import PublicKeyVerifier, CertificateVerifier


def build_aliyun_crypto(cache=False):
    config = AliyunConfig(ACCESS_KEY_ID, ACCESS_KEY_SECRET)
    client = AliyunCrypto(config)
    if cache:
        client.crypto_key_manager = CachingCryptoKeyManager(LocalDataKeyMaterialCache(), 5)
    return client


def sign_verify_with_kms_sample():
    provider = KmsAsymmetricKeyProvider(RSA_SIGN_VERIFY_KEY_ARN,
                                        RSA_SIGN_VERIFY_KEY_VERSION,
                                        SignatureAlgorithm.RSA_PKCS1_SHA_256)
    client = build_aliyun_crypto()
    signed_result = client.sign(provider, PLAIN_TEXT.encode("utf-8"), ContentType.MESSAGE)
    verify_result = client.verify(provider, PLAIN_TEXT.encode("utf-8"), signed_result, ContentType.MESSAGE)
    print("kms(message) verify result: " + str(verify_result))

    sha256_digest = hashlib.sha256(PLAIN_TEXT.encode("utf-8")).digest()
    signed_result = client.sign(provider, sha256_digest, ContentType.DIGEST)
    verify_result = client.verify(provider, sha256_digest, signed_result, ContentType.DIGEST)
    print("kms(digest) verify result: " + str(verify_result))


def public_key_verifier_sample():
    provider = KmsAsymmetricKeyProvider(
        RSA_SIGN_VERIFY_KEY_ARN,
        key_version_id=RSA_SIGN_VERIFY_KEY_VERSION,
        signature_algorithm=SignatureAlgorithm.RSA_PKCS1_SHA_256
    )
    client = build_aliyun_crypto()
    signed_result = client.sign(provider, PLAIN_TEXT.encode("utf-8"), ContentType.MESSAGE)

    verifier = PublicKeyVerifier(SignatureAlgorithm.RSA_PKCS1_SHA_256, RSA_SIGN_VERIFY_PUBLIC_KEY.encode())
    verify_result = client.verify(verifier, PLAIN_TEXT.encode("utf-8"), signed_result, ContentType.MESSAGE)
    print("publicKeyVerifier(message) verify result: " + str(verify_result))


def certificate_verifier_sample():
    provider = KmsAsymmetricKeyProvider(
        RSA_SIGN_VERIFY_KEY_ARN,
        key_version_id=RSA_SIGN_VERIFY_KEY_VERSION,
        signature_algorithm=SignatureAlgorithm.RSA_PKCS1_SHA_256,
    )
    client = build_aliyun_crypto()
    signed_result = client.sign(provider, PLAIN_TEXT.encode("utf-8"), ContentType.MESSAGE)

    verifier = CertificateVerifier(RSA_SIGN_VERIFY_PUBLIC_CERT.encode())
    verify_result = client.verify(verifier, PLAIN_TEXT.encode("utf-8"), signed_result, ContentType.MESSAGE)
    print("CertificateVerifier verify result: " + str(verify_result))


if __name__ == '__main__':
    PLAIN_TEXT = "test_plain_text"
    ACCESS_KEY_ID = os.getenv("ACCESS_KEY_ID")
    ACCESS_KEY_SECRET = os.getenv("ACCESS_KEY_SECRET")
    RSA_SIGN_VERIFY_KEY_ARN = os.getenv("RSA_SIGN_VERIFY_KEY_ARN")
    RSA_SIGN_VERIFY_KEY_VERSION = os.getenv("RSA_SIGN_VERIFY_KEY_VERSION")
    RSA_SIGN_VERIFY_PUBLIC_KEY = os.getenv("RSA_SIGN_VERIFY_PUBLIC_KEY")
    RSA_SIGN_VERIFY_PUBLIC_CERT = os.getenv("RSA_SIGN_VERIFY_PUBLIC_CERT")
    sign_verify_with_kms_sample()
    public_key_verifier_sample()
    certificate_verifier_sample()
