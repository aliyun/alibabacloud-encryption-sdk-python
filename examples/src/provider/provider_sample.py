# -*- coding: UTF-8 -*-

import base64
import os

from aliyun_encryption_sdk.cache.local import LocalDataKeyMaterialCache
from aliyun_encryption_sdk.ckm.cache import CachingCryptoKeyManager
from aliyun_encryption_sdk.client import AliyunCrypto
from aliyun_encryption_sdk.kms import AliyunConfig
from aliyun_encryption_sdk.provider.secret_manager import SecretManagerDataKeyProvider
from aliyun_encryption_sdk.provider.default import DefaultDataKeyProvider


def build_aliyun_crypto(cache=False):
    config = AliyunConfig(ACCESS_KEY_ID, ACCESS_KEY_SECRET)
    client = AliyunCrypto(config)
    if cache:
        client.crypto_key_manager = CachingCryptoKeyManager(LocalDataKeyMaterialCache(), 5)
    return client


def build_default_dataKey_provider():
    return DefaultDataKeyProvider(AES_KEY_ARN)


def build_secret_manager_provider():
    return SecretManagerDataKeyProvider(AES_KEY_ARN, "test_secret_key")


def encrypt_sample(provider, client):
    print("原文: " + PLAIN_TEXT)
    cipher_text, enc_material = client.encrypt(provider, PLAIN_TEXT.encode("utf-8"), ENCRYPTION_CONTEXT)
    cipher_text_str = base64.standard_b64encode(cipher_text).decode("utf-8")
    print(u"加密密文: " + cipher_text_str)
    return cipher_text_str


def decrypt_sample(provider, client, cipher_text):
    cipher_text_bytes = base64.standard_b64decode(cipher_text.encode())
    plain_text, dec_material = client.decrypt(provider, cipher_text_bytes)
    print(u"解密结果: " + bytes.decode(plain_text))
    return plain_text


if __name__ == '__main__':
    PLAIN_TEXT = "test_plain_text"
    AES_KEY_ARN = os.getenv("AES_KEY_ARN")
    ACCESS_KEY_ID = os.getenv("ACCESS_KEY_ID")
    ACCESS_KEY_SECRET = os.getenv("ACCESS_KEY_SECRET")
    ENCRYPTION_CONTEXT = {
        "this": "context",
        "can help you": "to confirm",
        "this data": "is your original data"
    }
    crypto_client = build_aliyun_crypto(False)
    print("========= DefaultDataKeyProvider =========")
    cipher_text_default_provider = encrypt_sample(build_default_dataKey_provider(), crypto_client)
    decrypt_sample(build_default_dataKey_provider(), crypto_client, cipher_text_default_provider)
    print("========= DefaultDataKeyProvider =========\n")

    print("========= SecretManagerDataKeyProvider =========")
    cipher_text_secret_manager_provider = encrypt_sample(build_secret_manager_provider(), crypto_client)
    decrypt_sample(build_secret_manager_provider(), crypto_client, cipher_text_secret_manager_provider)
    print("========= SecretManagerDataKeyProvider =========")
