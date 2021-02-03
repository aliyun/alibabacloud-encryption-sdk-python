# -*- coding: UTF-8 -*-
"""Example showing basic encryption and decryption."""

import base64
import os

from aliyun_encryption_sdk.cache.local import LocalDataKeyMaterialCache
from aliyun_encryption_sdk.ckm.cache import CachingCryptoKeyManager
from aliyun_encryption_sdk.client import AliyunCrypto
from aliyun_encryption_sdk.kms import AliyunConfig
from aliyun_encryption_sdk.provider.default import DefaultDataKeyProvider


def build_aliyun_crypto(cache=False):
    config = AliyunConfig(ACCESS_KEY_ID, ACCESS_KEY_SECRET)
    client = AliyunCrypto(config)
    if cache:
        client.crypto_key_manager = CachingCryptoKeyManager(LocalDataKeyMaterialCache(), 5)
    return client


def encrypt_sample():
    print("原文: " + PLAIN_TEXT)
    provider = DefaultDataKeyProvider(AES_KEY_ARN)
    client = build_aliyun_crypto(False)
    cipher_text, enc_material = client.encrypt(provider, PLAIN_TEXT.encode("utf-8"), ENCRYPTION_CONTEXT)
    cipher_text_str = base64.standard_b64encode(cipher_text).decode("utf-8")
    print(u"加密密文: " + cipher_text_str)
    return cipher_text_str


def decrypt_sample(cipher_text):
    cipher_text_bytes = base64.standard_b64decode(cipher_text.encode("utf-8"))
    provider = DefaultDataKeyProvider(AES_KEY_ARN)
    client = build_aliyun_crypto(False)
    plain_text, dec_material = client.decrypt(provider, cipher_text_bytes)
    print(u"解密结果: " + bytes.decode(plain_text))
    return plain_text


if __name__ == '__main__':
    PLAIN_TEXT = "some plaintext"
    ACCESS_KEY_ID = os.getenv("ACCESS_KEY_ID")
    ACCESS_KEY_SECRET = os.getenv("ACCESS_KEY_SECRET")
    REGION_ID = os.getenv("REGION_ID")
    AES_KEY_ARN = os.getenv("AES_KEY_ARN")
    ENCRYPTION_CONTEXT = {
        "this": "context",
        "can help you": "to confirm",
        "this data": "is your original data"
    }
    cipherText = encrypt_sample()
    decrypt_sample(cipherText)
