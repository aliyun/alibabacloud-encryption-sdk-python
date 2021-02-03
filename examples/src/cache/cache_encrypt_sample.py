# -*- coding: UTF-8 -*-

import base64
import os

from aliyun_encryption_sdk.provider.default import DefaultDataKeyProvider
from aliyun_encryption_sdk.cache.local import LocalDataKeyMaterialCache
from aliyun_encryption_sdk.ckm.cache import CachingCryptoKeyManager
from aliyun_encryption_sdk.client import AliyunCrypto
from aliyun_encryption_sdk.kms import AliyunConfig


def encrypt_with_caching():
    plain_data = "My plaintext data"
    config = AliyunConfig(ACCESS_KEY_ID, ACCESS_KEY_SECRET)
    client = AliyunCrypto(config)
    # 设置缓存过期时间10秒
    client.crypto_key_manager = CachingCryptoKeyManager(LocalDataKeyMaterialCache(), 10)
    # 设置缓存最大字节数1024字节
    client.crypto_key_manager.max_encryption_bytes = 1024
    # 设置缓存最大加密消息数量
    client.crypto_key_manager.max_encryption_messages = 10
    key_provider = DefaultDataKeyProvider(AES_KEY_ARN)
    cipher_text, enc_material = client.encrypt(key_provider, plain_data.encode("utf-8"), ENCRYPTION_CONTEXT)
    cipher_text_str = base64.standard_b64encode(cipher_text).decode("utf-8")
    print(u"加密密文: " + cipher_text_str)
    return cipher_text_str


def decrypt_with_caching(cipher_text_str):
    cipher_text_bytes = base64.standard_b64decode(cipher_text_str.encode("utf-8"))
    config = AliyunConfig(ACCESS_KEY_ID, ACCESS_KEY_SECRET)
    client = AliyunCrypto(config)
    # 设置缓存过期时间10秒
    client.crypto_key_manager = CachingCryptoKeyManager(LocalDataKeyMaterialCache(), 10)
    # 设置缓存最大字节数1024字节
    client.crypto_key_manager.max_encryption_bytes = 1024
    # 设置缓存最大加密消息数量
    client.crypto_key_manager.max_encryption_messages = 10
    key_provider = DefaultDataKeyProvider(AES_KEY_ARN)
    plain_text, dec_material = client.decrypt(key_provider, cipher_text_bytes)
    print(u"解密结果: " + bytes.decode(plain_text))


if __name__ == '__main__':
    AES_KEY_ARN = os.getenv("AES_KEY_ARN")
    ACCESS_KEY_ID = os.getenv("ACCESS_KEY_ID")
    ACCESS_KEY_SECRET = os.getenv("ACCESS_KEY_SECRET")
    ENCRYPTION_CONTEXT = {
        "this": "context",
        "can help you": "to confirm",
        "this data": "is your original data"
    }
    cipher_text = encrypt_with_caching()
    decrypt_with_caching(cipher_text)
