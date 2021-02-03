# -*- coding: UTF-8 -*-
"""
oss upload with encrypted and download with decrypted
"""
import base64
import datetime
import os
import time

import oss2

from aliyun_encryption_sdk.cache.local import LocalDataKeyMaterialCache
from aliyun_encryption_sdk.ckm.cache import CachingCryptoKeyManager
from aliyun_encryption_sdk.client import AliyunCrypto
from aliyun_encryption_sdk.kms import AliyunConfig
from aliyun_encryption_sdk.provider.default import DefaultDataKeyProvider


def upload_with_encrypted(bucket, content, file_path):
    print("object plaintext: " + content)
    client = build_aliyun_crypto()
    provider = DefaultDataKeyProvider(AES_KEY_ARN)
    cipher_text, enc_material = client.encrypt(provider, content.encode("utf-8"), ENCRYPTION_CONTEXT)
    bucket.put_object(file_path, cipher_text)
    print("object enc result: " + base64.standard_b64encode(cipher_text).decode())


def download_with_decrypted(bucket, file_path):
    object_stream = bucket.get_object(file_path)
    cipher_text = object_stream.read()
    client = build_aliyun_crypto()
    provider = DefaultDataKeyProvider(AES_KEY_ARN)
    plain_text, dec_material = client.decrypt(provider, cipher_text)
    print("(simple)get object dec result: " + bytes.decode(plain_text) + "\n")


def build_aliyun_crypto(cache=False):
    config = AliyunConfig(ACCESS_KEY_ID, ACCESS_KEY_SECRET)
    client = AliyunCrypto(config)
    if cache:
        client.crypto_key_manager = CachingCryptoKeyManager(LocalDataKeyMaterialCache(), 5)
    return client


if __name__ == '__main__':
    AES_KEY_ARN = os.getenv("AES_KEY_ARN")
    ACCESS_KEY_ID = os.getenv("ACCESS_KEY_ID")
    ACCESS_KEY_SECRET = os.getenv("ACCESS_KEY_SECRET")
    ENCRYPTION_CONTEXT = {
        "this": "context",
        "can help you": "to confirm",
        "this data": "is your original data"
    }
    OSS_ENDPOINT = os.getenv("OSS_ENDPOINT")
    OSS_BUCKET_NAME = os.getenv("OSS_BUCKET_NAME")
    CONTENT = "jdjfhdus6182042795hlnf12s8yhfs976y2nfoshhnsdfsf235bvsmnhtskbcfd!"
    auth = oss2.Auth(ACCESS_KEY_ID, ACCESS_KEY_SECRET)
    bucket = oss2.Bucket(auth, OSS_ENDPOINT, OSS_BUCKET_NAME)
    current_date = datetime.datetime.now()
    file_path = "test" + "/" + str(current_date.year) + "/" + str(current_date.month) + "/" + str(current_date.day) \
                + "/" + str(int(round(time.time() * 1000))) + ".txt"
    upload_with_encrypted(bucket, CONTENT, file_path)
    print("=============== simple get object ===============")
    download_with_decrypted(bucket, file_path)
