# -*- coding: UTF-8 -*-

import base64
import os

import pymysql

from aliyun_encryption_sdk.cache.local import LocalDataKeyMaterialCache
from aliyun_encryption_sdk.ckm.cache import CachingCryptoKeyManager
from aliyun_encryption_sdk.client import AliyunCrypto
from aliyun_encryption_sdk.kms import AliyunConfig
from aliyun_encryption_sdk.provider.default import DefaultDataKeyProvider


def user_add(user):
    # 连接database
    conn = db_connection()
    # 得到一个可以执行SQL语句并且将结果作为字典返回的游标
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)
    # 定义要执行的SQL语句
    sql = 'insert into user(name, email) values(%s,%s);'
    # 执行SQL语句
    cursor.execute(sql, [user.name, user.email])
    print("insert name: " + user.name)
    print("insert email: " + user.email)
    # 涉及写操作要注意提交
    conn.commit()
    last_id = cursor.lastrowid
    # 关闭光标对象
    cursor.close()
    # 关闭数据库连接
    conn.close()
    return last_id


def user_select_by_id(id):
    # 连接database
    conn = db_connection()
    # 得到一个可以执行SQL语句并且将结果作为字典返回的游标
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)
    # 定义要执行的SQL语句
    sql = 'select * from user where id = %s;'
    # 执行SQL语句
    cursor.execute(sql, [id])
    result = cursor.fetchone()
    print("select result: " + str(result))
    user = User()
    user.__dict__ = result
    # 关闭光标对象
    cursor.close()
    # 关闭数据库连接
    conn.close()
    return user


def enc_convert():
    def enc_(func):
        def wrapper(self, plain_text):
            provider = DefaultDataKeyProvider(AES_KEY_ARN)
            client = build_aliyun_crypto(False)
            cipher_text, enc_material = client.encrypt(provider, plain_text.encode("utf-8"), ENCRYPTION_CONTEXT)
            cipher_text_str = base64.standard_b64encode(cipher_text).decode("utf-8")
            f = func(self, cipher_text_str)
            return f

        return wrapper

    return enc_


def dec_convert(column_name):
    def dec_(func):
        def wrapper(self):
            user = self.__dict__
            cipher_text = user.get(column_name)
            cipher_text_bytes = base64.standard_b64decode(cipher_text.encode("utf-8"))
            provider = DefaultDataKeyProvider(AES_KEY_ARN)
            client = build_aliyun_crypto(False)
            plain_text, dec_material = client.decrypt(provider, cipher_text_bytes)
            user[column_name] = bytes.decode(plain_text)
            result = User()
            result.__dict__ = user
            f = func(result)
            return f

        return wrapper

    return dec_


def db_connection():
    # 连接database
    conn = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        passwd=DB_PASS,
        database=DB_NAME,
        charset="utf8")
    return conn


def build_aliyun_crypto(cache=False):
    config = AliyunConfig(ACCESS_KEY_ID, ACCESS_KEY_SECRET)
    client = AliyunCrypto(config)
    if cache:
        client.crypto_key_manager = CachingCryptoKeyManager(LocalDataKeyMaterialCache(), 5)
    return client


class User(object):
    @dec_convert(column_name="name")
    def get_name(self):
        return self.name

    @enc_convert()
    def set_name(self, value):
        self.name = value

    @dec_convert(column_name="email")
    def get_email(self):
        return self.email

    @enc_convert()
    def set_email(self, value):
        self.email = value


if __name__ == '__main__':
    AES_KEY_ARN = os.getenv("AES_KEY_ARN")
    ACCESS_KEY_ID = os.getenv("ACCESS_KEY_ID")
    ACCESS_KEY_SECRET = os.getenv("ACCESS_KEY_SECRET")
    ENCRYPTION_CONTEXT = {
        "this": "context",
        "can help you": "to confirm",
        "this data": "is your original data"
    }
    DB_HOST = os.getenv("DB_HOST")
    DB_PORT = int(os.getenv("DB_PORT", 3306))
    DB_USER = os.getenv("DB_USER")
    DB_PASS = os.getenv("DB_PASS")
    DB_NAME = os.getenv("DB_NAME")
    user = User()
    user.set_name("test")
    user.set_email("test@example.com")
    last_inset_id = user_add(user)
    user = user_select_by_id(last_inset_id)
    print("decrypt name: " + user.get_name())
    print("decrypt email: " + user.get_email())
