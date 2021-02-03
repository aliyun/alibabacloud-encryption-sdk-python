import abc
import base64

import six
from asn1crypto import core

from aliyun_encryption_sdk import to_bytes, to_str
from aliyun_encryption_sdk.model import CipherHeader, Algorithm, CipherMaterial, CipherBody
from aliyun_encryption_sdk.provider import EncryptedDataKey


@six.add_metaclass(abc.ABCMeta)
class FormatHandler(object):

    @abc.abstractmethod
    def serialize(self, cipher_material):
        pass

    @abc.abstractmethod
    def serialize_cipher_header(self, cipher_header):
        pass

    @abc.abstractmethod
    def serialize_cipher_body(self, cipher_body):
        pass

    @abc.abstractmethod
    def deserialize(self, cipher_text):
        pass

    @abc.abstractmethod
    def deserialize_cipher_header(self, cipher_text):
        pass

    @abc.abstractmethod
    def deserialize_cipher_body(self, cipher_text):
        pass


class Asn1FormatHandler(FormatHandler):

    def serialize(self, cipher_material):
        cipher_header = cipher_material.cipher_header
        cipher_body = cipher_material.cipher_body
        asn1_header, asn1_body = None, None
        if cipher_header:
            asn1_header = self._combine_asn1_header(cipher_header)
        if cipher_body:
            asn1_body = self._combine_asn1_body(cipher_body)
        asn1_cipher = self._combine_asn1_encryption_info(asn1_header, asn1_body)
        return asn1_cipher.dump()

    def serialize_cipher_header(self, cipher_header):
        asn1_header = self._combine_asn1_header(cipher_header)
        return asn1_header.dump()

    def serialize_cipher_body(self, cipher_body):
        asn1_body = self._combine_asn1_body(cipher_body)
        return asn1_body.dump()

    def deserialize(self, cipher_text):
        asn1_cipher = ASN1Cipher.load(cipher_text)
        cipher_header = self._parse_asn1_header(asn1_cipher['header'])
        cipher_body = self._parse_asn1_body(asn1_cipher['body'])
        return CipherMaterial(cipher_header, cipher_body)

    def deserialize_cipher_header(self, cipher_text):
        asn1_header = ASN1CipherHeader.load(cipher_text)
        return self._parse_asn1_header(asn1_header)

    def deserialize_cipher_body(self, cipher_text):
        asn1_body = ASN1CipherBody.load(cipher_text)
        return self._parse_asn1_body(asn1_body)

    @staticmethod
    def _combine_asn1_header(header):
        asn1_header = ASN1CipherHeader()
        asn1_header['version'] = header.version
        asn1_header['algorithm'] = header.algorithm.algorithm_id

        asn1_data_keys = ASN1EncryptedDataKeys()
        for data_key in header.encrypted_data_keys:
            asn1_data_key = ASN1EncryptedDataKey()
            asn1_data_key['key_id'] = data_key.key_arn
            asn1_data_key['encrypted_data_key'] = base64.b64decode(data_key.encrypted_data_key)
            asn1_data_keys.append(asn1_data_key)
        asn1_header['encrypted_data_keys'] = asn1_data_keys

        if header.encryption_context:
            asn1_contexts = ASN1EncryptionContexts()
            for k, v in header.encryption_context.items():
                asn1_context = ASN1EncryptionContext()
                asn1_context['key'] = to_bytes(k)
                asn1_context['value'] = to_bytes(v)
                asn1_contexts.append(asn1_context)
            asn1_header['encryption_context'] = asn1_contexts
        else:
            asn1_header['encryption_context'] = ASN1EncryptionContexts(contents=bytes())

        asn1_header['header_iv'] = header.header_iv
        asn1_header['header_auth_tag'] = header.header_auth_tag
        return asn1_header

    @staticmethod
    def _parse_asn1_header(asn1_header):
        version = asn1_header['version'].native
        algorithm = Algorithm.get_algorithm_by_id(asn1_header['algorithm'].native)

        encrypted_data_keys = set([])
        for encrypted_data_key in asn1_header['encrypted_data_keys'].native:
            encrypted_data_keys.add(
                EncryptedDataKey(
                    encrypted_data_key['key_id'],
                    base64.b64encode(encrypted_data_key['encrypted_data_key'])
                )
            )

        encryption_context = {}
        for context in asn1_header['encryption_context'].native:
            encryption_context[to_str(context['key'])] = to_str(context['value'])

        header_iv = asn1_header['header_iv'].native
        header_auth_tag = asn1_header['header_auth_tag'].native

        kwargs = dict(
            algorithm=algorithm,
            encryption_context=encryption_context,
            encrypted_data_keys=encrypted_data_keys,
            version=version,
            header_iv=header_iv,
            header_auth_tag=header_auth_tag
        )
        return CipherHeader(**kwargs)

    @staticmethod
    def _combine_asn1_body(body):
        asn1_body = ASN1CipherBody()
        asn1_body['iv'] = body.iv
        asn1_body['cipher_text'] = body.cipher_text
        asn1_body['auth_tag'] = body.auth_tag
        return asn1_body

    @staticmethod
    def _parse_asn1_body(asn1_body):
        iv = asn1_body['iv'].native
        cipher_text = asn1_body['cipher_text'].native
        auth_tag = asn1_body['auth_tag'].native
        return CipherBody(iv, cipher_text, auth_tag)

    @staticmethod
    def _combine_asn1_encryption_info(header, body):
        asn1_cipher = ASN1Cipher()
        asn1_cipher['header'] = header
        asn1_cipher['body'] = body
        return asn1_cipher


class ASN1EncryptedDataKey(core.Sequence):
    _fields = [
        ('key_id', core.OctetString),
        ('encrypted_data_key', core.OctetString),
    ]


class ASN1EncryptedDataKeys(core.SetOf):
    _child_spec = ASN1EncryptedDataKey


class ASN1EncryptionContext(core.Sequence):
    _fields = [
        ('key', core.OctetString),
        ('value', core.OctetString),
    ]


class ASN1EncryptionContexts(core.SetOf):
    _child_spec = ASN1EncryptionContext


class ASN1CipherHeader(core.Sequence):
    _fields = [
        ('version', core.Integer),
        ('algorithm', core.Integer),
        ('encrypted_data_keys', ASN1EncryptedDataKeys),
        ('encryption_context', ASN1EncryptionContexts),
        ('header_iv', core.OctetString),
        ('header_auth_tag', core.OctetString),
    ]


class ASN1CipherBody(core.Sequence):
    _fields = [
        ('iv', core.OctetString),
        ('cipher_text', core.OctetString),
        ('auth_tag', core.OctetString),
    ]


class ASN1Cipher(core.Sequence):
    _fields = [
        ('header', ASN1CipherHeader),
        ('body', ASN1CipherBody),
    ]
