import base64

import pytest
from mock import MagicMock, sentinel

import aliyun_encryption_sdk
from aliyun_encryption_sdk import to_str
from aliyun_encryption_sdk.handle.format import Asn1FormatHandler, ASN1CipherHeader, ASN1CipherBody, ASN1Cipher
from aliyun_encryption_sdk.model import CipherHeader, Algorithm, CipherBody, CipherMaterial
from aliyun_encryption_sdk.provider import EncryptedDataKey

ENCRYPTION_CONTEXT = {
    "key": "value"
}

ENCRYPTED_DATA_KEYS = {
    EncryptedDataKey(
        key_id=b'acs:kms:RegionId:UserId:key/CmkId',
        encrypted_data_key=b'NmE3OTViMjYtYmFjZC00MmJkLTg2MGEtMjVjMTg5MWExZjEx'
                           b'oQhjkULy6VLcQH6fRGuKvC1G6erG/KsW3s8gomiQKTIuFIn7W'
                           b'Dt1BSPBnuAzu82bYeQqKGnyHsb4cD/v5Kv5xNdq/WgdZCoK'
    )
}

CIPHER_HEADER = CipherHeader(
    algorithm=Algorithm.AES_GCM_NOPADDING_256,
    encryption_context=ENCRYPTION_CONTEXT,
    encrypted_data_keys=ENCRYPTED_DATA_KEYS,
    version=1,
    header_iv=b'\xca\xca\x97:)\x82\x18\xc2\xa9\xa9\xf5\x00',
    header_auth_tag=b'\xcb\xa2\x00\xc2\xfc\xe3\xab\xc0\xca\x8b\\\xaed@\xa1\x1e'
)

CIPHER_BODY = CipherBody(
    iv=b'@^~x9\xde\x92\xc6.r#\xfe',
    cipher_text=b'\rt\x7fc\x04\xf49q\xa5X\xf0\xf6\xf9\x1d\xa6|',
    auth_tag=b'v\xd3&\xc5\x8c7}\xc9\x8cJ\xa7#\x0e,\xdb\xd9'
)

CIPHER_MATERIAL = CipherMaterial(
    cipher_header=CIPHER_HEADER,
    cipher_body=CIPHER_BODY
)


def test_combine_asn1_header():
    format_handler = Asn1FormatHandler()

    result = format_handler._combine_asn1_header(CIPHER_HEADER)

    assert isinstance(result, ASN1CipherHeader)
    assert result["version"].native == CIPHER_HEADER.version
    assert result["algorithm"].native == CIPHER_HEADER.algorithm.algorithm_id
    for encrypted_data_key in result["encrypted_data_keys"].native:
        for source_data_key in CIPHER_HEADER.encrypted_data_keys:
            if encrypted_data_key["key_id"] == source_data_key.key_arn:
                assert encrypted_data_key["encrypted_data_key"] == base64.b64decode(source_data_key.encrypted_data_key)
                break
    for context in result['encryption_context'].native:
        if CIPHER_HEADER.encryption_context[to_str(context["key"])]:
            assert to_str(context["value"]) == CIPHER_HEADER.encryption_context[to_str(context["key"])]
    assert result["header_iv"].native == CIPHER_HEADER.header_iv
    assert result["header_auth_tag"].native == CIPHER_HEADER.header_auth_tag


def test_parse_asn1_header():
    format_handler = Asn1FormatHandler()
    test_asn1_header = format_handler._combine_asn1_header(CIPHER_HEADER)

    result = format_handler._parse_asn1_header(test_asn1_header)

    assert isinstance(result, CipherHeader)
    assert result.version == CIPHER_HEADER.version
    assert result.algorithm == CIPHER_HEADER.algorithm
    assert result.encrypted_data_keys == CIPHER_HEADER.encrypted_data_keys
    assert result.encryption_context == CIPHER_HEADER.encryption_context
    assert result.header_iv == CIPHER_HEADER.header_iv
    assert result.header_auth_tag == CIPHER_HEADER.header_auth_tag


def test_combine_asn1_body():
    format_handler = Asn1FormatHandler()

    result = format_handler._combine_asn1_body(CIPHER_BODY)

    assert isinstance(result, ASN1CipherBody)
    assert result["iv"].native == CIPHER_BODY.iv
    assert result["cipher_text"].native == CIPHER_BODY.cipher_text
    assert result["auth_tag"].native == CIPHER_BODY.auth_tag


def test_parse_asn1_body():
    format_handler = Asn1FormatHandler()
    test_asn1_body = format_handler._combine_asn1_body(CIPHER_BODY)

    result = format_handler._parse_asn1_body(test_asn1_body)

    assert isinstance(result, CipherBody)
    assert result.iv == CIPHER_BODY.iv
    assert result.cipher_text == CIPHER_BODY.cipher_text
    assert result.auth_tag == CIPHER_BODY.auth_tag


def test_combine_asn1_encryption_info():
    format_handler = Asn1FormatHandler()
    test_asn1_header = format_handler._combine_asn1_header(CIPHER_HEADER)
    test_asn1_body = format_handler._combine_asn1_body(CIPHER_BODY)

    result = format_handler._combine_asn1_encryption_info(test_asn1_header, test_asn1_body)

    assert isinstance(result, ASN1Cipher)
    assert result["header"] is test_asn1_header
    assert result["body"] is test_asn1_body


@pytest.yield_fixture
def patch_combine_asn1_header(mocker):
    mocker.patch.object(Asn1FormatHandler, "_combine_asn1_header")
    yield Asn1FormatHandler._combine_asn1_header


@pytest.yield_fixture
def patch_combine_asn1_body(mocker):
    mocker.patch.object(Asn1FormatHandler, "_combine_asn1_body")
    yield Asn1FormatHandler._combine_asn1_body


@pytest.yield_fixture
def patch_combine_asn1_encryption_info(mocker):
    mocker.patch.object(Asn1FormatHandler, "_combine_asn1_encryption_info")
    yield Asn1FormatHandler._combine_asn1_encryption_info


def test_serialize(
        patch_combine_asn1_header,
        patch_combine_asn1_body,
        patch_combine_asn1_encryption_info
):
    mock_material = MagicMock(cipher_header=sentinel.cipher_header, cipher_body=sentinel.cipher_body)
    format_handler = Asn1FormatHandler()

    result = format_handler.serialize(mock_material)

    patch_combine_asn1_header.assert_called_once_with(sentinel.cipher_header)
    patch_combine_asn1_body.assert_called_once_with(sentinel.cipher_body)
    patch_combine_asn1_encryption_info.assert_called_once_with(
        patch_combine_asn1_header.return_value,
        patch_combine_asn1_body.return_value
    )
    patch_combine_asn1_encryption_info.return_value.dump.assert_called_once_with()
    assert result is patch_combine_asn1_encryption_info.return_value.dump.return_value


def test_serialize_cipher_header(patch_combine_asn1_header):
    format_handler = Asn1FormatHandler()

    result = format_handler.serialize_cipher_header(sentinel.cipher_header)

    patch_combine_asn1_header.assert_called_once_with(sentinel.cipher_header)
    patch_combine_asn1_header.return_value.dump.assert_called_once_with()
    assert result is patch_combine_asn1_header.return_value.dump.return_value


def test_serialize_cipher_body(patch_combine_asn1_body):
    format_handler = Asn1FormatHandler()

    result = format_handler.serialize_cipher_body(sentinel.cipher_body)

    patch_combine_asn1_body.assert_called_once_with(sentinel.cipher_body)
    patch_combine_asn1_body.return_value.dump.assert_called_once_with()
    assert result is patch_combine_asn1_body.return_value.dump.return_value


@pytest.yield_fixture
def patch_parse_asn1_header(mocker):
    mocker.patch.object(Asn1FormatHandler, "_parse_asn1_header")
    yield Asn1FormatHandler._parse_asn1_header


@pytest.yield_fixture
def patch_parse_asn1_body(mocker):
    mocker.patch.object(Asn1FormatHandler, "_parse_asn1_body")
    yield Asn1FormatHandler._parse_asn1_body


@pytest.yield_fixture
def patch_ASN1Cipher_load(mocker):
    mocker.patch.object(ASN1Cipher, "load")
    yield ASN1Cipher.load


@pytest.yield_fixture
def patch_cipher_material(mocker):
    mocker.patch.object(aliyun_encryption_sdk.handle.format, "CipherMaterial")
    yield aliyun_encryption_sdk.handle.format.CipherMaterial


def test_deserialize(
        patch_parse_asn1_header,
        patch_parse_asn1_body,
        patch_ASN1Cipher_load,
        patch_cipher_material
):
    patch_ASN1Cipher_load.return_value = MagicMock()
    format_handler = Asn1FormatHandler()

    result = format_handler.deserialize(sentinel.cipher_text)

    patch_ASN1Cipher_load.assert_called_once_with(sentinel.cipher_text)
    patch_parse_asn1_header.assert_called_once_with(patch_ASN1Cipher_load.return_value["header"])
    patch_parse_asn1_body.assert_called_once_with(patch_ASN1Cipher_load.return_value["body"])
    patch_cipher_material.assert_called_once_with(
        patch_parse_asn1_header.return_value,
        patch_parse_asn1_body.return_value
    )
    assert result is patch_cipher_material.return_value


@pytest.yield_fixture
def patch_ASN1CipherHeader_load(mocker):
    mocker.patch.object(ASN1CipherHeader, "load")
    yield ASN1CipherHeader.load


def test_deserialize_cipher_header(
    patch_ASN1CipherHeader_load,
    patch_parse_asn1_header
):
    patch_ASN1CipherHeader_load.return_value = MagicMock()
    format_handler = Asn1FormatHandler()

    result = format_handler.deserialize_cipher_header(sentinel.cipher_text)

    patch_ASN1CipherHeader_load.assert_called_once_with(sentinel.cipher_text)
    patch_parse_asn1_header.assert_called_once_with(patch_ASN1CipherHeader_load.return_value)
    assert result is patch_parse_asn1_header.return_value


@pytest.yield_fixture
def patch_ASN1CipherBody_load(mocker):
    mocker.patch.object(ASN1CipherBody, "load")
    yield ASN1CipherBody.load


def test_deserialize_cipher_body(
    patch_ASN1CipherBody_load,
    patch_parse_asn1_body
):
    patch_ASN1CipherBody_load.return_value = MagicMock()
    format_handler = Asn1FormatHandler()

    result = format_handler.deserialize_cipher_body(sentinel.cipher_text)

    patch_ASN1CipherBody_load.assert_called_once_with(sentinel.cipher_text)
    patch_parse_asn1_body.assert_called_once_with(patch_ASN1CipherBody_load.return_value)
    assert result is patch_parse_asn1_body.return_value
