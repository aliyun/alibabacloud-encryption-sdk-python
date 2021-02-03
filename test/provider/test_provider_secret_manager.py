import pytest
from aliyunsdkcore.acs_exception.exceptions import ClientException
from mock import MagicMock, sentinel

import aliyun_encryption_sdk
from aliyun_encryption_sdk.handle.format import FormatHandler
from aliyun_encryption_sdk.kms.kms import AliyunKms
from aliyun_encryption_sdk.model import CipherHeader
from aliyun_encryption_sdk.provider.base import BaseDataKeyProvider
from aliyun_encryption_sdk.provider.secret_manager import SecretManagerDataKeyProvider

KEY_ID = "acs:kms:RegionId:UserId:key/CmkId"
TEST_DATA_KEY_NAME = "data_key_name"


def build_provider(**kwargs):
    parameter = dict(
        key_id=KEY_ID,
        data_key_name=TEST_DATA_KEY_NAME
    )
    parameter.update(kwargs)
    return SecretManagerDataKeyProvider(**parameter)


@pytest.mark.parametrize(
    "invalid_kwargs, error_message",
    (
        (dict(data_key_name=None), r"'data_key_name' must be str type"),
    ),
)
def test_invalid_parameter_type(invalid_kwargs, error_message):
    with pytest.raises(TypeError) as e:
        build_provider(**invalid_kwargs)

    e.match(error_message)


@pytest.yield_fixture
def patch_base64_b64decode(mocker):
    mocker.patch.object(aliyun_encryption_sdk.provider.secret_manager.base64, "b64decode")
    yield aliyun_encryption_sdk.provider.secret_manager.base64.b64decode


def test_get_cipher_header_unprocessed_type(patch_base64_b64decode):
    mock_kms = MagicMock(
        __class__=AliyunKms,
        get_secret_value=MagicMock(return_value=(sentinel.secret_data, "binary")),
    )
    mock_format_handle = MagicMock(
        __class__=FormatHandler,
        deserialize_cipher_header=MagicMock(),
    )
    provider = build_provider(kms=mock_kms, format_handle=mock_format_handle)

    with pytest.raises(Exception) as e:
        provider.get_cipher_header()

    e.match(r"Unprocessed case where secretDataType is binary")


def test_get_cipher_header_processed_type(patch_base64_b64decode):
    mock_kms = MagicMock(
        __class__=AliyunKms,
        get_secret_value=MagicMock(return_value=(sentinel.secret_data, "text")),
    )
    mock_format_handle = MagicMock(
        __class__=FormatHandler,
        deserialize_cipher_header=MagicMock(),
    )
    provider = build_provider(kms=mock_kms, format_handle=mock_format_handle)

    result = provider.get_cipher_header()

    mock_kms.get_secret_value.assert_called_once_with(
        provider.key, provider._data_key_name
    )
    patch_base64_b64decode.assert_called_once_with(sentinel.secret_data)
    mock_format_handle.deserialize_cipher_header.assert_called_once_with(patch_base64_b64decode.return_value)
    assert result is mock_format_handle.deserialize_cipher_header.return_value


def test_get_cipher_header_resource_not_found_exception(patch_base64_b64decode):
    mock_kms = MagicMock(
        __class__=AliyunKms,
        get_secret_value=MagicMock(side_effect=ClientException("Forbidden.ResourceNotFound", "Resource Not Found!")),
    )
    mock_format_handle = MagicMock(
        __class__=FormatHandler,
        deserialize_cipher_header=MagicMock(),
    )
    provider = build_provider(kms=mock_kms, format_handle=mock_format_handle)

    result = provider.get_cipher_header()

    mock_kms.get_secret_value.assert_called_once_with(
        provider.key, provider._data_key_name
    )
    assert not patch_base64_b64decode.called
    assert not mock_format_handle.deserialize_cipher_header.called
    assert result is None


def test_get_cipher_header_other_exception(patch_base64_b64decode):
    mock_kms = MagicMock(
        __class__=AliyunKms,
        get_secret_value=MagicMock(side_effect=ClientException("Undefined", "Undefined Exception")),
    )
    mock_format_handle = MagicMock(
        __class__=FormatHandler,
        deserialize_cipher_header=MagicMock(),
    )
    provider = build_provider(kms=mock_kms, format_handle=mock_format_handle)

    with pytest.raises(ClientException):
        provider.get_cipher_header()


@pytest.yield_fixture
def patch_decrypt_data_key(mocker):
    mocker.patch.object(SecretManagerDataKeyProvider, "decrypt_data_key")
    yield SecretManagerDataKeyProvider.decrypt_data_key


@pytest.yield_fixture
def patch_DecryptionMaterial(mocker):
    mocker.patch.object(aliyun_encryption_sdk.provider.secret_manager, "DecryptionMaterial")
    yield aliyun_encryption_sdk.provider.secret_manager.DecryptionMaterial


def test_get_encryption_material_success(patch_decrypt_data_key, patch_DecryptionMaterial):
    patch_decrypt_data_key.return_value = MagicMock(plaintext_data_key=sentinel.plaintext_data_key)
    mock_cipher_header = MagicMock(
        algorithm=sentinel.algorithm,
        encryption_context=sentinel.encryption_context,
        encrypted_data_keys=sentinel.encrypted_data_keys,
        version=sentinel.version,
    )
    mock_encryption_material = MagicMock()
    provider = build_provider()

    result = provider.get_encryption_material(mock_cipher_header, mock_encryption_material)

    patch_DecryptionMaterial.assert_called_once_with(
        encryption_context=sentinel.encryption_context,
        algorithm=sentinel.algorithm,
    )
    patch_decrypt_data_key.assert_called_once_with(patch_DecryptionMaterial.return_value, sentinel.encrypted_data_keys)
    assert result.plaintext_data_key is sentinel.plaintext_data_key
    assert result.encrypted_data_keys is sentinel.encrypted_data_keys
    assert result.version is sentinel.version
    assert result.algorithm is sentinel.algorithm
    assert result.encryption_context is sentinel.encryption_context


def test_get_encryption_material_failed(patch_decrypt_data_key, patch_DecryptionMaterial):
    patch_decrypt_data_key.return_value = None
    mock_cipher_header = MagicMock(
        algorithm=sentinel.algorithm,
        encryption_context=sentinel.encryption_context,
        encrypted_data_keys=sentinel.encrypted_data_keys,
        version=sentinel.version,
    )
    mock_encryption_material = MagicMock()
    provider = build_provider()

    with pytest.raises(Exception) as e:
        provider.get_encryption_material(mock_cipher_header, mock_encryption_material)

    e.match(r"Failed to get dataKey from 'encrypted_data_keys'")


@pytest.yield_fixture
def patch_CipherHeader(mocker):
    mocker.patch.object(aliyun_encryption_sdk.provider.secret_manager, "CipherHeader")
    yield aliyun_encryption_sdk.provider.secret_manager.CipherHeader


@pytest.yield_fixture
def patch_calculate_header_auth_tag(mocker):
    mocker.patch.object(CipherHeader, "calculate_header_auth_tag")
    yield CipherHeader.calculate_header_auth_tag


@pytest.yield_fixture
def patch_base64_b64encode(mocker):
    mocker.patch.object(aliyun_encryption_sdk.provider.secret_manager.base64, "b64encode")
    yield aliyun_encryption_sdk.provider.secret_manager.base64.b64encode


@pytest.yield_fixture
def patch_uuid1(mocker):
    mocker.patch.object(aliyun_encryption_sdk.provider.secret_manager.uuid, "uuid1")
    yield aliyun_encryption_sdk.provider.secret_manager.uuid.uuid1


def test_store_cipher_header(
    patch_CipherHeader,
    patch_base64_b64encode,
    patch_uuid1
):
    mock_encryption_material = MagicMock(
        algorithm=sentinel.algorithm,
        encryption_context=sentinel.encryption_context,
        encrypted_data_keys=sentinel.encrypted_data_keys,
        plaintext_data_key=sentinel.plaintext_data_key
    )
    mock_kms = MagicMock(
        __class__=AliyunKms,
        create_secret=MagicMock(),
    )
    mock_format_handle = MagicMock(
        __class__=FormatHandler,
        serialize_cipher_header=MagicMock(),
    )
    provider = build_provider(kms=mock_kms, format_handle=mock_format_handle)

    provider.store_cipher_header(mock_encryption_material)

    patch_CipherHeader.assert_called_once_with(
        algorithm=sentinel.algorithm,
        encryption_context=sentinel.encryption_context,
        encrypted_data_keys=sentinel.encrypted_data_keys
    )
    patch_CipherHeader.return_value.calculate_header_auth_tag.assert_called_once_with(
        sentinel.plaintext_data_key
    )
    mock_format_handle.serialize_cipher_header.assert_called_once_with(patch_CipherHeader.return_value)
    patch_base64_b64encode.assert_called_once_with(mock_format_handle.serialize_cipher_header.return_value)
    patch_uuid1.assert_called_once_with()
    mock_kms.create_secret.assert_called_once_with(
        provider.key, provider._data_key_name,
        patch_uuid1.return_value,
        patch_base64_b64encode.return_value,
        'text'
    )


def test_process_cipher_material():
    mock_cipher_material = MagicMock(cipher_body=sentinel.cipher_body)
    mock_format_handle = MagicMock(
        __class__=FormatHandler,
        serialize_cipher_body=MagicMock(),
    )
    provider = build_provider(format_handle=mock_format_handle)

    result = provider.process_cipher_material(mock_cipher_material)

    mock_format_handle.serialize_cipher_body.assert_called_once_with(sentinel.cipher_body)
    assert result is mock_format_handle.serialize_cipher_body.return_value


@pytest.yield_fixture
def patch_get_cipher_header(mocker):
    mocker.patch.object(SecretManagerDataKeyProvider, "get_cipher_header")
    yield SecretManagerDataKeyProvider.get_cipher_header


@pytest.yield_fixture
def patch_CipherMaterial(mocker):
    mocker.patch.object(aliyun_encryption_sdk.provider.secret_manager, "CipherMaterial")
    yield aliyun_encryption_sdk.provider.secret_manager.CipherMaterial


def test_get_cipher_material_success(patch_get_cipher_header, patch_CipherMaterial):
    mock_format_handle = MagicMock(
        __class__=FormatHandler,
        deserialize_cipher_body=MagicMock(),
    )
    provider = build_provider(format_handle=mock_format_handle)

    result = provider.get_cipher_material(sentinel.cipher_text)

    mock_format_handle.deserialize_cipher_body.assert_called_once_with(sentinel.cipher_text)
    patch_get_cipher_header.assert_called_once_with()
    patch_CipherMaterial.assert_called_once_with(
        patch_get_cipher_header.return_value,
        mock_format_handle.deserialize_cipher_body.return_value
    )
    assert result is patch_CipherMaterial.return_value


def test_get_cipher_material_failed(patch_get_cipher_header):
    patch_get_cipher_header.return_value = None
    mock_format_handle = MagicMock(
        __class__=FormatHandler,
        deserialize_cipher_body=MagicMock(),
    )
    provider = build_provider(format_handle=mock_format_handle)

    with pytest.raises(Exception) as e:
        provider.get_cipher_material(sentinel.cipher_text)

    e.match(r"cannot get dataKey from external")


@pytest.yield_fixture
def patch_encrypt_data_key(mocker):
    mocker.patch.object(BaseDataKeyProvider, "encrypt_data_key")
    yield BaseDataKeyProvider.encrypt_data_key


@pytest.yield_fixture
def patch_get_encryption_material(mocker):
    mocker.patch.object(SecretManagerDataKeyProvider, "get_encryption_material")
    yield SecretManagerDataKeyProvider.get_encryption_material


@pytest.yield_fixture
def patch_store_cipher_header(mocker):
    mocker.patch.object(SecretManagerDataKeyProvider, "store_cipher_header")
    yield SecretManagerDataKeyProvider.store_cipher_header


def test_encrypt_data_key_get_header_none(
    patch_get_cipher_header,
    patch_encrypt_data_key,
    patch_get_encryption_material,
    patch_store_cipher_header
):
    patch_get_cipher_header.return_value = None
    provider = build_provider()

    result = provider.encrypt_data_key(sentinel.encryption_material)

    patch_get_cipher_header.assert_called_once_with()
    assert not patch_get_encryption_material.called
    patch_encrypt_data_key.assert_called_once_with(sentinel.encryption_material)
    patch_store_cipher_header.assert_called_once_with(patch_encrypt_data_key.return_value)
    assert result is patch_encrypt_data_key.return_value


def test_encrypt_data_key_get_header_exception(patch_get_cipher_header):
    patch_get_cipher_header.side_effect = Exception()
    provider = build_provider()

    with pytest.raises(Exception):
        provider.encrypt_data_key(sentinel.encryption_material)


def test_encrypt_data_key_get_header_success_get_encryption_material_failed(
    patch_get_cipher_header,
    patch_get_encryption_material,
):
    patch_get_encryption_material.side_effect = Exception("Failed to get dataKey from 'encrypted_data_keys'")
    provider = build_provider()

    with pytest.raises(Exception) as e:
        provider.encrypt_data_key(sentinel.encryption_material)

    e.match("Failed to get dataKey from 'encrypted_data_keys'")


def test_encrypt_data_key_get_header_success_get_encryption_material_success(
    patch_get_cipher_header,
    patch_get_encryption_material,
    patch_encrypt_data_key,
    patch_store_cipher_header
):
    provider = build_provider()

    result = provider.encrypt_data_key(sentinel.encryption_material)

    patch_get_cipher_header.assert_called_once_with()
    patch_get_encryption_material.assert_called_once_with(
        patch_get_cipher_header.return_value,
        sentinel.encryption_material
    )
    assert not patch_encrypt_data_key.called
    assert not patch_store_cipher_header.called
    assert result is patch_get_encryption_material.return_value
