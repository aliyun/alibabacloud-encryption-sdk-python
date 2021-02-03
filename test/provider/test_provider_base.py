import pytest
from mock import MagicMock, sentinel, call

import aliyun_encryption_sdk
from aliyun_encryption_sdk.handle.format import FormatHandler, Asn1FormatHandler
from aliyun_encryption_sdk.kms.kms import AliyunKms
from aliyun_encryption_sdk.model import Algorithm
from aliyun_encryption_sdk.provider.base import BaseDataKeyProvider


KEY_ID = "acs:kms:RegionId:UserId:key/CmkId"
HANGZHOU_KEY = "acs:kms:cn-hangzhou:UserId:key/CmkId"
HANGZHOU_KEY1 = "acs:kms:cn-hangzhou:UserId:key/CmkId1"
HANGZHOU_KEY2 = "acs:kms:cn-hangzhou:UserId:key/CmkId2"
BEIJING_KEY1 = "acs:kms:cn-beijing:UserId:key/CmkId1"
SHANGHAI_KEY1 = "acs:kms:cn-shanghai:UserId:key/CmkId1"


class MockDataKeyProvider(BaseDataKeyProvider):
    def process_cipher_material(self, cipher_material):
        pass

    def get_cipher_material(self, cipher_text):
        pass


def build_provider(**kwargs):
    parameter = dict(
        key_id=KEY_ID
    )
    parameter.update(kwargs)
    return MockDataKeyProvider(**parameter)


@pytest.mark.parametrize(
    "invalid_kwargs, error_message",
    (
        (dict(key_id=None), r"'key_id' must be str type"),
        (dict(kms=MagicMock()), r"'kms' must be AliyunKms type"),
        (dict(format_handle=None), r"'format_handle' must be FormatHandler type"),
        (dict(algorithm=None), r"'algorithm' must be Algorithm type"),
        (dict(keys=MagicMock()), r"'keys' must be set or list type")
    ),
)
def test_invalid_parameter_type(invalid_kwargs, error_message):
    with pytest.raises(TypeError) as e:
        build_provider(**invalid_kwargs)

    e.match(error_message)


def test_valid_parameter():
    moch_kms = MagicMock(__class__=AliyunKms)
    mock_format_handle = MagicMock(__class__=FormatHandler)
    keys = set()
    keys.add("acs:kms:RegionId:UserId:key/CmkId1")
    keys.add("acs:kms:RegionId:UserId:key/CmkId2")
    key_id = "acs:kms:RegionId:UserId:key/CmkId"
    valid_kwargs = dict(
        key_id=key_id,
        kms=moch_kms,
        format_handle=mock_format_handle,
        algorithm=Algorithm.AES_GCM_NOPADDING_128,
        keys=keys
    )

    provider = build_provider(**valid_kwargs)

    assert provider.kms is moch_kms
    assert provider.format_handle is mock_format_handle
    assert provider.algorithm is Algorithm.AES_GCM_NOPADDING_128
    for key in provider._keys:
        assert key.key_arn in keys


def test_default():
    provider = build_provider()

    assert provider.key.key_arn == KEY_ID
    assert provider.kms is None
    assert isinstance(provider.format_handle, Asn1FormatHandler)
    assert provider.algorithm is Algorithm.AES_GCM_NOPADDING_256
    assert provider._keys == set()


@pytest.yield_fixture
def patch_EncryptedDataKey(mocker):
    mocker.patch.object(aliyun_encryption_sdk.provider.base, "EncryptedDataKey")
    yield aliyun_encryption_sdk.provider.base.EncryptedDataKey


@pytest.yield_fixture
def patch_to_bytes(mocker):
    mocker.patch.object(aliyun_encryption_sdk.provider.base, "to_bytes")
    yield aliyun_encryption_sdk.provider.base.to_bytes


@pytest.yield_fixture
def patch_base64_b64decode(mocker):
    mocker.patch.object(aliyun_encryption_sdk.provider.base.base64, "b64decode")
    yield aliyun_encryption_sdk.provider.base.base64.b64decode


def test_encrypt_data_key_no_multi_keys(
    patch_EncryptedDataKey,
    patch_to_bytes,
    patch_base64_b64decode
):
    mock_encryption_material = MagicMock(encryption_context=sentinel.encryption_context)
    mock_kms = MagicMock(
        __class__=AliyunKms,
        generate_data_key=MagicMock(
            return_value=(sentinel.plaintext_data_key, sentinel.encrypted_data_key)
        ),
        reEncrypt_data_key=MagicMock(),
        encrypt_data_key=MagicMock()
    )
    provider = build_provider(kms=mock_kms)

    result = provider.encrypt_data_key(mock_encryption_material)

    mock_kms.generate_data_key.assert_called_once_with(
        provider.key, provider.algorithm, sentinel.encryption_context
    )
    patch_base64_b64decode.assert_called_once_with(sentinel.plaintext_data_key)
    assert not mock_kms.reEncrypt_data_key.called
    assert not mock_kms.encrypt_data_key.called
    assert patch_EncryptedDataKey.return_value in result.encrypted_data_keys
    assert result.plaintext_data_key is patch_base64_b64decode.return_value


def test_encrypt_data_key_multi_same_region_keys(
    patch_EncryptedDataKey,
    patch_to_bytes,
    patch_base64_b64decode
):
    mock_encryption_material = MagicMock(encryption_context=sentinel.encryption_context)
    mock_kms = MagicMock(
        __class__=AliyunKms,
        generate_data_key=MagicMock(
            return_value=(sentinel.plaintext_data_key,sentinel.encrypted_data_key)
        ),
        reEncrypt_data_key=MagicMock(side_effect=(sentinel.key1, sentinel.key2)),
        encrypt_data_key=MagicMock()
    )
    keys = {HANGZHOU_KEY1, HANGZHOU_KEY2}
    provider = build_provider(key_id=HANGZHOU_KEY, kms=mock_kms, keys=keys)

    result = provider.encrypt_data_key(mock_encryption_material)

    mock_kms.generate_data_key.assert_called_once_with(
        provider.key, provider.algorithm, sentinel.encryption_context
    )
    mock_kms.reEncrypt_data_key.assert_has_calls(
        [call(key, patch_EncryptedDataKey.return_value, sentinel.encryption_context) for key in provider._keys],
        True
    )
    assert not mock_kms.encrypt_data_key.called
    assert len(result.encrypted_data_keys) == 3
    assert patch_EncryptedDataKey.return_value in result.encrypted_data_keys
    assert sentinel.key1 in result.encrypted_data_keys
    assert sentinel.key2 in result.encrypted_data_keys
    assert result.plaintext_data_key is patch_base64_b64decode.return_value


def test_encrypt_data_key_multi_different_region_keys(
    patch_EncryptedDataKey,
    patch_to_bytes,
    patch_base64_b64decode
):
    mock_encryption_material = MagicMock(encryption_context=sentinel.encryption_context)
    mock_kms = MagicMock(
        __class__=AliyunKms,
        generate_data_key=MagicMock(
            return_value=(sentinel.plaintext_data_key, sentinel.encrypted_data_key)
        ),
        reEncrypt_data_key=MagicMock(),
        encrypt_data_key=MagicMock(side_effect=(sentinel.key1, sentinel.key2))
    )
    keys = {BEIJING_KEY1, SHANGHAI_KEY1}
    provider = build_provider(key_id=HANGZHOU_KEY, kms=mock_kms, keys=keys)

    result = provider.encrypt_data_key(mock_encryption_material)

    mock_kms.generate_data_key.assert_called_once_with(
        provider.key, provider.algorithm, sentinel.encryption_context
    )
    mock_kms.encrypt_data_key.assert_has_calls(
        [call(key, sentinel.plaintext_data_key, sentinel.encryption_context) for key in provider._keys],
        True
    )
    assert not mock_kms.reEncrypt_data_key.called
    assert len(result.encrypted_data_keys) == 3
    assert patch_EncryptedDataKey.return_value in result.encrypted_data_keys
    assert sentinel.key1 in result.encrypted_data_keys
    assert sentinel.key2 in result.encrypted_data_keys
    assert result.plaintext_data_key is patch_base64_b64decode.return_value


def test_encrypt_data_key_multi_mix_region_keys(
    patch_EncryptedDataKey,
    patch_to_bytes,
    patch_base64_b64decode
):
    mock_encryption_material = MagicMock(encryption_context=sentinel.encryption_context)
    mock_kms = MagicMock(
        __class__=AliyunKms,
        generate_data_key=MagicMock(
            return_value=(sentinel.plaintext_data_key, sentinel.encrypted_data_key)
        ),
        reEncrypt_data_key=MagicMock(return_value=sentinel.key1),
        encrypt_data_key=MagicMock(return_value=sentinel.key2)
    )
    keys = {HANGZHOU_KEY1, SHANGHAI_KEY1}
    provider = build_provider(key_id=HANGZHOU_KEY, kms=mock_kms, keys=keys)

    result = provider.encrypt_data_key(mock_encryption_material)

    mock_kms.generate_data_key.assert_called_once_with(
        provider.key, provider.algorithm, sentinel.encryption_context
    )
    for key in provider._keys:
        if provider.key.isCommonRegion(key):
            mock_kms.reEncrypt_data_key.assert_called_once_with(
                key, patch_EncryptedDataKey.return_value, sentinel.encryption_context
            )
        else:
            mock_kms.encrypt_data_key.assert_called_once_with(
                key, sentinel.plaintext_data_key, sentinel.encryption_context
            )
    assert len(result.encrypted_data_keys) == 3
    assert patch_EncryptedDataKey.return_value in result.encrypted_data_keys
    assert sentinel.key1 in result.encrypted_data_keys
    assert sentinel.key2 in result.encrypted_data_keys
    assert result.plaintext_data_key is patch_base64_b64decode.return_value


def test_decrypt_data_key_valid(patch_base64_b64decode):
    mock_decryption_material = MagicMock(encryption_context=sentinel.encryption_context)
    mock_key1 = MagicMock(key_id=HANGZHOU_KEY)
    mock_key2 = MagicMock(key_id=HANGZHOU_KEY1)
    mock_encrypted_data_keys = {mock_key1, mock_key2}
    mock_kms = MagicMock(
        __class__=AliyunKms,
        generate_data_key=MagicMock(
            return_value=(sentinel.plaintext_data_key, sentinel.encrypted_data_key)
        ),
        decrypt_data_key=MagicMock(),
    )
    provider = build_provider(key_id=HANGZHOU_KEY, kms=mock_kms)

    result = provider.decrypt_data_key(mock_decryption_material, mock_encrypted_data_keys)

    mock_kms.decrypt_data_key.assert_called_once_with(
        mock_key1, sentinel.encryption_context
    )
    assert result.plaintext_data_key is patch_base64_b64decode.return_value


def test_decrypt_data_key_invalid(patch_base64_b64decode):
    mock_decryption_material = MagicMock(encryption_context=sentinel.encryption_context)
    mock_key1 = MagicMock(key_id=HANGZHOU_KEY1)
    mock_key2 = MagicMock(key_id=HANGZHOU_KEY2)
    mock_encrypted_data_keys = {mock_key1, mock_key2}
    mock_kms = MagicMock(
        __class__=AliyunKms,
        generate_data_key=MagicMock(
            return_value=(sentinel.plaintext_data_key, sentinel.encrypted_data_key)
        ),
        decrypt_data_key=MagicMock(),
    )
    provider = build_provider(key_id=HANGZHOU_KEY, kms=mock_kms)

    result = provider.decrypt_data_key(mock_decryption_material, mock_encrypted_data_keys)

    assert not mock_kms.decrypt_data_key.called
    assert not patch_base64_b64decode.called
    assert result is None
