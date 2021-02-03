import pytest
from mock import MagicMock, sentinel

import aliyun_encryption_sdk
from aliyun_encryption_sdk.ckm.default import DefaultCryptoKeyManager
from aliyun_encryption_sdk.constants import SDK_VERSION


def fake_provider():
    mock_encryption_material = MagicMock(
        version=SDK_VERSION, encryption_context=sentinel.encryption_context,
        algorithm=sentinel.algorithm, plaintext_data_key=sentinel.data_key,
        encrypted_data_keys=sentinel.enc_data_keys
    )
    mock_decryption_material = MagicMock(
        encryption_context=sentinel.encryption_context,
        algorithm=sentinel.algorithm,
        plaintext_data_key=sentinel.data_key,
    )
    mock_provider = MagicMock(
        algorithm=sentinel.algorithm,
        encrypt_data_key=MagicMock(return_value=mock_encryption_material),
        decrypt_data_key=MagicMock(return_value=mock_decryption_material)
    )
    return mock_provider


@pytest.yield_fixture
def patch_encryption_material(mocker):
    mocker.patch.object(aliyun_encryption_sdk.ckm.default, "EncryptionMaterial")
    yield aliyun_encryption_sdk.ckm.default.EncryptionMaterial


def test_get_encrypt_dataKey_material(patch_encryption_material):
    mock_provider = fake_provider()
    dckm = DefaultCryptoKeyManager()

    material = dckm.get_encrypt_dataKey_material(mock_provider, sentinel.encryption_context, sentinel.plaintext_size)

    patch_encryption_material.assert_called_once_with(
        version=SDK_VERSION,
        encryption_context=sentinel.encryption_context,
        algorithm=sentinel.algorithm
    )
    mock_provider.encrypt_data_key.assert_called_once_with(patch_encryption_material.return_value)
    assert material is mock_provider.encrypt_data_key.return_value


@pytest.yield_fixture
def patch_decryption_material(mocker):
    mocker.patch.object(aliyun_encryption_sdk.ckm.default, "DecryptionMaterial")
    yield aliyun_encryption_sdk.ckm.default.DecryptionMaterial


def test_get_decrypt_dataKey_material(patch_decryption_material):
    mock_provider = fake_provider()
    dckm = DefaultCryptoKeyManager()

    material = dckm.get_decrypt_dataKey_material(mock_provider, sentinel.encryption_context, sentinel.enc_data_keys)

    patch_decryption_material.assert_called_once_with(
        encryption_context=sentinel.encryption_context,
        algorithm=sentinel.algorithm
    )
    mock_provider.decrypt_data_key.assert_called_once_with(patch_decryption_material.return_value, sentinel.enc_data_keys)
    assert material is mock_provider.decrypt_data_key.return_value
