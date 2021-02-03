import pytest
from mock import MagicMock, sentinel

import aliyun_encryption_sdk
from aliyun_encryption_sdk.cache.base import DataKeyCache
from aliyun_encryption_sdk.ckm.cache import CachingCryptoKeyManager, MAX_TIME, MAX_BYTE, MAX_MESSAGE
from aliyun_encryption_sdk.constants import SDK_VERSION
from test.ckm.test_ckm_default import fake_provider


def build_ckm(**kwargs):
    parameter = dict(
        cache=MagicMock(__class__=DataKeyCache)
    )
    parameter.update(kwargs)
    return CachingCryptoKeyManager(**parameter)


@pytest.mark.parametrize(
    "invalid_kwargs",
    (
        dict(cache=None),
        dict(max_survival_time=None),
        dict(max_encryption_bytes=None),
        dict(max_encryption_messages=None)
    ),
)
def test_invalid_parameter_type(invalid_kwargs):
    with pytest.raises(TypeError):
        build_ckm(**invalid_kwargs)


@pytest.mark.parametrize(
    "invalid_kwargs, error_message",
    (
        (dict(max_survival_time=-1), r"'max_survival_time' cannot be less than 0"),
        (dict(max_encryption_bytes=-1), r"'max_encryption_bytes' cannot be less than 0"),
        (dict(max_encryption_messages=-1), r"'max_encryption_messages' cannot be less than 0")
    )
)
def test_invalid_parameter_values(invalid_kwargs, error_message):
    with pytest.raises(ValueError) as e:
        build_ckm(**invalid_kwargs)

    e.match(error_message)


def test_valid_parameter():
    mock_cache = MagicMock(__class__=DataKeyCache)
    valid_kwargs = dict(
        cache=mock_cache,
        max_survival_time=10,
        max_encryption_bytes=1000,
        max_encryption_messages=20
    )

    cckm = build_ckm(**valid_kwargs)

    assert cckm.cache is mock_cache
    assert cckm.max_survival_time == 10
    assert cckm.max_encryption_bytes == 1000
    assert cckm.max_encryption_messages == 20


def test_default():
    moch_cache = MagicMock(__class__=DataKeyCache)
    cckm = CachingCryptoKeyManager(moch_cache)

    assert cckm.cache is moch_cache
    assert cckm.max_survival_time == MAX_TIME
    assert cckm.max_encryption_bytes == MAX_BYTE
    assert cckm.max_encryption_messages == MAX_MESSAGE


@pytest.mark.parametrize(
    "encrypted_bytes, encrypted_messages, result",
    (
        (-1, -1, False), (1, 1, False),
        (1, -1, False), (-1, 1, False),
        (1, 6, True), (6, 1, True),
        (1, 5, False), (5, 1, False),
        (5, 5, False), (5, 5, False),
        (6, 6, True), (6, 6, True)
    )
)
def test_cache_entry_is_exceed_max_limit(encrypted_bytes, encrypted_messages, result):
    mock_entry = MagicMock(encrypted_bytes=encrypted_bytes, encrypted_messages=encrypted_messages)
    cckm = build_ckm(max_encryption_bytes=5, max_encryption_messages=5)

    if result:
        assert cckm._is_exceed_max_limit(mock_entry)
    else:
        assert not cckm._is_exceed_max_limit(mock_entry)


@pytest.yield_fixture
def patch_encryption_material(mocker):
    mocker.patch.object(aliyun_encryption_sdk.ckm.cache, "EncryptionMaterial")
    yield aliyun_encryption_sdk.ckm.cache.EncryptionMaterial


@pytest.yield_fixture
def patch_encrypt_cache_key(mocker):
    mocker.patch.object(CachingCryptoKeyManager, "_get_encrypt_cache_key")
    yield CachingCryptoKeyManager._get_encrypt_cache_key


@pytest.yield_fixture
def patch_is_exceed_max_limit(mocker):
    mocker.patch.object(CachingCryptoKeyManager, "_is_exceed_max_limit")
    CachingCryptoKeyManager._is_exceed_max_limit.return_value = False
    yield CachingCryptoKeyManager._is_exceed_max_limit


@pytest.mark.parametrize("plaintext_size", (-1, MAX_BYTE+1))
def test_get_encrypt_dataKey_material_invalid_plaintext_size(
    plaintext_size,
    patch_encryption_material,
    patch_encrypt_cache_key
):
    mock_provider = fake_provider()
    cckm = build_ckm()

    material = cckm.get_encrypt_dataKey_material(mock_provider, sentinel.encryption_context, plaintext_size)

    patch_encryption_material.assert_called_once_with(
        version=SDK_VERSION,
        encryption_context=sentinel.encryption_context,
        algorithm=sentinel.algorithm
    )
    assert not patch_encrypt_cache_key.called
    assert not cckm.cache.get_encrypt_entry.called
    assert material is mock_provider.encrypt_data_key.return_value


def test_get_encrypt_dataKey_material_miss_cache(
    patch_encryption_material,
    patch_encrypt_cache_key,
    patch_is_exceed_max_limit
):
    mock_provider = fake_provider()
    plaintext_size = 10
    cckm = build_ckm()
    cckm.cache.get_encrypt_entry.return_value = None

    material = cckm.get_encrypt_dataKey_material(mock_provider, sentinel.encryption_context, plaintext_size)

    patch_encryption_material.assert_called_once_with(
        version=SDK_VERSION,
        encryption_context=sentinel.encryption_context,
        algorithm=sentinel.algorithm
    )
    patch_encrypt_cache_key.assert_called_once_with(
        sentinel.algorithm, sentinel.encryption_context
    )
    cckm.cache.get_encrypt_entry.assert_called_once_with(patch_encrypt_cache_key.return_value, plaintext_size)
    assert not patch_is_exceed_max_limit.called
    assert not cckm.cache.remove.called
    mock_provider.encrypt_data_key.assert_called_once_with(patch_encryption_material.return_value)
    cckm.cache.put_encrypt_entry.assert_called_once_with(
        patch_encrypt_cache_key.return_value, plaintext_size,
        material, MAX_TIME
    )
    assert material is mock_provider.encrypt_data_key.return_value


def test_get_encrypt_dataKey_material_hit_good_cache(
    patch_encryption_material,
    patch_encrypt_cache_key,
    patch_is_exceed_max_limit
):
    patch_is_exceed_max_limit.return_value = False
    mock_provider = fake_provider()
    plaintext_size = 10
    cckm = build_ckm()

    material = cckm.get_encrypt_dataKey_material(mock_provider, sentinel.encryption_context, plaintext_size)

    patch_encryption_material.assert_called_once_with(
        version=SDK_VERSION,
        encryption_context=sentinel.encryption_context,
        algorithm=sentinel.algorithm
    )
    patch_encrypt_cache_key.assert_called_once_with(
        sentinel.algorithm, sentinel.encryption_context
    )
    cckm.cache.get_encrypt_entry.assert_called_once_with(patch_encrypt_cache_key.return_value, plaintext_size)
    patch_is_exceed_max_limit.assert_called_once_with(cckm.cache.get_encrypt_entry.return_value)
    assert not cckm.cache.remove.called
    assert not mock_provider.encrypt_data_key.called
    assert not cckm.cache.put_encrypt_entry.called
    assert material is cckm.cache.get_encrypt_entry.return_value.material


def test_get_encrypt_dataKey_material_hit_has_exceed_max_limit(
    patch_encryption_material,
    patch_encrypt_cache_key,
    patch_is_exceed_max_limit
):
    patch_is_exceed_max_limit.return_value = True
    mock_provider = fake_provider()
    plaintext_size = 10
    cckm = build_ckm()

    material = cckm.get_encrypt_dataKey_material(mock_provider, sentinel.encryption_context, plaintext_size)

    patch_encryption_material.assert_called_once_with(
        version=SDK_VERSION,
        encryption_context=sentinel.encryption_context,
        algorithm=sentinel.algorithm
    )
    patch_encrypt_cache_key.assert_called_once_with(
        sentinel.algorithm, sentinel.encryption_context
    )
    cckm.cache.get_encrypt_entry.assert_called_once_with(patch_encrypt_cache_key.return_value, plaintext_size)
    patch_is_exceed_max_limit.assert_called_once_with(cckm.cache.get_encrypt_entry.return_value)
    cckm.cache.remove.assert_called_once_with(cckm.cache.get_encrypt_entry.return_value)
    mock_provider.encrypt_data_key.assert_called_once_with(patch_encryption_material.return_value)
    cckm.cache.put_encrypt_entry.assert_called_once_with(
        patch_encrypt_cache_key.return_value, plaintext_size,
        material, MAX_TIME
    )
    assert material is mock_provider.encrypt_data_key.return_value


@pytest.yield_fixture
def patch_decryption_material(mocker):
    mocker.patch.object(aliyun_encryption_sdk.ckm.cache, "DecryptionMaterial")
    yield aliyun_encryption_sdk.ckm.cache.DecryptionMaterial


@pytest.yield_fixture
def patch_decrypt_cache_key(mocker):
    mocker.patch.object(CachingCryptoKeyManager, "_get_decrypt_cache_key")
    yield CachingCryptoKeyManager._get_decrypt_cache_key


def test_get_decrypt_dataKey_material_miss_cache(
    patch_decryption_material,
    patch_decrypt_cache_key
):
    mock_provider = fake_provider()
    cckm = build_ckm()
    cckm.cache.get_decrypt_entry.return_value = None

    material = cckm.get_decrypt_dataKey_material(
        mock_provider, sentinel.encryption_context,
        sentinel.encrypted_data_keys
    )

    patch_decryption_material.assert_called_once_with(
        encryption_context=sentinel.encryption_context,
        algorithm=sentinel.algorithm
    )
    patch_decrypt_cache_key.assert_called_once_with(
        sentinel.algorithm, sentinel.encryption_context, sentinel.encrypted_data_keys
    )
    cckm.cache.get_decrypt_entry.assert_called_once_with(patch_decrypt_cache_key.return_value)
    mock_provider.decrypt_data_key.assert_called_once_with(patch_decryption_material.return_value)
    cckm.cache.put_decrypt_entry.assert_called_once_with(
        patch_decrypt_cache_key.return_value,
        material, MAX_TIME
    )
    assert material is mock_provider.decrypt_data_key.return_value


def test_get_decrypt_dataKey_material_hit_good_cache(
    patch_decryption_material,
    patch_decrypt_cache_key
):
    mock_provider = fake_provider()
    cckm = build_ckm()

    material = cckm.get_decrypt_dataKey_material(
        mock_provider, sentinel.encryption_context,
        sentinel.encrypted_data_keys
    )
    patch_decryption_material.assert_called_once_with(
        encryption_context=sentinel.encryption_context,
        algorithm=sentinel.algorithm
    )
    patch_decrypt_cache_key.assert_called_once_with(
        sentinel.algorithm, sentinel.encryption_context, sentinel.encrypted_data_keys
    )
    cckm.cache.get_decrypt_entry.assert_called_once_with(patch_decrypt_cache_key.return_value)
    assert not mock_provider.decrypt_data_key.called
    assert not cckm.cache.put_decrypt_entry.called
    assert material is cckm.cache.get_decrypt_entry.return_value.material
