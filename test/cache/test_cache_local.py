from collections import OrderedDict

import pytest
from mock import MagicMock, sentinel

import aliyun_encryption_sdk
from aliyun_encryption_sdk.cache import MaterialsCacheEntry
from aliyun_encryption_sdk.cache.local import LocalDataKeyMaterialCache, DEFAULT_CAPACITY


@pytest.mark.parametrize("capacity", (None, "1", -1))
def test_invalid_parameter(capacity):
    local_cache = LocalDataKeyMaterialCache(capacity)
    assert local_cache._capacity == DEFAULT_CAPACITY
    assert local_cache._cache == OrderedDict()


@pytest.mark.parametrize("capacity", (1, 5, 10))
def test_valid_parameter(capacity):
    local_cache = LocalDataKeyMaterialCache(capacity)
    assert local_cache._capacity == capacity
    assert local_cache._cache == OrderedDict()


def test_defaults():
    local_cache = LocalDataKeyMaterialCache()
    assert local_cache._capacity == DEFAULT_CAPACITY
    assert local_cache._cache == OrderedDict()


def test_eliminate():
    local_cache = LocalDataKeyMaterialCache()
    mock_a = MagicMock(cache_key=sentinel.a, is_expired=False)
    mock_b = MagicMock(cache_key=sentinel.b, is_expired=False)
    mock_c = MagicMock(cache_key=sentinel.c, is_expired=True)
    local_cache._cache[sentinel.a] = mock_a
    local_cache._cache[sentinel.b] = mock_b
    local_cache._cache[sentinel.c] = mock_c

    local_cache._eliminate()

    assert len(local_cache._cache) == 2


@pytest.yield_fixture
def patch_eliminate(mocker):
    mocker.patch.object(LocalDataKeyMaterialCache, "_eliminate")
    yield LocalDataKeyMaterialCache._eliminate


def test_check_capacity():
    local_cache = LocalDataKeyMaterialCache(2)
    local_cache._cache[sentinel.a] = MagicMock()
    local_cache._cache[sentinel.b] = MagicMock()
    local_cache._cache[sentinel.c] = MagicMock()

    local_cache._check_capacity()

    assert len(local_cache._cache) == 2
    assert sentinel.a not in local_cache._cache
    assert sentinel.b in local_cache._cache
    assert sentinel.c in local_cache._cache


@pytest.yield_fixture
def patch_check_capacity(mocker):
    mocker.patch.object(LocalDataKeyMaterialCache, "_check_capacity")
    yield LocalDataKeyMaterialCache._check_capacity


def test_remove():
    local_cache = LocalDataKeyMaterialCache()
    mock_entry = MagicMock(cache_key=sentinel.cache_key)
    local_cache._cache[sentinel.cache_key] = mock_entry

    assert sentinel.cache_key in local_cache._cache

    local_cache.remove(mock_entry)

    assert sentinel.cache_key not in local_cache._cache


@pytest.yield_fixture
def patch_remove(mocker):
    mocker.patch.object(LocalDataKeyMaterialCache, "remove")
    yield LocalDataKeyMaterialCache.remove


def test_put_entry_with_miss_cache(patch_eliminate, patch_check_capacity):
    local_cache = LocalDataKeyMaterialCache()
    mock_entry = MagicMock(cache_key=sentinel.cache_key)

    local_cache._put_entry(mock_entry)

    assert local_cache._cache[sentinel.cache_key] is mock_entry
    patch_eliminate.assert_called_once_with()
    patch_check_capacity.assert_called_once_with()


def test_put_entry_with_hit_cache(patch_eliminate, patch_check_capacity):
    local_cache = LocalDataKeyMaterialCache()
    mock_entry = MagicMock(cache_key=sentinel.cache_key)
    local_cache._cache[sentinel.cache_key] = MagicMock()

    local_cache._put_entry(mock_entry)

    assert local_cache._cache[sentinel.cache_key] is mock_entry
    patch_eliminate.assert_called_once_with()
    patch_check_capacity.assert_called_once_with()


@pytest.yield_fixture
def patch_put_entry(mocker):
    mocker.patch.object(LocalDataKeyMaterialCache, "_put_entry")
    yield LocalDataKeyMaterialCache._put_entry


def test_get_entry_with_miss_cache():
    local_cache = LocalDataKeyMaterialCache()

    assert sentinel.cache_key not in local_cache._cache
    assert local_cache._get_entry(sentinel.cache_key) is None


def test_get_entry_with_hit_valid_cache():
    local_cache = LocalDataKeyMaterialCache()
    mock_entry = MagicMock(cache_key=sentinel.cache_key, is_expired=False)
    local_cache._cache[sentinel.cache_key] = mock_entry

    entry = local_cache._get_entry(sentinel.cache_key)

    assert entry is mock_entry


def test_get_entry_with_hit_invalid_cache(patch_remove):
    local_cache = LocalDataKeyMaterialCache()
    mock_entry = MagicMock(cache_key=sentinel.cache_key, is_expired=True)
    local_cache._cache[sentinel.cache_key] = mock_entry

    assert local_cache._get_entry(sentinel.cache_key) is None
    patch_remove.assert_called_once_with(mock_entry)


@pytest.yield_fixture
def patch_get_entry(mocker):
    mocker.patch.object(LocalDataKeyMaterialCache, "_get_entry")
    yield LocalDataKeyMaterialCache._get_entry


def test_get_encrypt_entry(patch_get_entry):
    local_cache = LocalDataKeyMaterialCache()
    plaintext_length = 100

    entry = local_cache.get_encrypt_entry(sentinel.cache_key, plaintext_length)

    patch_get_entry.assert_called_once_with(sentinel.cache_key)
    patch_get_entry.return_value.add_encrypted_usage_info.assert_called_once_with(plaintext_length)
    assert entry is patch_get_entry.return_value


@pytest.yield_fixture
def patch_cache_entry(mocker):
    mocker.patch.object(aliyun_encryption_sdk.cache.local, "MaterialsCacheEntry")
    yield aliyun_encryption_sdk.cache.local.MaterialsCacheEntry


def test_put_encrypt_entry(patch_put_entry, patch_cache_entry):
    local_cache = LocalDataKeyMaterialCache()

    local_cache.put_encrypt_entry(
        sentinel.cache_key, sentinel.plaintext_length,
        sentinel.encryption_material, sentinel.survival_time,
    )

    patch_cache_entry.assert_called_once_with(
        sentinel.cache_key, sentinel.encryption_material,
        sentinel.survival_time, sentinel.plaintext_length, 1
    )
    patch_put_entry.assert_called_once_with(patch_cache_entry.return_value)


def test_get_decrypt_entry(patch_get_entry):
    local_cache = LocalDataKeyMaterialCache()

    entry = local_cache.get_decrypt_entry(sentinel.cache_key)

    patch_get_entry.assert_called_once_with(sentinel.cache_key)
    assert entry is patch_get_entry.return_value


def test_put_decrypt_entry(patch_put_entry, patch_cache_entry):
    local_cache = LocalDataKeyMaterialCache()

    local_cache.put_decrypt_entry(
        sentinel.cache_key, sentinel.decryption_material,
        sentinel.survival_time,
    )

    patch_cache_entry.assert_called_once_with(
        sentinel.cache_key, sentinel.decryption_material,
        sentinel.survival_time
    )
    patch_put_entry.assert_called_once_with(patch_cache_entry.return_value)