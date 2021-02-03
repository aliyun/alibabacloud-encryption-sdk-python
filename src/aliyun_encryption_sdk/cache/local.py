from collections import OrderedDict
from threading import RLock

import six

from aliyun_encryption_sdk.cache import MaterialsCacheEntry
from aliyun_encryption_sdk.cache.base import DataKeyCache

DEFAULT_CAPACITY = 10


class LocalDataKeyMaterialCache(DataKeyCache):

    def __init__(self, capacity=DEFAULT_CAPACITY):
        if isinstance(capacity, six.integer_types) and capacity >= 1:
            self._capacity = capacity
        else:
            self._capacity = DEFAULT_CAPACITY
        self._cache = OrderedDict()
        self._cache_lock = RLock()

    def get_encrypt_entry(self, cache_key, plaintext_length):
        with self._cache_lock:
            entry = self._get_entry(cache_key)
            if entry:
                entry.add_encrypted_usage_info(plaintext_length)
            return entry

    def put_encrypt_entry(self, cache_key, plaintext_length, encryption_material, survival_time):
        entry = MaterialsCacheEntry(
            cache_key, encryption_material, survival_time,
            plaintext_length, 1
        )
        self._put_entry(entry)

    def get_decrypt_entry(self, cache_key):
        with self._cache_lock:
            return self._get_entry(cache_key)

    def put_decrypt_entry(self, cache_key, decryption_material, survival_time):
        entry = MaterialsCacheEntry(
            cache_key, decryption_material, survival_time
        )
        self._put_entry(entry)

    def remove(self, value):
        with self._cache_lock:
            try:
                del self._cache[value.cache_key]
            except KeyError:
                pass

    def _get_entry(self, cache_key):
        with self._cache_lock:
            try:
                entry = self._cache[cache_key]
            except KeyError:
                return None
            if entry.is_expired:
                self.remove(entry)
                return None
            self._cache.move_to_end(entry.cache_key)
            return entry

    def _put_entry(self, entry):
        with self._cache_lock:
            self._eliminate()
            if entry.cache_key in self._cache:
                self._cache.move_to_end(entry.cache_key)
            self._cache[entry.cache_key] = entry
            self._check_capacity()

    def _eliminate(self):
        with self._cache_lock:
            for key in list(self._cache):
                entry = self._cache[key]
                if entry.is_expired:
                    self.remove(entry)

    def _check_capacity(self):
        while len(self._cache) > self._capacity:
            self._cache.popitem(last=False)
