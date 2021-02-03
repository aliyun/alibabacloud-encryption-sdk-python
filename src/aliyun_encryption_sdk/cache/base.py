import six
import abc


@six.add_metaclass(abc.ABCMeta)
class DataKeyCache(object):

    @abc.abstractmethod
    def get_encrypt_entry(self, cache_key, plaintext_length):
        pass

    @abc.abstractmethod
    def put_encrypt_entry(self, cache_key, plaintext_length, encryption_material, survival_time):
        pass

    @abc.abstractmethod
    def get_decrypt_entry(self, cache_key):
        pass

    @abc.abstractmethod
    def put_decrypt_entry(self, cache_key, decryption_material, survival_time):
        pass
