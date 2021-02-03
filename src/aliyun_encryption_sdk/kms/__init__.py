import abc
import attr
import six
import math


MAX_RETRIES = 5


@six.add_metaclass(abc.ABCMeta)
class BackoffStrategy(object):
    @abc.abstractmethod
    def wait_time_exponential(self, retry_times):
        pass


@attr.s(hash=False)
class FullJitterBackoffStrategy(BackoffStrategy):
    retry_initial_interval_mills = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    capacity = attr.ib(validator=attr.validators.instance_of(six.integer_types))

    def wait_time_exponential(self, retry_times):
        return min(self.__capacity, (math.pow(2, retry_times) * self.__retry_initial_interval_mills))


@attr.s
class AliyunConfig(object):
    access_key_id = attr.ib(validator=attr.validators.instance_of(six.string_types))
    access_key_secret = attr.ib(validator=attr.validators.instance_of(six.string_types))
    region = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))
    max_retries = attr.ib(default=MAX_RETRIES, validator=attr.validators.instance_of(six.integer_types))
    backoff_strategy = attr.ib(
        default=FullJitterBackoffStrategy(retry_initial_interval_mills=200, capacity=10000),
        validator=attr.validators.instance_of(BackoffStrategy)
    )