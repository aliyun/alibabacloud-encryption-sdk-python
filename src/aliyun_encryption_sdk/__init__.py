import codecs
import six

from aliyun_encryption_sdk.constants import ENCODING

__version__ = constants.__version__


def to_str(data):
    if isinstance(data, bytes):
        return codecs.decode(data, ENCODING)
    return data


def to_bytes(data):
    if isinstance(data, six.string_types) and not isinstance(data, bytes):
        return codecs.encode(data, ENCODING)
    return data
