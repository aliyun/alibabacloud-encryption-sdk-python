import struct

import attr
import six


class CmkId(object):
    def __init__(self, key_arn):
        if not isinstance(key_arn, six.string_types):
            raise TypeError("'key_id' must be str type")
        key_arn = key_arn.strip()
        if key_arn.isspace():
            raise ValueError("keyId cannot be empty")
        self.key_arn = key_arn

        if key_arn.startswith("acs"):
            self.__parsing_key_id()

    def __eq__(self, other):
        if isinstance(other, CmkId):
            return self.key_arn == other.key_arn
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.key_arn)

    def __parsing_key_id(self):
        str_arr = self.key_arn.split(":")
        if len(str_arr) != 5:
            raise Exception("ARN parsing error, ARN format would be 'acs:kms:<region>:<uid>:key/<cmkid>'")

        if str_arr[0] != "acs":
            raise Exception("ARN must start with 'acs:'")
        if str_arr[1] != "kms":
            raise Exception("ARN must specify service")
        if len(str_arr[2]) == 0:
            raise Exception("ARN must specify region")
        if len(str_arr[3]) == 0:
            raise Exception("ARN must specify uid")
        if len(str_arr[4]) == 0:
            raise Exception("ARN must specify resource")
        if not str_arr[4].startswith("key/"):
            raise Exception("ARN resource type must be 'key'")

        self.region = str_arr[2]
        self.raw_key_id = str_arr[4][str_arr[4].find("/") + 1:]
        self.is_arn = True

    def isCommonRegion(self, key):
        if hasattr(self, "region") and hasattr(key, "region"):
            return self.region == key.region
        return False


def str_to_cmk(key_arn):
    return CmkId(key_arn)


@attr.s(hash=True)
class EncryptedDataKey(object):
    key_arn = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    encrypted_data_key = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))

    def serialize(self):
        return struct.pack(
            ">I{key_id_len}sI{encrypted_data_key_len}s".format(
                key_id_len=len(self.key_arn), encrypted_data_key_len=len(self.encrypted_data_key)
            ),
            len(self.key_arn), self.key_arn,
            len(self.encrypted_data_key), self.encrypted_data_key
        )
