import attr
import six

from aliyun_encryption_sdk.model import Algorithm, SignatureAlgorithm


@attr.s(hash=False)
class EncryptionMaterial(object):
    version = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    encryption_context = attr.ib(validator=attr.validators.instance_of(dict))
    algorithm = attr.ib(validator=attr.validators.instance_of(Algorithm))
    plaintext_data_key = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))
    encrypted_data_keys = attr.ib(default=set(), validator=attr.validators.optional(attr.validators.instance_of(set)))


@attr.s(hash=False)
class DecryptionMaterial(object):
    encryption_context = attr.ib(validator=attr.validators.instance_of(dict))
    algorithm = attr.ib(validator=attr.validators.instance_of(Algorithm))
    plaintext_data_key = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))


@attr.s(hash=False)
class SignatureMaterial(object):
    signature_algorithm = attr.ib(validator=attr.validators.instance_of(SignatureAlgorithm))
    message = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))
    digest = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))
    signed_value = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))


@attr.s(hash=False)
class VerifyMaterial(object):
    signed_value = attr.ib(validator=attr.validators.instance_of(bytes))
    signature_algorithm = attr.ib(validator=attr.validators.instance_of(SignatureAlgorithm))
    message = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))
    digest = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))
    verify_value = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bool)))
