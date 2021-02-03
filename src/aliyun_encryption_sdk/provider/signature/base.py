import base64
import attr
import six

from aliyun_encryption_sdk.kms.kms import AliyunKms
from aliyun_encryption_sdk.model import SignatureAlgorithm
from aliyun_encryption_sdk.provider import str_to_cmk, CmkId
from aliyun_encryption_sdk.provider.signature import get_digest
from aliyun_encryption_sdk.provider.signature.verifier import Verifier, KmsVerifier


@attr.s(hash=False)
class KmsAsymmetricKeyProvider(object):
    key = attr.ib(validator=attr.validators.instance_of(CmkId), converter=str_to_cmk)
    key_version_id = attr.ib(validator=attr.validators.instance_of(six.string_types))
    signature_algorithm = attr.ib(validator=attr.validators.instance_of(SignatureAlgorithm))
    _kms = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(AliyunKms)))
    _verifier = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(Verifier)))

    def __attrs_post_init__(self):
        if self._verifier is None:
            self._verifier = KmsVerifier(
                key_arn=self.key.key_arn,
                key_version_id=self.key_version_id,
                kms=self._kms,
                signature_algorithm=self.signature_algorithm
            )

    @property
    def kms(self):
        return self._kms

    @kms.setter
    def kms(self, kms):
        if not isinstance(kms, AliyunKms):
            raise TypeError("kms must be of type AliyunKms")
        if self._kms is None:
            self._kms = kms
            if isinstance(self._verifier, KmsVerifier):
                self._verifier.kms = kms

    def sign_data(self, signature_material):
        digest = signature_material.digest
        if digest is None or len(digest) == 0:
            digest = get_digest(signature_material.message, self.signature_algorithm)
        signed_value = self._kms.asymmetric_sign(
            self.key, self.key_version_id, self.signature_algorithm, base64.b64encode(digest)
        )
        signature_material.signed_value = signed_value
        return signature_material

    def verify_data(self, verify_material):
        return self._verifier.verify_data(verify_material)
