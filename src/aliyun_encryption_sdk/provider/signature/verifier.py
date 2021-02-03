import abc
import base64
import six

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import load_pem_x509_certificate

from aliyun_encryption_sdk.kms.kms import AliyunKms
from aliyun_encryption_sdk.model import SignatureAlgorithm
from aliyun_encryption_sdk.provider import str_to_cmk
from aliyun_encryption_sdk.provider.signature import get_digest


@six.add_metaclass(abc.ABCMeta)
class Verifier(object):
    def __init__(self, signature_algorithm, public_key=None):
        if not isinstance(signature_algorithm, SignatureAlgorithm):
            raise TypeError("'signature_algorithm' must be SignatureAlgorithm type")
        self.signature_algorithm = signature_algorithm
        self.public_key = public_key

    def verify_data(self, verify_material):
        if self.signature_algorithm is SignatureAlgorithm.RSA_PSS_SHA_256:
            verifier = self.public_key.verifier(
                verify_material.signed_value,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif self.signature_algorithm is SignatureAlgorithm.RSA_PKCS1_SHA_256:
            verifier = self.public_key.verifier(
                verify_material.signed_value,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        else:
            raise Exception("algorithm not support")
        verifier.update(verify_material.message)
        try:
            verifier.verify()
        except InvalidSignature:
            verify_value = False
        else:
            verify_value = True
        verify_material.verify_value = verify_value
        return verify_material


class KmsVerifier(Verifier):
    def __init__(self, key_arn, key_version_id, kms, signature_algorithm):
        if not isinstance(key_arn, six.string_types):
            raise TypeError("'key_arn' must be str type")
        if not isinstance(key_version_id, six.string_types):
            raise TypeError("'key_version_id' must be str type")
        if kms is not None and not isinstance(kms, AliyunKms):
            raise TypeError("'kms' must be AliyunKms type")
        self.key = str_to_cmk(key_arn)
        self.key_version_id = key_version_id
        self.kms = kms
        super(KmsVerifier, self).__init__(signature_algorithm)

    def verify_data(self, verify_material):
        digest = verify_material.digest
        if digest is None or len(digest) == 0:
            digest = get_digest(verify_material.message, self.signature_algorithm)
        verify_value = self.kms.asymmetric_verify(
            self.key, self.key_version_id, self.signature_algorithm,
            base64.b64encode(digest), base64.b64encode(verify_material.signed_value)
        )
        verify_material.verify_value = verify_value
        return verify_material


class PublicKeyVerifier(Verifier):
    def __init__(self, signature_algorithm, pem_public_key):
        if not isinstance(signature_algorithm, SignatureAlgorithm):
            raise TypeError("'signature_algorithm' must be SignatureAlgorithm type")
        if not isinstance(pem_public_key, (six.string_types, bytes)):
            raise TypeError("'pem_public_key' must be str or bytes type")
        public_key = load_pem_public_key(pem_public_key)
        super(PublicKeyVerifier, self).__init__(signature_algorithm, public_key)


class CertificateVerifier(Verifier):
    def __init__(self, pem_certificate):
        if not isinstance(pem_certificate, (six.string_types, bytes)):
            raise TypeError("'pem_certificate' must be str or bytes type")
        cert = load_pem_x509_certificate(pem_certificate)
        if cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256:
            signature_algorithm = SignatureAlgorithm.RSA_PKCS1_SHA_256
        elif cert.signature_algorithm_oid._name == "SM3WITHSM2":
            signature_algorithm = None
        else:
            raise Exception("signature algorithm not support")
        public_key = cert.public_key()
        super(CertificateVerifier, self).__init__(signature_algorithm, public_key)