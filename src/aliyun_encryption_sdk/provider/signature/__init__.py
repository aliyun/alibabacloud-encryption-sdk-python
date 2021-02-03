from cryptography.hazmat.primitives import hashes


def get_digest(content, algorithm):
    if content is None or len(content) == 0:
        raise Exception("'content' must not be empty")
    if "SM2DSA" == algorithm.algorithm_name:
        pass
    else:
        digest = hashes.Hash(algorithm.digest_algorithm())
        digest.update(content)
        return digest.finalize()