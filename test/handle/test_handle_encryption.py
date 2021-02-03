import pytest
from mock import MagicMock, sentinel

import aliyun_encryption_sdk
from aliyun_encryption_sdk.handle.encryption import DefaultEncryptHandler, Encryptor, Decryptor


@pytest.yield_fixture
def patch_default_backend(mocker):
    mocker.patch.object(aliyun_encryption_sdk.handle.encryption, "default_backend")
    yield aliyun_encryption_sdk.handle.encryption.default_backend


@pytest.yield_fixture
def patch_cipher(mocker):
    mocker.patch.object(aliyun_encryption_sdk.handle.encryption, "Cipher")
    yield aliyun_encryption_sdk.handle.encryption.Cipher


@pytest.mark.parametrize("with_aad", (True, False))
def test_encryptor_init(with_aad, patch_default_backend, patch_cipher):
    algorithm = MagicMock(with_aad=with_aad)
    encryptor = Encryptor(
        algorithm=algorithm,
        key_spec=sentinel.key_spec,
        iv=sentinel.iv,
        content_aad=sentinel.content_aad
    )

    assert encryptor._key_spec is sentinel.key_spec
    algorithm.cipher_algorithm.assert_called_once_with(sentinel.key_spec)
    algorithm.init_mode_iv.assert_called_once_with(sentinel.iv, None)
    patch_default_backend.assert_called_once_with()
    patch_cipher.assert_called_once_with(
        algorithm.cipher_algorithm.return_value,
        algorithm.init_mode_iv.return_value,
        patch_default_backend.return_value
    )
    patch_cipher.return_value.encryptor.assert_called_once_with()
    assert encryptor._cipher is patch_cipher.return_value.encryptor.return_value
    if with_aad:
        encryptor._cipher.authenticate_additional_data.assert_called_once_with(sentinel.content_aad)


@pytest.mark.parametrize("with_aad", (True, False))
def test_encryptor_update(with_aad, patch_default_backend, patch_cipher):
    encryptor = Encryptor(
        algorithm=MagicMock(with_aad=with_aad),
        key_spec=sentinel.key_spec,
        iv=sentinel.iv,
        content_aad=sentinel.content_aad
    )

    result = encryptor.update(sentinel.plain_text)

    encryptor._cipher.update.assert_called_once_with(sentinel.plain_text)
    assert result is encryptor._cipher.update.return_value


@pytest.mark.parametrize("with_aad", (True, False))
def test_encryptor_finalize(with_aad, patch_default_backend, patch_cipher):
    encryptor = Encryptor(
        algorithm=MagicMock(with_aad=with_aad),
        key_spec=sentinel.key_spec,
        iv=sentinel.iv,
        content_aad=sentinel.content_aad
    )

    result = encryptor.finalize()

    encryptor._cipher.finalize.assert_called_once_with()
    assert result is encryptor._cipher.finalize.return_value


@pytest.mark.parametrize("with_aad", (True, False))
def test_encryptor_tag(with_aad, patch_default_backend, patch_cipher):
    encryptor = Encryptor(
        algorithm=MagicMock(with_aad=with_aad),
        key_spec=sentinel.key_spec,
        iv=sentinel.iv,
        content_aad=sentinel.content_aad
    )

    result = encryptor.tag

    assert result is encryptor._cipher.tag


@pytest.mark.parametrize("with_aad", (True, False))
def test_decryptor_init(with_aad, patch_default_backend, patch_cipher):
    algorithm = MagicMock(with_aad=with_aad)
    decryptor = Decryptor(
        algorithm=algorithm,
        key_spec=sentinel.key_spec,
        iv=sentinel.iv,
        content_aad=sentinel.content_aad,
        tag=sentinel.tag
    )

    assert decryptor._key_spec is sentinel.key_spec
    algorithm.cipher_algorithm.assert_called_once_with(sentinel.key_spec)
    algorithm.init_mode_iv.assert_called_once_with(sentinel.iv, sentinel.tag)
    patch_default_backend.assert_called_once_with()
    patch_cipher.assert_called_once_with(
        algorithm.cipher_algorithm.return_value,
        algorithm.init_mode_iv.return_value,
        patch_default_backend.return_value
    )
    patch_cipher.return_value.decryptor.assert_called_once_with()
    assert decryptor._cipher is patch_cipher.return_value.decryptor.return_value
    if with_aad:
        decryptor._cipher.authenticate_additional_data.assert_called_once_with(sentinel.content_aad)


@pytest.mark.parametrize("with_aad", (True, False))
def test_decryptor_update(with_aad, patch_default_backend, patch_cipher):
    decryptor = Decryptor(
        algorithm=MagicMock(with_aad=with_aad),
        key_spec=sentinel.key_spec,
        iv=sentinel.iv,
        content_aad=sentinel.content_aad,
        tag=sentinel.tag
    )

    result = decryptor.update(sentinel.cipher_text)

    decryptor._cipher.update.assert_called_once_with(sentinel.cipher_text)
    assert result is decryptor._cipher.update.return_value


@pytest.mark.parametrize("with_aad", (True, False))
def test_decryptor_finalize(with_aad, patch_default_backend, patch_cipher):
    decryptor = Decryptor(
        algorithm=MagicMock(with_aad=with_aad),
        key_spec=sentinel.key_spec,
        iv=sentinel.iv,
        content_aad=sentinel.content_aad,
        tag=sentinel.tag
    )

    result = decryptor.finalize()

    decryptor._cipher.finalize.assert_called_once_with()
    assert result is decryptor._cipher.finalize.return_value


@pytest.yield_fixture
def patch_cipher_header(mocker):
    mocker.patch.object(aliyun_encryption_sdk.handle.encryption, "CipherHeader")
    yield aliyun_encryption_sdk.handle.encryption.CipherHeader


@pytest.yield_fixture
def patch_cipher_body(mocker):
    mocker.patch.object(aliyun_encryption_sdk.handle.encryption, "CipherBody")
    yield aliyun_encryption_sdk.handle.encryption.CipherBody


@pytest.yield_fixture
def patch_cipher_material(mocker):
    mocker.patch.object(aliyun_encryption_sdk.handle.encryption, "CipherMaterial")
    yield aliyun_encryption_sdk.handle.encryption.CipherMaterial


@pytest.yield_fixture
def patch_encryptor(mocker):
    mocker.patch.object(aliyun_encryption_sdk.handle.encryption, "Encryptor")
    yield aliyun_encryption_sdk.handle.encryption.Encryptor


def test_encrypt(
        mocker,
        patch_cipher_header,
        patch_cipher_body,
        patch_cipher_material,
        patch_encryptor
):
    patch_encryptor.return_value.update.return_value = b"update "
    patch_encryptor.return_value.finalize.return_value = b"finalize"
    patch_encryptor.return_value.tag = b"tag"
    mocker.patch.object(aliyun_encryption_sdk.handle.encryption, "os")
    aliyun_encryption_sdk.handle.encryption.os.urandom.return_value = b"123456789123"

    algorithm = MagicMock(iv_len=sentinel.iv_len)
    mock_encryption_material = MagicMock(
        version=sentinel.version,
        encryption_context=sentinel.encryption_context,
        algorithm=algorithm,
        plaintext_data_key=sentinel.plaintext_data_key,
        encrypted_data_keys=sentinel.encrypted_data_keys
    )
    encrypt_handler = DefaultEncryptHandler()

    result = encrypt_handler.encrypt(sentinel.plain_text, mock_encryption_material)

    patch_cipher_header.assert_called_once_with(
        algorithm=algorithm,
        encryption_context=sentinel.encryption_context,
        encrypted_data_keys=sentinel.encrypted_data_keys,
        version=sentinel.version
    )
    aliyun_encryption_sdk.handle.encryption.os.urandom.assert_called_once_with(sentinel.iv_len)
    patch_encryptor.assert_called_once_with(
        algorithm, sentinel.plaintext_data_key,
        aliyun_encryption_sdk.handle.encryption.os.urandom.return_value,
        patch_cipher_header.return_value.encryption_context_bytes
    )
    patch_cipher_header.return_value.calculate_header_auth_tag.assert_called_once_with(sentinel.plaintext_data_key)
    algorithm.padding_data.assert_called_once_with(sentinel.plain_text)
    patch_encryptor.return_value.update.assert_called_once_with(algorithm.padding_data.return_value)
    patch_encryptor.return_value.finalize.assert_called_once_with()
    patch_cipher_body.assert_called_once_with(
        aliyun_encryption_sdk.handle.encryption.os.urandom.return_value,
        b"update finalize", b"tag"
    )
    patch_cipher_material.assert_called_once_with(
        patch_cipher_header.return_value,
        patch_cipher_body.return_value
    )
    assert result is patch_cipher_material.return_value


@pytest.yield_fixture
def patch_decryptor(mocker):
    mocker.patch.object(aliyun_encryption_sdk.handle.encryption, "Decryptor")
    yield aliyun_encryption_sdk.handle.encryption.Decryptor


def test_decrypt_auth_success(patch_decryptor):
    patch_decryptor.return_value.update.return_value = b"update "
    patch_decryptor.return_value.finalize.return_value = b"finalize"
    mock_cipher_header = MagicMock(
        encryption_context_bytes=sentinel.encryption_context_bytes,
        verify_header_auth_tag=MagicMock(return_value=True)
    )
    mock_cipher_body = MagicMock(
        iv=sentinel.iv,
        cipher_text=sentinel.cipher_text,
        auth_tag=sentinel.auth_tag
    )
    mock_cipher_material = MagicMock(cipher_header=mock_cipher_header, cipher_body=mock_cipher_body)
    mock_decryption_material = MagicMock(
        algorithm=MagicMock(),
        plaintext_data_key=sentinel.plaintext_data_key
    )
    encrypt_handler = DefaultEncryptHandler()

    result = encrypt_handler.decrypt(mock_cipher_material, mock_decryption_material)

    mock_cipher_header.verify_header_auth_tag.assert_called_once_with(sentinel.plaintext_data_key)
    patch_decryptor.assert_called_once_with(
        mock_decryption_material.algorithm, sentinel.plaintext_data_key,
        sentinel.iv, sentinel.encryption_context_bytes, sentinel.auth_tag
    )
    patch_decryptor.return_value.update.assert_called_once_with(sentinel.cipher_text)
    patch_decryptor.return_value.finalize.assert_called_once_with()
    mock_decryption_material.algorithm.un_padding_data(b"update finalize")
    assert result is mock_decryption_material.algorithm.un_padding_data.return_value