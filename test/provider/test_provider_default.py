from mock import MagicMock, sentinel

from aliyun_encryption_sdk.handle.format import FormatHandler
from aliyun_encryption_sdk.provider.default import DefaultDataKeyProvider

KEY_ID = "acs:kms:RegionId:UserId:key/CmkId"


def build_provider(**kwargs):
    parameter = dict(
        key_id=KEY_ID
    )
    parameter.update(kwargs)
    return DefaultDataKeyProvider(**parameter)


def test_process_cipher_material():
    mock_format_handle = MagicMock(
        __class__=FormatHandler,
        serialize=MagicMock(),
    )
    provider = build_provider(format_handle=mock_format_handle)

    result = provider.process_cipher_material(sentinel.cipher_material)

    mock_format_handle.serialize.assert_called_once_with(sentinel.cipher_material)
    assert result is mock_format_handle.serialize.return_value


def test_get_cipher_material():
    mock_format_handle = MagicMock(
        __class__=FormatHandler,
        deserialize=MagicMock()
    )
    provider = build_provider(format_handle=mock_format_handle)

    result = provider.get_cipher_material(sentinel.cipher_text)

    mock_format_handle.deserialize.assert_called_once_with(sentinel.cipher_text)
    assert result is mock_format_handle.deserialize.return_value
