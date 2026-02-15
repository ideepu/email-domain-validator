from unittest.mock import MagicMock, patch

from email_validator import EmailNotValidError

from src.mx import extract_mx_record_info

_MOCK_TARGET = 'src.mx.validate_email'


def test_happy_path_single_mx() -> None:
    validated = MagicMock()
    validated.mx = [(10, 'mail.example.com')]
    with patch(_MOCK_TARGET, return_value=validated) as mock:
        result = extract_mx_record_info('user@example.com', timeout=3)
    assert result.valid is True
    assert result.records == ['mail.example.com']
    mock.assert_called_once_with('user@example.com', check_deliverability=True, timeout=3)


def test_multiple_mx_records() -> None:
    validated = MagicMock()
    validated.mx = [(10, 'mx1.example.com'), (20, 'mx2.example.com')]
    with patch(_MOCK_TARGET, return_value=validated):
        result = extract_mx_record_info('user@example.com')
    assert result.valid is True
    assert result.records == ['mx1.example.com', 'mx2.example.com']


def test_no_mx_attribute_returns_invalid() -> None:
    validated = MagicMock(spec=[])  # spec=[] means no attributes at all
    with patch(_MOCK_TARGET, return_value=validated):
        result = extract_mx_record_info('user@example.com')
    assert result.valid is False
    assert result.records is None


def test_email_not_valid_error_returns_invalid() -> None:
    with patch(_MOCK_TARGET, side_effect=EmailNotValidError('bad')):
        result = extract_mx_record_info('bad-email')
    assert result.valid is False
    assert result.records is None


def test_whitespace_stripped() -> None:
    validated = MagicMock()
    validated.mx = [(10, 'mail.example.com')]
    with patch(_MOCK_TARGET, return_value=validated) as mock:
        extract_mx_record_info('  user@example.com  ')
    mock.assert_called_once_with('user@example.com', check_deliverability=True, timeout=5)


def test_empty_mx_list() -> None:
    validated = MagicMock()
    validated.mx = []
    with patch(_MOCK_TARGET, return_value=validated):
        result = extract_mx_record_info('user@example.com')
    assert result.valid is True
    assert result.records == []
