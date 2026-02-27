from unittest.mock import MagicMock, patch

from dns.resolver import Resolver

from src.dmarc import extract_dmarc_record_info
from src.exceptions import DomainPolicyError
from src.models import DMARC_MARKER

_MOCK_TARGET = 'src.dmarc.get_domain_policy_record'


def test_happy_path() -> None:
    record = 'v=DMARC1; p=reject; rua=mailto:reports@example.com'
    with patch(_MOCK_TARGET, return_value=record) as mock:
        result = extract_dmarc_record_info('example.com')
    assert result.valid is True
    assert result.record == record
    mock.assert_called_once_with('_dmarc.example.com', DMARC_MARKER, resolver=None, timeout=5)


def test_semicolon_delimiter_no_space() -> None:
    record = 'v=DMARC1;p=reject'
    with patch(_MOCK_TARGET, return_value=record) as mock:
        result = extract_dmarc_record_info('example.com')
    assert result.valid is True
    assert result.record == record
    mock.assert_called_once_with('_dmarc.example.com', DMARC_MARKER, resolver=None, timeout=5)


def test_domain_policy_error_returns_invalid() -> None:
    with patch(_MOCK_TARGET, side_effect=DomainPolicyError('')):
        result = extract_dmarc_record_info('example.com')
    assert result.valid is False
    assert result.record is None


def test_correct_dns_name_and_marker() -> None:
    with patch(_MOCK_TARGET, return_value='v=DMARC1; p=none') as mock:
        result = extract_dmarc_record_info('sub.example.com', timeout=10)
    mock.assert_called_once_with('_dmarc.sub.example.com', DMARC_MARKER, resolver=None, timeout=10)
    assert result.valid is True
    assert result.record == 'v=DMARC1; p=none'


def test_no_record_found() -> None:
    with patch(_MOCK_TARGET, return_value='') as mock:
        result = extract_dmarc_record_info('example.com')
    assert result.valid is False
    assert result.record is None
    mock.assert_called_once_with('_dmarc.example.com', DMARC_MARKER, resolver=None, timeout=5)


def test_resolver_forwarded() -> None:
    sentinel_resolver = MagicMock(spec=Resolver)
    with patch(_MOCK_TARGET, return_value='v=DMARC1; p=none') as mock:
        extract_dmarc_record_info('example.com', resolver=sentinel_resolver, timeout=3)
    mock.assert_called_once_with('_dmarc.example.com', DMARC_MARKER, resolver=sentinel_resolver, timeout=3)
