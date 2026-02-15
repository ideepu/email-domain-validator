from unittest.mock import MagicMock, patch

from dns.resolver import Resolver

from src.dkim import extract_dkim_record_info
from src.exceptions import DomainPolicyError
from src.models import DKIM_MARKER

_MOCK_TARGET = 'src.dkim.get_domain_policy_record'
_VALID_RECORD = 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...'


def test_happy_path_first_selector_matches() -> None:
    with patch(_MOCK_TARGET, return_value=_VALID_RECORD) as mock:
        result = extract_dkim_record_info('example.com', selectors=['sel1'])
    assert result.valid is True
    assert result.record == _VALID_RECORD
    mock.assert_called_once_with('sel1._domainkey.example.com', DKIM_MARKER, resolver=None, timeout=5)


def test_first_miss_second_hit() -> None:
    with patch(_MOCK_TARGET, side_effect=[DomainPolicyError(''), _VALID_RECORD]) as mock:
        result = extract_dkim_record_info('example.com', selectors=['bad', 'good'])
    assert result.valid is True
    assert result.record == _VALID_RECORD
    assert mock.call_count == 2


def test_all_selectors_miss() -> None:
    with patch(_MOCK_TARGET, side_effect=DomainPolicyError('')) as mock:
        result = extract_dkim_record_info('example.com', selectors=['a', 'b', 'c'])
    assert result.valid is False
    assert result.record is None
    assert mock.call_count == 3


def test_custom_selectors_only_those_tried() -> None:
    with patch(_MOCK_TARGET, return_value=_VALID_RECORD) as mock:
        extract_dkim_record_info('example.com', selectors=['custom'])
    mock.assert_called_once_with('custom._domainkey.example.com', DKIM_MARKER, resolver=None, timeout=5)


def test_empty_record_returns_invalid() -> None:
    """get_domain_policy_record returns '' (falsy) -> skip, return valid=False."""
    with patch(_MOCK_TARGET, return_value=''):
        result = extract_dkim_record_info('example.com', selectors=['sel1'])
    assert result.valid is False
    assert result.record is None


def test_timeout_and_resolver_forwarded() -> None:
    sentinel_resolver = MagicMock(spec=Resolver)
    with patch(_MOCK_TARGET, return_value=_VALID_RECORD) as mock:
        extract_dkim_record_info('example.com', resolver=sentinel_resolver, timeout=15, selectors=['s'])
    mock.assert_called_once_with('s._domainkey.example.com', DKIM_MARKER, resolver=sentinel_resolver, timeout=15)


def test_defaults_to_dkim_selectors_list() -> None:
    """When selectors=None, the full DKIM_SELECTORS list is used."""
    with patch(_MOCK_TARGET, return_value=_VALID_RECORD):
        result = extract_dkim_record_info('example.com')
    # First selector hit -> valid
    assert result.valid is True
