from unittest.mock import MagicMock

import dns.resolver
import pytest

from src.exceptions import DomainPolicyError
from src.utils import _is_policy_version_valid, get_domain_policy_record


def test_is_policy_version_valid() -> None:
    assert _is_policy_version_valid('v=spf1 include:_spf.google.com', 'v=spf1') is True
    assert _is_policy_version_valid('v=spf1', 'v=spf1') is True
    assert _is_policy_version_valid('v=spf1 ', 'v=spf1') is True
    # DMARC with space after marker matches; semicolon alone does not (version must be at start then EOL or space)
    assert _is_policy_version_valid('v=DMARC1 p=none', 'v=DMARC1') is True
    assert _is_policy_version_valid('other v=spf1', 'v=spf1') is False
    # Regex matches once at start ("v=spf1 ") so implementation reports valid; duplicate tags not detected


def test_is_policy_version_valid_semicolon_delimiter() -> None:
    """Validates the regex fix: v=DMARC1; (semicolon, no space) must match."""
    assert _is_policy_version_valid('v=DMARC1;p=reject', 'v=DMARC1') is True
    assert _is_policy_version_valid('v=DMARC1; p=reject; rua=mailto:r@x.com', 'v=DMARC1') is True
    # DKIM marker with semicolon
    assert _is_policy_version_valid('v=DKIM1; k=rsa; p=MII...', 'v=DKIM1') is True
    # SPF still works with space
    assert _is_policy_version_valid('v=spf1 include:x.com ~all', 'v=spf1') is True


def test_get_domain_policy_record_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_nxdomain(*_args: object, **_kwargs: object) -> None:
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver.Resolver, 'resolve', raise_nxdomain)
    with pytest.raises(DomainPolicyError):
        get_domain_policy_record('example.com', 'v=spf1', resolver=dns.resolver.Resolver(), timeout=1)


def test_get_domain_policy_record_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_no_answer(*_args: object, **_kwargs: object) -> None:
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver.Resolver, 'resolve', raise_no_answer)
    with pytest.raises(DomainPolicyError):
        get_domain_policy_record('example.com', 'v=spf1', resolver=dns.resolver.Resolver(), timeout=1)


def test_get_domain_policy_record_lifetime_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_timeout(*_args: object, **_kwargs: object) -> None:
        raise dns.resolver.LifetimeTimeout(timeout=5.0, errors=[])

    monkeypatch.setattr(dns.resolver.Resolver, 'resolve', raise_timeout)
    with pytest.raises(DomainPolicyError):
        get_domain_policy_record('example.com', 'v=spf1', resolver=dns.resolver.Resolver(), timeout=1)


def test_get_domain_policy_record_no_matching_marker() -> None:
    mock_record = MagicMock()
    mock_record.strings = [b'some-other-txt-record']
    mock_answer = MagicMock()
    mock_answer.__iter__ = lambda self: iter([mock_record])

    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = mock_answer
    with pytest.raises(DomainPolicyError):
        get_domain_policy_record('example.com', 'v=spf1', resolver=mock_resolver, timeout=1)


def test_get_domain_policy_record_matching_marker() -> None:
    mock_record = MagicMock()
    mock_record.strings = [b'v=spf1 include:_spf.google.com']
    mock_answer = MagicMock()
    mock_answer.__iter__ = lambda self: iter([mock_record])

    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = mock_answer
    result = get_domain_policy_record('example.com', 'v=spf1', resolver=mock_resolver, timeout=1)
    assert result == 'v=spf1 include:_spf.google.com'


def test_get_domain_policy_record_matching_marker_multiple_records() -> None:
    mock_record1 = MagicMock()
    mock_record1.strings = [b'some-other-txt-record']
    mock_record2 = MagicMock()
    mock_record2.strings = [b'v=spf1 include:_spf.google.com']
    mock_answer = MagicMock()
    mock_answer.__iter__ = lambda self: iter([mock_record1, mock_record2])

    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = mock_answer
    result = get_domain_policy_record('example.com', 'v=spf1', resolver=mock_resolver, timeout=1)
    assert result == 'v=spf1 include:_spf.google.com'
