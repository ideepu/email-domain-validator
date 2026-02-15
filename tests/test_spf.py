from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from src.exceptions import DomainPolicyError
from src.models import CatchAllSecurityLevel
from src.spf import (
    _check_catchall,
    _check_deprecated_mechanism,
    _check_ip_addresses,
    _extract_includes,
    _is_policy_version_valid,
    extract_spf_record_info,
    get_domain_policy_record,
)


def test_is_policy_version_valid() -> None:
    assert _is_policy_version_valid('v=spf1 include:_spf.google.com', 'v=spf1') is True
    assert _is_policy_version_valid('v=spf1', 'v=spf1') is True
    assert _is_policy_version_valid('v=spf1 ', 'v=spf1') is True
    # DMARC with space after marker matches; semicolon alone does not (version must be at start then EOL or space)
    assert _is_policy_version_valid('v=DMARC1 p=none', 'v=DMARC1') is True
    assert _is_policy_version_valid('other v=spf1', 'v=spf1') is False
    # Regex matches once at start ("v=spf1 ") so implementation reports valid; duplicate tags not detected


def test_check_catchall() -> None:
    assert _check_catchall('v=spf1 include:_spf.google.com -all') == CatchAllSecurityLevel.HIGH
    assert _check_catchall('v=spf1 ~all') == CatchAllSecurityLevel.MEDIUM
    assert _check_catchall('v=spf1 ?all') == CatchAllSecurityLevel.LOW
    assert _check_catchall('v=spf1 +all') == CatchAllSecurityLevel.NONE
    assert _check_catchall('v=spf1 all') == CatchAllSecurityLevel.NONE
    assert _check_catchall('v=spf1 include:x.com') == CatchAllSecurityLevel.LOW
    assert _check_catchall('v=spf1 -all extra') is None


def test_check_deprecated_mechanism() -> None:
    assert _check_deprecated_mechanism('v=spf1 ptr:example.com -all') is True
    assert _check_deprecated_mechanism('v=spf1 ptr -all') is True
    assert _check_deprecated_mechanism('v=spf1 include:_spf.google.com -all') is False


def test_check_ip_addresses() -> None:
    assert _check_ip_addresses('v=spf1 ip4:192.168.1.1 -all') is True
    assert _check_ip_addresses('v=spf1 ip4:192.168.1.0/24 -all') is True
    assert _check_ip_addresses('v=spf1 ip6:::1 -all') is True
    assert _check_ip_addresses('v=spf1 ip4:999.999.999.999 -all') is False


def test_extract_includes_no_resolver_cap() -> None:
    # Without mocking DNS, _extract_includes on a record with no include: just returns []
    includes = _extract_includes('v=spf1 -all', resolver=None, timeout=1)
    assert not includes


def test_get_domain_policy_record_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_nxdomain(*_args: object, **_kwargs: object) -> None:
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver.Resolver, 'resolve', raise_nxdomain)
    with pytest.raises(DomainPolicyError):
        get_domain_policy_record('example.com', 'v=spf1', resolver=dns.resolver.Resolver(), timeout=1)


def test_extract_spf_record_info_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_no_answer(*_args: object, **_kwargs: object) -> None:
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver.Resolver, 'resolve', raise_no_answer)
    report = extract_spf_record_info('example.com', resolver=dns.resolver.Resolver(), timeout=1)
    assert report.valid is False
    assert report.info is None


def test_is_policy_version_valid_semicolon_delimiter() -> None:
    """Validates the regex fix: v=DMARC1; (semicolon, no space) must match."""
    assert _is_policy_version_valid('v=DMARC1;p=reject', 'v=DMARC1') is True
    assert _is_policy_version_valid('v=DMARC1; p=reject; rua=mailto:r@x.com', 'v=DMARC1') is True
    # DKIM marker with semicolon
    assert _is_policy_version_valid('v=DKIM1; k=rsa; p=MII...', 'v=DKIM1') is True
    # SPF still works with space
    assert _is_policy_version_valid('v=spf1 include:x.com ~all', 'v=spf1') is True


def test_extract_includes_recursive() -> None:
    call_count = 0

    def _mock_get_record(name: str, _marker: str, **_kwargs: object) -> str:
        nonlocal call_count
        call_count += 1
        if name == 'a.com':
            return 'v=spf1 include:b.com include:c.com ~all'
        if name == 'b.com':
            return 'v=spf1 include:d.com -all'
        if name == 'c.com':
            return 'v=spf1 ip4:1.2.3.4 -all'
        if name == 'd.com':
            return 'v=spf1 ip4:5.6.7.8 -all'
        raise DomainPolicyError('')

    with patch('src.spf.get_domain_policy_record', side_effect=_mock_get_record):
        includes = _extract_includes('v=spf1 include:a.com ~all', resolver=None, timeout=1)

    assert 'a.com' in includes
    assert 'b.com' in includes
    assert 'c.com' in includes
    assert 'd.com' in includes


def test_extract_includes_respects_max_dns_queries() -> None:
    """_extract_includes caps at 10 DNS lookups to prevent abuse."""
    # Build a record with 15 includes
    domains = [f'd{i}.com' for i in range(15)]
    record = 'v=spf1 ' + ' '.join(f'include:{d}' for d in domains) + ' -all'

    with patch('src.spf.get_domain_policy_record', side_effect=DomainPolicyError('')):
        includes = _extract_includes(record, resolver=None, timeout=1)

    assert len(includes) <= 10


def test_extract_spf_record_info_success() -> None:
    spf_record = 'v=spf1 include:_spf.example.com ip4:10.0.0.0/8 ~all'
    with patch('src.spf.get_domain_policy_record', return_value=spf_record):
        report = extract_spf_record_info('example.com')
    assert report.valid is True
    assert report.info is not None
    assert report.info.record == spf_record
    assert report.info.catchall == CatchAllSecurityLevel.MEDIUM
    assert report.info.deprecated_mechanism is False
    assert report.info.ip_addresses is True


def test_get_domain_policy_record_lifetime_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_timeout(*_args: object, **_kwargs: object) -> None:
        raise dns.resolver.LifetimeTimeout(timeout=5.0, errors=[])

    monkeypatch.setattr(dns.resolver.Resolver, 'resolve', raise_timeout)
    with pytest.raises(DomainPolicyError):
        get_domain_policy_record('example.com', 'v=spf1', resolver=dns.resolver.Resolver(), timeout=5)


def test_get_domain_policy_record_no_matching_marker() -> None:
    mock_record = MagicMock()
    mock_record.strings = [b'some-other-txt-record']
    mock_answer = MagicMock()
    mock_answer.__iter__ = lambda self: iter([mock_record])

    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = mock_answer
    with pytest.raises(DomainPolicyError):
        get_domain_policy_record('example.com', 'v=spf1', resolver=mock_resolver, timeout=1)
