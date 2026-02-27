from unittest.mock import patch

from src.exceptions import DomainPolicyError
from src.models import SPF_MARKER, CatchAllSecurityLevel
from src.spf import (
    _check_catchall,
    _check_deprecated_mechanism,
    _check_ip_addresses,
    _extract_includes,
    extract_spf_record_info,
)


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

    with patch('src.spf.get_domain_policy_record', side_effect=DomainPolicyError('')) as mock:
        includes = _extract_includes(record, resolver=None, timeout=1)

    assert len(includes) <= 10
    assert mock.call_count == 10


def test_extract_spf_record_info_no_record_found() -> None:
    with patch('src.spf.get_domain_policy_record', side_effect=DomainPolicyError('')) as mock:
        report = extract_spf_record_info('example.com')
    assert report.valid is False
    assert report.info is None
    mock.assert_called_once_with('example.com', SPF_MARKER, resolver=None, timeout=5)


def test_extract_spf_record_info_success() -> None:
    spf_record = 'v=spf1 include:_spf.example.com ip4:10.0.0.0/8 ~all'
    with patch('src.spf.get_domain_policy_record', return_value=spf_record) as mock:
        report = extract_spf_record_info('example.com')
    assert report.valid is True
    assert report.info is not None
    assert report.info.record == spf_record
    assert report.info.catchall == CatchAllSecurityLevel.MEDIUM
    assert report.info.deprecated_mechanism is False
    assert report.info.ip_addresses is True
    mock.assert_called()
