from unittest.mock import MagicMock, patch

import dns.resolver

from src.models import (
    CatchAllSecurityLevel,
    DKIMVerificationReport,
    DMARCVerificationReport,
    EmailDomainValidationResult,
    MXVerificationReport,
    SPFRecordInfo,
    SPFVerificationReport,
    SSLCertInfo,
    SSLVerificationReport,
    ValidationOptions,
)
from src.runner import validate_email_and_domain

_MOCK_MX = MXVerificationReport(valid=True, records=['mx1.example.com'])
_MOCK_SPF = SPFVerificationReport(
    valid=True,
    info=SPFRecordInfo(
        record='v=spf1 include:_spf.example.com ~all',
        catchall=CatchAllSecurityLevel.MEDIUM,
        deprecated_mechanism=False,
        ip_addresses=True,
        includes=['_spf.example.com'],
    ),
)
_MOCK_DMARC = DMARCVerificationReport(valid=True, record='v=DMARC1; p=reject')
_MOCK_DKIM = DKIMVerificationReport(valid=True, record='v=DKIM1; k=rsa; p=MII...')
_MOCK_SSL = SSLVerificationReport(
    valid=True,
    info=SSLCertInfo(
        host='example.com',
        resolved_ip='1.2.3.4',
        tls_version='TLS 1.2',
        issued_to='example.com',
        issued_o=None,
        issuer_c='US',
        issuer_o='Test CA',
        issuer_ou=None,
        issuer_cn='Test CA',
        cert_sn='12345',
        cert_alg='1.2.840.113549.1.1.11',
        cert_ver=2,
        cert_sans=['example.com'],
        cert_exp=False,
        cert_age=30,
        valid_from='2025-01-01',
        valid_till='2026-01-01',
        validity_days=365,
        days_left=335,
    ),
)


class _NoAnswerResolver(dns.resolver.Resolver):
    """Resolver that raises NoAnswer so SPF/DMARC/DKIM return valid=False without real DNS."""

    def resolve(self, *args: object, **kwargs: object) -> dns.resolver.Answer:
        raise dns.resolver.NoAnswer()


def _resolver_that_raises_no_answer() -> dns.resolver.Resolver:
    return _NoAnswerResolver()


def test_validate_email_and_domain_invalid_email() -> None:
    opts = ValidationOptions(resolver=_resolver_that_raises_no_answer(), run_ssl=False)
    r = validate_email_and_domain('not-an-email', options=opts)
    assert isinstance(r, EmailDomainValidationResult)
    assert r.email_valid is False
    assert r.normalized_email is None
    assert r.domain == 'not-an-email'


def test_validate_email_and_domain_valid_email_returns_domain() -> None:
    opts = ValidationOptions(resolver=_resolver_that_raises_no_answer(), run_ssl=False)
    r = validate_email_and_domain('user@example.com', options=opts)
    assert r.email_valid is True
    assert r.normalized_email == 'user@example.com'
    assert r.domain == 'example.com'


def test_validate_email_and_domain_options_disable_checks() -> None:
    opts = ValidationOptions(run_mx=False, run_spf=False, run_dmarc=False, run_dkim=False, run_ssl=False)
    r = validate_email_and_domain('a@b.co', options=opts)
    assert r.email_valid is True
    assert r.domain == 'b.co'
    assert r.mx.valid is False
    assert r.spf.valid is False
    assert r.dmarc.valid is False
    assert r.dkim.valid is False
    assert r.ssl.valid is False


@patch('src.runner.extract_ssl_cert_info', return_value=_MOCK_SSL)
@patch('src.runner.extract_dkim_record_info', return_value=_MOCK_DKIM)
@patch('src.runner.extract_dmarc_record_info', return_value=_MOCK_DMARC)
@patch('src.runner.extract_spf_record_info', return_value=_MOCK_SPF)
@patch('src.runner.extract_mx_record_info', return_value=_MOCK_MX)
def test_all_checks_succeed(
    mock_mx: MagicMock,
    mock_spf: MagicMock,
    mock_dmarc: MagicMock,
    mock_dkim: MagicMock,
    mock_ssl: MagicMock,
) -> None:
    r = validate_email_and_domain('user@example.com')
    assert r.email_valid is True
    assert r.normalized_email == 'user@example.com'
    assert r.domain == 'example.com'
    assert r.mx.valid is True
    assert r.mx.records == ['mx1.example.com']
    assert r.spf.valid is True
    assert r.spf.info == _MOCK_SPF.info
    assert r.dmarc.valid is True
    assert r.dmarc.record == _MOCK_DMARC.record
    assert r.dkim.valid is True
    assert r.dkim.record == _MOCK_DKIM.record
    assert r.ssl.valid is True
    assert r.ssl.info == _MOCK_SSL.info
    mock_mx.assert_called_once_with('user@example.com', timeout=5)
    mock_spf.assert_called_once_with('example.com', resolver=None, timeout=5)
    mock_dmarc.assert_called_once_with('example.com', resolver=None, timeout=5)
    mock_dkim.assert_called_once_with('example.com', resolver=None, timeout=5)
    mock_ssl.assert_called_once_with('example.com', timeout=5)


@patch('src.runner.extract_ssl_cert_info', return_value=SSLVerificationReport(valid=False, info=None))
@patch('src.runner.extract_dkim_record_info', return_value=_MOCK_DKIM)
@patch('src.runner.extract_dmarc_record_info', return_value=DMARCVerificationReport(valid=False, record=None))
@patch('src.runner.extract_spf_record_info', return_value=_MOCK_SPF)
@patch('src.runner.extract_mx_record_info', return_value=_MOCK_MX)
def test_mixed_results(
    mock_mx: MagicMock,
    mock_spf: MagicMock,
    mock_dmarc: MagicMock,
    mock_dkim: MagicMock,
    mock_ssl: MagicMock,
) -> None:
    r = validate_email_and_domain('user@example.com')
    assert r.mx.valid is True
    assert r.spf.valid is True
    assert r.dmarc.valid is False
    assert r.dmarc.record is None
    assert r.dkim.valid is True
    assert r.ssl.valid is False
    assert r.ssl.info is None
    mock_mx.assert_called_once_with('user@example.com', timeout=5)
    mock_spf.assert_called_once_with('example.com', resolver=None, timeout=5)
    mock_dmarc.assert_called_once_with('example.com', resolver=None, timeout=5)
    mock_dkim.assert_called_once_with('example.com', resolver=None, timeout=5)
    mock_ssl.assert_called_once_with('example.com', timeout=5)


@patch('src.runner.extract_ssl_cert_info', return_value=_MOCK_SSL)
@patch('src.runner.extract_dkim_record_info', return_value=_MOCK_DKIM)
@patch('src.runner.extract_dmarc_record_info', return_value=_MOCK_DMARC)
@patch('src.runner.extract_spf_record_info', return_value=_MOCK_SPF)
@patch('src.runner.extract_mx_record_info', return_value=_MOCK_MX)
def test_default_options_runs_all_checks(
    mock_mx: MagicMock,
    mock_spf: MagicMock,
    mock_dmarc: MagicMock,
    mock_dkim: MagicMock,
    mock_ssl: MagicMock,
) -> None:
    """When no options are passed, all checks should run (verify all mocks called)."""
    r = validate_email_and_domain('user@example.com')
    assert r.mx.valid is True
    assert r.spf.valid is True
    assert r.dmarc.valid is True
    assert r.dkim.valid is True
    assert r.ssl.valid is True
    mock_mx.assert_called_once_with('user@example.com', timeout=5)
    mock_spf.assert_called_once_with('example.com', resolver=None, timeout=5)
    mock_dmarc.assert_called_once_with('example.com', resolver=None, timeout=5)
    mock_dkim.assert_called_once_with('example.com', resolver=None, timeout=5)
    mock_ssl.assert_called_once_with('example.com', timeout=5)
