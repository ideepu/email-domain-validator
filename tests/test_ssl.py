import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound

from src.ssl_ import (
    _get_cert,
    _get_cert_info,
    _get_cert_sans,
    _resolve_name_attribute_to_str,
    extract_ssl_cert_info,
)


def _make_name_attr(value: str | bytes) -> MagicMock:
    attr = MagicMock()
    attr.value = value
    return attr


def _attr_getter(oid_to_value: dict[object, str | None]) -> object:
    def getter(oid: object) -> list[MagicMock]:
        val = oid_to_value.get(oid)
        return [_make_name_attr(val)] if val else []

    return getter


def _make_san_extension(sans: list[str] | None, has_san: bool) -> MagicMock:
    if not has_san:
        return MagicMock(side_effect=ExtensionNotFound('no SAN', x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME))
    names = [MagicMock(value=s) for s in (sans or ['example.com', '*.example.com'])]
    san_ext = MagicMock()
    san_ext.value = names
    return MagicMock(return_value=san_ext)


def _make_mock_cert(  # pylint: disable=too-many-arguments
    *,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    cn: str = 'example.com',
    org: str | None = None,
    issuer_cn: str = 'Test CA',
    issuer_c: str = 'US',
    issuer_o: str = 'Test Org',
    issuer_ou: str | None = None,
    serial: int = 12345,
    alg_oid: str = '1.2.840.113549.1.1.11',
    version_value: int = 2,
    sans: list[str] | None = None,
    has_san_extension: bool = True,
) -> MagicMock:
    now = datetime.now(timezone.utc)
    cert = MagicMock()
    cert.not_valid_before_utc = not_before or (now - timedelta(days=30))
    cert.not_valid_after_utc = not_after or (now + timedelta(days=335))
    cert.serial_number = serial
    cert.signature_algorithm_oid.dotted_string = alg_oid
    cert.version.value = version_value
    cert.subject.get_attributes_for_oid = _attr_getter(
        {
            x509.NameOID.COMMON_NAME: cn,
            x509.NameOID.ORGANIZATION_NAME: org,
        }
    )
    cert.issuer.get_attributes_for_oid = _attr_getter(
        {
            x509.NameOID.COMMON_NAME: issuer_cn,
            x509.NameOID.COUNTRY_NAME: issuer_c,
            x509.NameOID.ORGANIZATION_NAME: issuer_o,
            x509.NameOID.ORGANIZATIONAL_UNIT_NAME: issuer_ou,
        }
    )
    cert.extensions.get_extension_for_oid = _make_san_extension(sans, has_san_extension)
    return cert


class TestGetCertSans:
    def test_returns_san_list(self) -> None:
        cert = _make_mock_cert(sans=['a.com', 'b.com'])
        assert _get_cert_sans(cert) == ['a.com', 'b.com']

    def test_extension_not_found_returns_empty(self) -> None:
        cert = _make_mock_cert(has_san_extension=False)
        assert not _get_cert_sans(cert)

    def test_falsy_extension_returns_empty(self) -> None:
        cert = MagicMock()
        cert.extensions.get_extension_for_oid = MagicMock(return_value=None)
        assert not _get_cert_sans(cert)

    def test_name_without_value_attribute(self) -> None:
        """SAN entry that lacks .value uses str() fallback."""
        cert = MagicMock()

        @dataclass
        class _NameWithoutValue:
            def __str__(self) -> str:
                return 'fallback.com'

        san_ext = MagicMock()
        san_ext.value = [_NameWithoutValue()]
        cert.extensions.get_extension_for_oid = MagicMock(return_value=san_ext)
        assert _get_cert_sans(cert) == ['fallback.com']


class TestResolveNameAttribute:
    def test_empty_list_returns_none(self) -> None:
        assert _resolve_name_attribute_to_str([]) is None

    def test_str_value_returned(self) -> None:
        attr = _make_name_attr('example.com')
        assert _resolve_name_attribute_to_str([attr]) == 'example.com'

    def test_bytes_value_decoded(self) -> None:
        attr = _make_name_attr(b'example.com')
        assert _resolve_name_attribute_to_str([attr]) == 'example.com'


class TestGetCertInfo:
    def test_all_fields_populated(self) -> None:
        now = datetime.now(timezone.utc)
        not_before = now - timedelta(days=30)
        not_after = now + timedelta(days=335)
        cert = _make_mock_cert(
            not_before=not_before,
            not_after=not_after,
            cn='example.com',
            org='Example Inc',
            issuer_cn='CA',
            issuer_c='US',
            issuer_o='CA Org',
            issuer_ou='CA Unit',
            serial=99999,
            sans=['example.com'],
        )
        info = _get_cert_info('example.com', cert, '1.2.3.4', 'TLS 1.2')
        assert info.host == 'example.com'
        assert info.resolved_ip == '1.2.3.4'
        assert info.tls_version == 'TLS 1.2'
        assert info.issued_to == 'example.com'
        assert info.issued_o == 'Example Inc'
        assert info.issuer_c == 'US'
        assert info.issuer_o == 'CA Org'
        assert info.issuer_ou == 'CA Unit'
        assert info.issuer_cn == 'CA'
        assert info.cert_sn == '99999'
        assert info.cert_ver == 2
        assert info.cert_sans == ['example.com']
        assert info.cert_exp is False
        assert info.cert_age == 30
        assert info.validity_days == 365
        # days_left can be 334 or 335 depending on time-of-day rounding
        assert info.days_left in (334, 335)

    def test_expired_cert(self) -> None:
        now = datetime.now(timezone.utc)
        not_before = now - timedelta(days=400)
        not_after = now - timedelta(days=5)
        cert = _make_mock_cert(not_before=not_before, not_after=not_after)
        info = _get_cert_info('expired.com', cert, '5.6.7.8', 'TLS 1.2')
        assert info.cert_exp is True
        assert info.days_left < 0

    def test_naive_datetimes_get_utc(self) -> None:
        """If cert returns naive datetimes, they get replaced with UTC."""
        naive_before = datetime(2025, 1, 1)
        naive_after = datetime(2027, 1, 1)
        cert = _make_mock_cert()
        cert.not_valid_before_utc = naive_before
        cert.not_valid_after_utc = naive_after
        info = _get_cert_info('example.com', cert, '1.2.3.4', 'TLS 1.2')
        assert info.valid_from == '2025-01-01'
        assert info.valid_till == '2027-01-01'


class TestGetCert:
    def _setup_socket_mocks(self, cert_der: bytes | None = b'\x00') -> tuple[MagicMock, MagicMock, MagicMock]:
        mock_sock = MagicMock()
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = cert_der
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_sock
        return mock_sock, mock_ssl_sock, mock_context

    @patch('src.ssl_.socket.gethostbyname', return_value='1.2.3.4')
    @patch('src.ssl_.x509.load_der_x509_certificate')
    @patch('src.ssl_.ssl.create_default_context')
    @patch('src.ssl_.socket.socket')
    def test_happy_path(
        self, mock_socket_cls: MagicMock, mock_ctx_fn: MagicMock, mock_load_cert: MagicMock, _mock_resolve: MagicMock
    ) -> None:
        mock_sock, _mock_ssl_sock, mock_context = self._setup_socket_mocks(b'\x30\x00')
        mock_socket_cls.return_value = mock_sock
        mock_ctx_fn.return_value = mock_context
        fake_cert = MagicMock()
        mock_load_cert.return_value = fake_cert

        cert, ip, tls_ver = _get_cert('example.com', 5)
        assert cert is fake_cert
        assert ip == '1.2.3.4'
        assert tls_ver == 'TLS 1.2'
        mock_sock.settimeout.assert_called_once_with(5)
        mock_sock.connect.assert_called_once_with(('example.com', 443))

    @patch('src.ssl_.ssl.create_default_context')
    @patch('src.ssl_.socket.socket')
    def test_all_tls_versions_fail(self, mock_socket_cls: MagicMock, mock_ctx_fn: MagicMock) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.do_handshake.side_effect = ssl.SSLError('handshake fail')
        mock_ctx_fn.return_value = mock_context

        with pytest.raises(ssl.SSLError, match='Failed to establish SSL connection'):
            _get_cert('bad.com', 5)
        mock_sock.close.assert_called()

    @patch('src.ssl_.ssl.create_default_context')
    @patch('src.ssl_.socket.socket')
    def test_cert_der_none_raises(self, mock_socket_cls: MagicMock, mock_ctx_fn: MagicMock) -> None:
        mock_sock, _mock_ssl_sock, mock_context = self._setup_socket_mocks(cert_der=None)
        mock_socket_cls.return_value = mock_sock
        mock_ctx_fn.return_value = mock_context

        # cert_der=None raises SSLError, caught in loop, tries next version -> eventually all fail
        with pytest.raises(ssl.SSLError, match='Failed to establish SSL connection'):
            _get_cert('nocert.com', 5)


class TestExtractSslCertInfo:
    @patch('src.ssl_._get_cert')
    def test_happy_path(self, mock_get_cert: MagicMock) -> None:
        cert = _make_mock_cert(cn='secure.com', sans=['secure.com'])
        mock_get_cert.return_value = (cert, '10.0.0.1', 'TLS 1.2')
        result = extract_ssl_cert_info('secure.com', timeout=3)
        assert result.valid is True
        assert result.info is not None
        assert result.info.host == 'secure.com'
        mock_get_cert.assert_called_once_with('secure.com', 3, 443)

    @patch('src.ssl_._get_cert', side_effect=OSError('connection refused'))
    def test_os_error(self, _mock: MagicMock) -> None:
        result = extract_ssl_cert_info('down.com')
        assert result.valid is False
        assert result.info is None

    @patch('src.ssl_._get_cert', side_effect=ssl.SSLCertVerificationError('cert invalid'))
    def test_certificate_error(self, _mock: MagicMock) -> None:
        result = extract_ssl_cert_info('badcert.com')
        assert result.valid is False
        assert result.info is None

    @patch('src.ssl_._get_cert', side_effect=ssl.SSLError('ssl error'))
    def test_ssl_error(self, _mock: MagicMock) -> None:
        result = extract_ssl_cert_info('sslerror.com')
        assert result.valid is False
        assert result.info is None

    @patch('src.ssl_._get_cert')
    def test_custom_port(self, mock_get_cert: MagicMock) -> None:
        cert = _make_mock_cert()
        mock_get_cert.return_value = (cert, '10.0.0.1', 'TLS 1.2')
        extract_ssl_cert_info('example.com', port=8443)
        mock_get_cert.assert_called_once_with('example.com', 5, 8443)
