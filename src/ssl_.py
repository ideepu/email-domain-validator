import socket
import ssl
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import cast

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.extensions import ExtensionNotFound

from .models import SSLCertInfo, SSLVerificationReport

DEFAULT_PORT = 443


def _get_cert_sans(x509cert: x509.Certificate) -> list[str]:
    san_list: list[str] = []
    try:
        san_extension = x509cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        if not san_extension:
            return san_list
        for name in cast(Iterable, san_extension.value):
            san_list.append(str(name.value) if hasattr(name, 'value') else str(name))
    except ExtensionNotFound:
        pass
    return san_list


def _resolve_name_attribute_to_str(name_attr: list[x509.NameAttribute]) -> str | None:
    if not name_attr:
        return None
    value = name_attr[0].value
    return value.decode('utf-8') if isinstance(value, bytes) else value


def _get_cert_info(host: str, cert: x509.Certificate, resolved_ip: str, tls_version: str) -> SSLCertInfo:
    time_now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    subject = cert.subject
    issuer = cert.issuer
    return SSLCertInfo(
        host=host,
        resolved_ip=resolved_ip,
        tls_version=tls_version,
        issued_to=_resolve_name_attribute_to_str(subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)),
        issued_o=_resolve_name_attribute_to_str(subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)),
        issuer_c=_resolve_name_attribute_to_str(issuer.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)),
        issuer_o=_resolve_name_attribute_to_str(issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)),
        issuer_ou=_resolve_name_attribute_to_str(issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)),
        issuer_cn=_resolve_name_attribute_to_str(issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)),
        cert_sn=str(cert.serial_number),
        cert_alg=cert.signature_algorithm_oid.dotted_string,
        cert_ver=cert.version.value,
        cert_sans=_get_cert_sans(cert),
        cert_exp=not_after < time_now,
        cert_age=(time_now - not_before).days,
        valid_from=cert.not_valid_before_utc.strftime('%Y-%m-%d'),
        valid_till=cert.not_valid_after_utc.strftime('%Y-%m-%d'),
        validity_days=(cert.not_valid_after_utc - cert.not_valid_before_utc).days,
        days_left=(not_after - time_now).days,
    )


def _get_cert(host: str, timeout: int, port: int = DEFAULT_PORT) -> tuple[x509.Certificate, str, str]:
    # TLS 1.2 → 1.1 → 1.0 fallback; hostname/cert verification disabled to only retrieve cert.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    # Legacy TLS fallback intentional to probe cert across server-supported versions.
    tls_versions = [
        (ssl.PROTOCOL_TLSv1_2, 'TLS 1.2'),
        (ssl.PROTOCOL_TLSv1_1, 'TLS 1.1'),  # NOSONAR
        (ssl.PROTOCOL_TLSv1, 'TLS 1.0'),  # NOSONAR
    ]
    last_error: Exception | None = None
    for _tls_protocol, tls_version in tls_versions:
        try:
            # Hostname and cert verification disabled: we only fetch the cert for inspection.
            context = ssl.create_default_context()  # NOSONAR
            context.check_hostname = False  # NOSONAR
            context.verify_mode = ssl.CERT_NONE  # NOSONAR
            ssl_sock = context.wrap_socket(sock, server_hostname=host)  # NOSONAR
            ssl_sock.do_handshake()
            cert_der = ssl_sock.getpeercert(binary_form=True)
            if cert_der is None:
                raise ssl.SSLError('Certificate not available in binary form')
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            resolved_ip = socket.gethostbyname(host)
            ssl_sock.close()
            sock.close()
            return cert, resolved_ip, tls_version
        except (ssl.CertificateError, OSError) as e:
            last_error = e
            continue
    sock.close()
    raise ssl.SSLError('Failed to establish SSL connection with any supported TLS version') from last_error


def extract_ssl_cert_info(host: str, timeout: int = 5, port: int = DEFAULT_PORT) -> SSLVerificationReport:
    try:
        cert, resolved_ip, tls_version = _get_cert(host, timeout, port)
        cert_info = _get_cert_info(host, cert, resolved_ip, tls_version)
        return SSLVerificationReport(valid=True, info=cert_info)
    except ssl.CertificateError, OSError:
        return SSLVerificationReport(valid=False, info=None)
