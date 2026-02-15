import ipaddress
import re
from typing import TYPE_CHECKING

import dns.resolver
from dns.rdatatype import RdataType

from .exceptions import DomainPolicyError
from .models import (
    SPF_MARKER,
    CatchAllSecurityLevel,
    SPFRecordInfo,
    SPFVerificationReport,
)

if TYPE_CHECKING:
    from dns.resolver import Resolver


def _is_policy_version_valid(policy_record: str, marker: str) -> bool:
    # The only valid version is the marker and it must be only one instance at the beginning of the record.
    version_regex = re.compile(f'^{re.escape(marker)}$|^{re.escape(marker)}', re.IGNORECASE)
    match = version_regex.search(policy_record)
    if not match or match.start() != 0:
        return False
    instances = version_regex.findall(policy_record)
    return len(instances) == 1


def get_domain_policy_record(
    name: str,
    marker: str,
    resolver: 'Resolver | None' = None,
    timeout: int = 5,
) -> str:
    res = resolver or dns.resolver.get_default_resolver()
    try:
        txt_records = res.resolve(qname=name, rdtype=RdataType.TXT, lifetime=timeout)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout) as e:
        raise DomainPolicyError('Domain policy record not found', name=name) from e
    for record in txt_records:
        record_text = ''.join(a.decode('utf-8') for a in record.strings)
        if marker in record_text and _is_policy_version_valid(record_text, marker):
            return record_text
    raise DomainPolicyError('Domain policy record not found', name=name)


def _check_catchall(spf_record: str) -> CatchAllSecurityLevel | None:
    # RFC 7208 §4.7: -all (fail), ~all (softfail), ?all (neutral), +all/all (none).
    catchall_regex = re.compile(r'\s[~\+\-\?]?all\b', re.IGNORECASE)
    catchall_instances = catchall_regex.search(spf_record)
    if not catchall_instances:
        return CatchAllSecurityLevel.LOW
    if catchall_instances.end() != len(spf_record):
        return None
    catchall = catchall_instances.group().strip()
    level_by_catchall: dict[str, CatchAllSecurityLevel] = {
        '-all': CatchAllSecurityLevel.HIGH,
        '~all': CatchAllSecurityLevel.MEDIUM,
        '?all': CatchAllSecurityLevel.LOW,
        'all': CatchAllSecurityLevel.NONE,
        '+all': CatchAllSecurityLevel.NONE,
    }
    return level_by_catchall.get(catchall)


def _check_deprecated_mechanism(spf_record: str) -> bool:
    # RFC 7208 §5.5: PTR mechanism is deprecated.
    ptr_regex = re.compile(r'\bptr:?(\S+)?\b', re.IGNORECASE)
    return bool(ptr_regex.search(spf_record))


def _is_ip_address_valid(ip_address: str) -> bool:
    # Strip off the ip4: or ip6: prefix
    ip = ip_address[4:]
    if '/' not in ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False
    try:
        ipaddress.ip_network(ip)
    except ValueError:
        return False
    return True


def _check_ip_addresses(spf_record: str) -> bool:
    ip4_regex = re.compile(r'\bip4:\S+\b', re.IGNORECASE)
    ip6_regex = re.compile(r'\bip6:\S+\b', re.IGNORECASE)
    ip_instances = ip4_regex.findall(spf_record) + ip6_regex.findall(spf_record)
    return all(_is_ip_address_valid(ip_instance) for ip_instance in ip_instances)


def _extract_includes(spf_record: str, resolver: 'Resolver | None', timeout: int) -> list[str]:
    # RFC 7208 §4.6.4: evaluation must stop with permerror after 10 DNS lookups.
    include_regex = re.compile(r'\binclude:\S+\b', re.IGNORECASE)
    max_dns_queries = 10
    includes: list[str] = []
    res = resolver or dns.resolver.get_default_resolver()

    def _get_includes_recursive(spf: str) -> None:
        for i in include_regex.findall(spf):
            if len(includes) >= max_dns_queries:
                return
            domain = i.split(':', 1)[1]
            includes.append(domain)
            try:
                included = get_domain_policy_record(domain, SPF_MARKER, resolver=res, timeout=timeout)
                _get_includes_recursive(included)
            except DomainPolicyError:
                continue

    _get_includes_recursive(spf_record)
    return includes


def extract_spf_record_info(domain: str, resolver: 'Resolver | None' = None, timeout: int = 5) -> SPFVerificationReport:
    """
    Extract and validate SPF record info for the domain.
    Logic derived from: spf-validator (fpcorso)
    If strict validation is required, use pyspf (sdgathman) or magicspoofing (magichk).
    """
    try:
        spf_record = get_domain_policy_record(domain, SPF_MARKER, resolver=resolver, timeout=timeout)
    except DomainPolicyError:
        return SPFVerificationReport(valid=False, info=None)
    info = SPFRecordInfo(
        record=spf_record,
        catchall=_check_catchall(spf_record),
        deprecated_mechanism=_check_deprecated_mechanism(spf_record),
        ip_addresses=_check_ip_addresses(spf_record),
        includes=_extract_includes(spf_record, resolver, timeout),
    )
    return SPFVerificationReport(valid=True, info=info)
