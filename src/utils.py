import re
from typing import TYPE_CHECKING

import dns.resolver
from dns.rdatatype import RdataType

from .exceptions import DomainPolicyError

if TYPE_CHECKING:
    from dns.resolver import Resolver


def _is_policy_version_valid(policy_record: str, marker: str) -> bool:
    version_regex = re.compile(f'^{re.escape(marker)}$|^{re.escape(marker)}', re.IGNORECASE)
    match = version_regex.search(policy_record)
    if not match:
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
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.LifetimeTimeout,
        dns.resolver.NoNameservers,
    ) as e:
        raise DomainPolicyError('Domain policy record not found') from e
    for record in txt_records:
        record_text = ''.join(a.decode('utf-8') for a in record.strings)
        if marker in record_text and _is_policy_version_valid(record_text, marker):
            return record_text
    raise DomainPolicyError('Domain policy record not found')
