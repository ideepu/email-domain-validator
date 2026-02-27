from typing import TYPE_CHECKING

from .exceptions import DomainPolicyError
from .models import DKIM_MARKER, DKIM_SELECTORS, DKIMVerificationReport
from .utils import get_domain_policy_record

if TYPE_CHECKING:
    from dns.resolver import Resolver


def extract_dkim_record_info(
    domain: str,
    resolver: 'Resolver | None' = None,
    timeout: int = 5,
    selectors: list[str] | None = None,
) -> DKIMVerificationReport:
    """
    Look up DKIM policy record for the domain by trying selectors until one matches.
    Performs up to one DNS query per selector (default list size ~76).
    For more strict validation, use magicspoofing (magichk).
    """
    selectors = selectors or DKIM_SELECTORS
    for selector in selectors:
        try:
            if dkim_record := get_domain_policy_record(
                f'{selector}._domainkey.{domain}',
                DKIM_MARKER,
                resolver=resolver,
                timeout=timeout,
            ):
                return DKIMVerificationReport(valid=True, record=dkim_record)
        except DomainPolicyError:
            continue
    return DKIMVerificationReport(valid=False, record=None)
