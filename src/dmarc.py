from typing import TYPE_CHECKING

from .exceptions import DomainPolicyError
from .models import DMARC_MARKER, DMARCVerificationReport
from .utils import get_domain_policy_record

if TYPE_CHECKING:
    from dns.resolver import Resolver


def extract_dmarc_record_info(
    domain: str,
    resolver: 'Resolver | None' = None,
    timeout: int = 5,
) -> DMARCVerificationReport:
    """
    For more strict validation, use checkdmarc (domainaware), magicspoofing (magichk).
    """
    try:
        if dmarc_record := get_domain_policy_record(
            f'_dmarc.{domain}',
            DMARC_MARKER,
            resolver=resolver,
            timeout=timeout,
        ):
            return DMARCVerificationReport(valid=True, record=dmarc_record)
    except DomainPolicyError:
        pass
    return DMARCVerificationReport(valid=False, record=None)
