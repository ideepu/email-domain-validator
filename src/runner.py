from .dkim import extract_dkim_record_info
from .dmarc import extract_dmarc_record_info
from .email_validation import get_domain_from_email, normalize_email
from .models import (
    DKIMVerificationReport,
    DMARCVerificationReport,
    EmailDomainValidationResult,
    MXVerificationReport,
    SPFVerificationReport,
    SSLVerificationReport,
    ValidationOptions,
)
from .mx import extract_mx_record_info
from .spf import extract_spf_record_info
from .ssl_ import extract_ssl_cert_info


def validate_email_and_domain(
    email: str,
    *,
    options: ValidationOptions | None = None,
) -> EmailDomainValidationResult:
    opts = options or ValidationOptions()
    timeout = opts.timeout
    resolver = opts.resolver
    domain = get_domain_from_email(email)

    normalized_email: str | None = normalize_email(email, check_deliverability=False)
    email_valid = normalized_email is not None

    mx = MXVerificationReport(valid=False, records=None)
    if opts.run_mx and email_valid:
        mx = extract_mx_record_info(email, timeout=timeout)

    spf = SPFVerificationReport(valid=False, info=None)
    if opts.run_spf:
        spf = extract_spf_record_info(domain, resolver=resolver, timeout=timeout)

    dmarc = DMARCVerificationReport(valid=False, record=None)
    if opts.run_dmarc:
        dmarc = extract_dmarc_record_info(domain, resolver=resolver, timeout=timeout)

    dkim = DKIMVerificationReport(valid=False, record=None)
    if opts.run_dkim:
        dkim = extract_dkim_record_info(domain, resolver=resolver, timeout=timeout)

    ssl = SSLVerificationReport(valid=False, info=None)
    if opts.run_ssl:
        ssl = extract_ssl_cert_info(domain, timeout=timeout)

    return EmailDomainValidationResult(
        email_valid=email_valid,
        normalized_email=normalized_email,
        domain=domain,
        mx=mx,
        spf=spf,
        dmarc=dmarc,
        dkim=dkim,
        ssl=ssl,
    )
