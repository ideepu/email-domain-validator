# email-domain-validator

Validate an email address with syntax normalization, plus domain-level DNS
checks: MX, SPF, DMARC, DKIM, and SSL/TLS certificate inspection.

This package reports each check independently. It does **not** produce a single
global decision like 'valid' or 'invalid' for fraud, abuse, or trust. Treat the
output as verification signals that can feed your own risk scoring, allow/deny
rules, or enrichment pipeline.

## Install

**Requires:** Python >= 3.14

```bash
pip install email-domain-validator
```

## Quick start

### CLI

```bash
email-domain-validator user@example.com
```

### CLI options

- `--timeout N`: per-check timeout in seconds for DNS and TLS operations
  (default: `5`)
- `--no-mx`, `--no-spf`, `--no-dmarc`, `--no-dkim`, `--no-ssl`: skip one check
- `--compact`: print JSON output without indentation

### Library

```python
from email_domain_validator import validate_email_and_domain

result = validate_email_and_domain('user@example.com')
print(result.email_valid, result.mx.valid, result.spf.valid)
```

By default, all optional checks run. Use `ValidationOptions` to set timeout and
enable/disable checks (`run_mx`, `run_spf`, `run_dmarc`, `run_dkim`, `run_ssl`).

```python
from email_domain_validator import ValidationOptions, validate_email_and_domain

result = validate_email_and_domain(
    'user@example.com',
    options=ValidationOptions(run_dkim=False, run_ssl=False),
)
print(result.to_dict())
```

### Execution behavior

- Email syntax normalization always runs first and cannot be disabled.
- MX runs only when `email_valid=True` (that is, syntax normalization
  succeeds).
- SPF, DMARC, DKIM, and SSL run against the `domain`.

## Checks

The checks below follow widely used email-authentication and transport
conventions, while keeping results practical for application logic and risk
pipelines.

### Email (syntax and normalization)

Uses [`python-email-validator`](https://github.com/JoshData/python-email-validator)
for syntax validation and normalized email extraction, equivalent to:
`validate_email(email, check_deliverability=False)`.

If syntax validation raises an exception, the check result is returned as
`None`. This check is always executed and cannot be disabled.

This stage helps ensure downstream DNS and policy checks run against a clean,
normalized address form instead of raw user input.

### MX

Verifies whether the domain publishes mail-exchanger records using
[`python-email-validator`](https://github.com/JoshData/python-email-validator),
equivalent to:
`validate_email(email, check_deliverability=True, timeout=timeout)`.

The report includes discovered MX hosts when available. If MX lookup fails or
the email is invalid, the MX check is marked invalid. If lookup succeeds but no
hosts are returned, the result is `valid=True` with `records=[]`.

Operationally, this is a deliverability-oriented signal: domains with clear MX
configuration are usually better candidates for transactional email workflows.

### SPF

Looks for a TXT record that starts with `v=spf1`. If no SPF record is found, the
SPF check is marked invalid. When found, additional SPF checks are performed,
including:

- qualifier analysis for broad/catch-all sender matching behavior
- detection of `ptr` deprecated mechanism
- extraction and validation of declared IPv4/IPv6 addresses
- recursive extraction of `include` domains (maximum 10 DNS lookups)

This helps you identify overly permissive sender authorization, stale network
declarations, and inheritance patterns across included sender policies.

### DMARC

Looks up the DMARC policy record at `_dmarc.<domain>` and verifies the expected
`v=DMARC1` marker at record start.

DMARC presence is a strong governance signal because it indicates the domain
has published an authentication policy entry point, even when you still need
higher level business logic for final trust decisions.

### DKIM

Checks for DKIM records at `<selector>._domainkey.<domain>`. The validator
tries common DKIM selectors and stops on the first valid record found.

In the worst case, this performs one DNS TXT lookup per selector candidate
until a match is found (or candidates are exhausted).

Because selector usage varies by provider and deployment age, this check
targets commonly used selectors as a practical "likely configured" signal. It
validates selector/key record presence at the DNS level and does not verify
end-to-end DKIM message signatures.

### SSL/TLS

Inspects the domain certificate and reports connection metadata, including host
IP, TLS probe version label, and certificate expiration status.

Treat this as transport posture context for your domain profile, not as proof
of mail-channel security by itself. The SSL check fetches and parses the
presented certificate for inspection; it does not perform strict
hostname/chain trust validation.

## Result models

The library returns `EmailDomainValidationResult`; its attributes and nested
report types are defined in `src/models.py`.

## Further validation

Domain-level authentication checks are strong signals, but they are not a full
identity or abuse guarantee by themselves.

For stronger decisions, combine these results with disposable-domain and
role-based address intelligence, plus your own context-specific policies.

Examples:

- [disposable](<https://github.com/disposable>)
- [disposable-email-domains](https://github.com/disposable-email-domains)
- [disposable-email-domains (ivolo)](https://github.com/ivolo/disposable-email-domains)
- [role-based-email-addresses](https://github.com/mixmaxhq/role-based-email-addresses)
- [burner-email-providers](https://github.com/wesbos/burner-email-providers)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, test commands, and
change submission workflow.

## License

[MIT](LICENSE)
