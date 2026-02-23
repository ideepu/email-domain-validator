# email-domain-validator

Validate an email address and its domain using MX, SPF, DMARC, DKIM, and SSL
checks. The library reports whether each check passes or fails; it does not
decide if an email or domain is "valid" or "invalid" overall. Use the results
as signals for your own logic (e.g. risk scoring or filtering).

## Install

**Requires** Python>=3.10

From the project root:

```bash
uv sync
```

## Quick start

**CLI** (run from repo root):

```bash
python run.py user@example.com
```

Output is JSON: `email_valid`, `normalized_email`, `domain`, and reports for
`mx`, `spf`, `dmarc`, `dkim`, and `ssl`.

**Library:**

```python
from email_domain_validator import validate_email_and_domain

result = validate_email_and_domain('user@example.com')
print(result.email_valid, result.mx.valid, result.spf.valid)
```

Optional: pass `ValidationOptions` to set timeout, or turn checks on/off
(`run_mx`, `run_spf`, `run_dmarc`, `run_dkim`, `run_ssl`).

## Checks

| Check | What it does |
| ----- | ------------ |
| **Email** | Syntax and normalization; optional deliverability (MX). |
| **MX** | Whether the domain has mail servers (deliverability). |
| **SPF** | TXT record `v=spf1`; catch-all level and mechanisms. |
| **DMARC** | TXT at `_dmarc.<domain>` with `v=DMARC1`. |
| **DKIM** | TXT at `<selector>._domainkey.<domain>`; common selectors. |
| **SSL** | TLS cert for domain (port 443); validity and basic fields. |

Results are dataclasses (e.g. `EmailDomainValidationResult`,
`SPFVerificationReport`). See `src/models.py` for all report types.

## CLI options

- `--timeout N` — Timeout in seconds for DNS/SSL (default: 5).
- `--no-mx`, `--no-spf`, `--no-dmarc`, `--no-dkim`, `--no-ssl` — Skip that
  check.
- `--compact` — Output JSON without indentation.

## Further validation

For disposable or role-based domains, combine with external lists or
tools, for example:

- [disposable-email-domains](https://github.com/disposable-email-domains/disposable_email_blocklist.conf)
- [disposable-email-domains (ivolo)](https://github.com/ivolo/disposable-email-domains)
- [role-based-email-addresses](https://github.com/mixmaxhq/role-based-email-addresses)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, running tests, and how to
submit changes.

## License

[MIT](LICENSE).
