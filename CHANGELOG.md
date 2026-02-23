# Changelog

Notable changes to this project are listed here.

## [0.1.0]

- Initial release.
- Email validation (syntax and optional deliverability via MX).
- Domain checks: MX, SPF, DMARC, DKIM, and SSL certificate.
- CLI with JSON output and flags to skip individual checks.
- Library API: `validate_email_and_domain()` and `ValidationOptions`.
