# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-02

### Added

- Production/stable release (1.0.0).

## [0.1.1] - 2026-03-01

### Added

- PEP 561 marker (`py.typed`) for type-checker support when using the package as a dependency.
- Domain policy record utilities in `utils` (shared parsing for SPF/DMARC-style records).
- Burner-email-providers reference in documentation.

### Changed

- Public API documentation updated for SemVer (README).
- Domain policy record handling: shared utils; redundant match checks removed in SPF/DMARC/DKIM.

### Fixed

- Exception when a domain has no nameservers; validation no longer crashes and returns a proper result.

## [0.1.0] - 2026-02-26

### Added

- Initial release.
- Email validation (syntax; optional MX deliverability).
- Domain checks: MX, SPF, DMARC, DKIM, SSL certificate.
- CLI with `--timeout`, skip flags per check, and `--compact` JSON.
- Library API: `validate_email_and_domain()`, `ValidationOptions`, `EmailDomainValidationResult`.
