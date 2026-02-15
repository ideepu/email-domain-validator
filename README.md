# email-domain-validator

Validate email and domain (MX, SPF, DMARC, DKIM, SSL).

## Install

```bash
uv sync
```

## Usage

```python
from email_domain_validator.runner import validate_email_and_domain

result = validate_email_and_domain("user@example.com")
```

Description:

This lib would only give information about the email and domain integrity
against these checks. This doesn't mean that the email/domain is valid if all
the checks passes or if failed it's invalid. This only gives better
possibility to check the emails.

## For further domain validation

<https://github.com/disposable-email-domains/disposable-email-domains/blob/main/disposable_email_blocklist.conf>
<https://github.com/disposable>
<https://github.com/mixmaxhq/role-based-email-addresses>
<https://raw.githubusercontent.com/ivolo/disposable-email-domains/refs/heads/master/index.json>
<https://github.com/ivolo/disposable-email-domains/blob/master/wildcard.json>

## TODO

- Add the different blocked domains links in readme and somewhere and use for checks
- Make it a pypi module
- Documentation
- github action for test coverage of this repo
