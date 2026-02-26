from email_validator import EmailNotValidError, validate_email


def normalize_email(email: str, *, check_deliverability: bool = False) -> str | None:
    try:
        result = validate_email(email.strip(), check_deliverability=check_deliverability)
        return result.normalized
    except EmailNotValidError:
        return None


def get_domain_from_email(email: str) -> str:
    return email.strip().split('@')[-1].strip()
