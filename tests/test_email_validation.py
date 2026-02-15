from src.email_validation import get_domain_from_email, normalize_email


def test_normalize_email_valid() -> None:
    out = normalize_email('  User@Example.COM  ', check_deliverability=False)
    assert out is not None and '@' in out and out.endswith('@example.com')
    # Domain part is normalized (lowercased); local part may preserve case per email_validator


def test_normalize_email_invalid_raises() -> None:
    assert normalize_email('not-an-email', check_deliverability=False) is None
    assert normalize_email('@nodomain.com', check_deliverability=False) is None


def test_get_domain_from_email() -> None:
    assert get_domain_from_email('user@gmail.com') == 'gmail.com'
    assert get_domain_from_email('  a@b.co  ') == 'b.co'
