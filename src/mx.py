from email_validator import EmailNotValidError, validate_email

from .models import MXVerificationReport


def extract_mx_record_info(email: str, timeout: int = 5) -> MXVerificationReport:
    try:
        validated = validate_email(email.strip(), check_deliverability=True, timeout=timeout)
        if not hasattr(validated, 'mx'):
            return MXVerificationReport(valid=False, records=None)
        mx_records = [mx_record for _, mx_record in validated.mx]
        return MXVerificationReport(valid=True, records=mx_records)
    except EmailNotValidError:
        return MXVerificationReport(valid=False, records=None)
