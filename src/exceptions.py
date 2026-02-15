from dataclasses import dataclass


@dataclass(frozen=True)
class ErrorDetail:
    check: str
    message: str
    code: str
    extra: dict[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        out: dict[str, object] = {'check': self.check, 'message': self.message, 'code': self.code}
        if self.extra:
            out['extra'] = self.extra
        return out


class EmailDomainValidationError(Exception):
    def __init__(
        self,
        message: str,
        *args: object,
        details: list[ErrorDetail] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(message, *args, **kwargs)
        self._details: list[ErrorDetail] = list(details) if details else []

    @property
    def details(self) -> list[ErrorDetail]:
        return self._details

    def details_as_dicts(self) -> list[dict[str, object]]:
        return [d.as_dict() for d in self.details]


class DomainPolicyError(EmailDomainValidationError):
    def __init__(
        self,
        message: str,
        *args: object,
        policy: str | None = None,
        name: str | None = None,
        details: list[ErrorDetail] | None = None,
        **kwargs: object,
    ) -> None:
        if not details:
            extra: dict[str, object] = {}
            if name is not None:
                extra['name'] = name
            details = [
                ErrorDetail(
                    check=policy or 'policy',
                    message=message or 'Policy not found',
                    code='policy_not_found',
                    extra=extra or None,
                )
            ]
        super().__init__(message or 'Policy not found', *args, details=details, **kwargs)
