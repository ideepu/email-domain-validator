class DomainPolicyError(Exception):
    def __init__(self, message: str = 'Policy not found') -> None:
        super().__init__(message)
