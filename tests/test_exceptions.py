from src.exceptions import DomainPolicyError


class TestDomainPolicyError:
    def test_message(self) -> None:
        err = DomainPolicyError('msg')
        assert str(err) == 'msg'

    def test_default_message_when_empty(self) -> None:
        err = DomainPolicyError()
        assert str(err) == 'Policy not found'
