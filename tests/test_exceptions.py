from src.exceptions import DomainPolicyError, EmailDomainValidationError, ErrorDetail


class TestErrorDetail:
    def test_as_dict_without_extra(self) -> None:
        d = ErrorDetail(check='spf', message='not found', code='spf_missing')
        result = d.as_dict()
        assert result == {'check': 'spf', 'message': 'not found', 'code': 'spf_missing'}
        assert 'extra' not in result

    def test_as_dict_with_extra(self) -> None:
        d = ErrorDetail(check='dkim', message='fail', code='dkim_err', extra={'key': 'val'})
        result = d.as_dict()
        assert result['extra'] == {'key': 'val'}

    def test_frozen(self) -> None:
        d = ErrorDetail(check='a', message='b', code='c')
        try:
            d.check = 'x'  # type: ignore[misc]
            assert False, 'Should have raised'
        except AttributeError:
            pass


class TestEmailDomainValidationError:
    def test_default_details_empty(self) -> None:
        err = EmailDomainValidationError('test error')
        assert not err.details
        assert err.details_as_dicts() == []
        assert str(err) == 'test error'

    def test_custom_details_preserved(self) -> None:
        detail = ErrorDetail(check='x', message='y', code='z')
        err = EmailDomainValidationError('msg', details=[detail])
        assert len(err.details) == 1
        assert err.details[0] is detail

    def test_details_as_dicts(self) -> None:
        details = [
            ErrorDetail(check='a', message='b', code='c'),
            ErrorDetail(check='d', message='e', code='f', extra={'g': 1}),
        ]
        err = EmailDomainValidationError('msg', details=details)
        dicts = err.details_as_dicts()
        assert len(dicts) == 2
        assert dicts[0] == {'check': 'a', 'message': 'b', 'code': 'c'}
        assert dicts[1]['extra'] == {'g': 1}

    def test_is_exception(self) -> None:
        assert issubclass(EmailDomainValidationError, Exception)


class TestDomainPolicyError:
    def test_default_details(self) -> None:
        err = DomainPolicyError('')
        assert len(err.details) == 1
        d = err.details[0]
        assert d.check == 'policy'
        assert d.code == 'policy_not_found'
        assert d.extra is None

    def test_with_name_kwarg(self) -> None:
        err = DomainPolicyError('', name='_dmarc.example.com')
        d = err.details[0]
        assert d.extra == {'name': '_dmarc.example.com'}

    def test_with_policy_kwarg(self) -> None:
        err = DomainPolicyError('', policy='dmarc')
        assert err.details[0].check == 'dmarc'

    def test_custom_details_override(self) -> None:
        custom = [ErrorDetail(check='x', message='y', code='z')]
        err = DomainPolicyError('', details=custom)
        assert err.details[0].check == 'x'

    def test_inheritance(self) -> None:
        assert issubclass(DomainPolicyError, EmailDomainValidationError)
