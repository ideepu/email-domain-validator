import argparse
import json
import sys

from .models import ValidationOptions
from .runner import validate_email_and_domain


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='email-domain-validator',
        description='Validate an email address and its domain (MX, SPF, DMARC, DKIM, SSL).',
    )
    parser.add_argument('email', help='Email address to validate')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout in seconds for DNS/SSL lookups (default: 5)')
    parser.add_argument('--no-mx', action='store_true', help='Skip MX record check')
    parser.add_argument('--no-spf', action='store_true', help='Skip SPF record check')
    parser.add_argument('--no-dmarc', action='store_true', help='Skip DMARC record check')
    parser.add_argument('--no-dkim', action='store_true', help='Skip DKIM record check')
    parser.add_argument('--no-ssl', action='store_true', help='Skip SSL certificate check')
    parser.add_argument('--compact', action='store_true', help='Print compact JSON (no indentation)')
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    options = ValidationOptions(
        timeout=args.timeout,
        run_mx=not args.no_mx,
        run_spf=not args.no_spf,
        run_dmarc=not args.no_dmarc,
        run_dkim=not args.no_dkim,
        run_ssl=not args.no_ssl,
    )

    result = validate_email_and_domain(args.email, options=options)

    indent = None if args.compact else 2
    json.dump(result.to_dict(), sys.stdout, indent=indent)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
