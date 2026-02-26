from dataclasses import asdict, dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dns.resolver import Resolver


@dataclass
class SSLCertInfo:  # pylint: disable=too-many-instance-attributes
    host: str
    resolved_ip: str
    tls_version: str
    issued_to: str | None
    issued_o: str | None
    issuer_c: str | None
    issuer_o: str | None
    issuer_ou: str | None
    issuer_cn: str | None
    cert_sn: str
    cert_alg: str
    cert_ver: int
    cert_sans: list[str]
    cert_exp: bool
    cert_age: int
    valid_from: str
    valid_till: str
    validity_days: int
    days_left: int


@dataclass
class SSLVerificationReport:
    valid: bool
    info: SSLCertInfo | None


@dataclass
class MXVerificationReport:
    valid: bool
    records: list[str] | None


class CatchAllSecurityLevel(str, Enum):
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    NONE = 'none'


@dataclass
class SPFRecordInfo:
    record: str
    catchall: CatchAllSecurityLevel | None
    deprecated_mechanism: bool
    ip_addresses: bool
    includes: list[str]


@dataclass
class SPFVerificationReport:
    valid: bool
    info: SPFRecordInfo | None


@dataclass
class DMARCVerificationReport:
    valid: bool
    record: str | None


@dataclass
class DKIMVerificationReport:
    valid: bool
    record: str | None


# Common DKIM selectors used for discovery (bounded lookups to avoid abuse).
DKIM_SELECTORS: list[str] = [
    # --- Google Workspace (date-based rotation keys) ---
    '20230601',
    '20221208',
    '20210112',
    '20161025',
    '20150623',
    '20120113',
    'google',
    # --- Microsoft / Office 365 ---
    'selector1',
    'selector2',
    'selector3',
    's1-microsoft',
    's2-microsoft',
    'k2',
    'k3',
    # --- Amazon SES ---
    'amazonses',
    # --- SendGrid ---
    'sendgrid',
    'smtpapi',
    # --- Mailchimp / Mandrill ---
    'mandrill',
    'k1',
    # --- Fastmail ---
    'fm1',
    'fm2',
    'fm3',
    'mesmtp',
    # --- Postmark ---
    'pm',
    'postmark',
    # --- Mailjet ---
    'mailjet',
    # --- SparkPost ---
    'sparkpost',
    # --- Campaign Monitor ---
    'cm',
    # --- Protonmail ---
    'protonmail',
    # --- Rackspace ---
    'rackspace1',
    'rackspace2',
    # --- Zoho ---
    'zoho',
    'zmail',
    # --- Yahoo / Oath (key-size selectors) ---
    's1024',
    's2048',
    # --- Everlytic ---
    'everlytickey1',
    'everlytickey2',
    # --- TurboSMTP ---
    'turbo-smtp',
    # --- MxVault ---
    'mxvault',
    # --- Generic / widely seen in the wild ---
    'a1',
    'a2',
    'atl01',
    'atl02',
    'default',
    'dk',
    'dk1',
    'dk2',
    'dkim',
    'dkim1',
    'dkim2',
    'dkim3',
    'e1',
    'e2',
    'em1',
    'em2',
    'email',
    'hs1',
    'hs2',
    'key1',
    'key2',
    'krs',
    'm1',
    'm2',
    'mail',
    'mail2',
    'mailo',
    'mg',
    'mta',
    'mx',
    's1',
    's2',
    'sf1',
    'sf2',
    'sig1',
    'smtp',
    'smtp2',
]

# Policy record markers for TXT lookups.
SPF_MARKER = 'v=spf1'
DMARC_MARKER = 'v=DMARC1'
DKIM_MARKER = 'v=DKIM1'


@dataclass
class ValidationOptions:
    timeout: int = 5
    run_mx: bool = True
    run_spf: bool = True
    run_dmarc: bool = True
    run_dkim: bool = True
    run_ssl: bool = True
    resolver: 'Resolver | None' = None


@dataclass
class EmailDomainValidationResult:  # pylint: disable=too-many-instance-attributes
    email_valid: bool
    normalized_email: str | None
    domain: str
    mx: MXVerificationReport
    spf: SPFVerificationReport
    dmarc: DMARCVerificationReport
    dkim: DKIMVerificationReport
    ssl: SSLVerificationReport

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
