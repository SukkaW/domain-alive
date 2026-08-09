export interface DomainAliveReasons {
  readonly INVALID_DOMAIN: 'INVALID_DOMAIN',
  readonly NS_RECORDS: 'NS_RECORDS',
  readonly WHOIS_REGISTERED: 'WHOIS_REGISTERED',
  readonly WHOIS_NOT_REGISTERED: 'WHOIS_NOT_REGISTERED',
  readonly WHOIS_UNSUPPORTED: 'WHOIS_UNSUPPORTED',
  readonly WHOIS_ERROR: 'WHOIS_ERROR',
  readonly A_RECORDS: 'A_RECORDS',
  readonly AAAA_RECORDS: 'AAAA_RECORDS',
  readonly NO_ADDRESS_RECORDS: 'NO_ADDRESS_RECORDS',
  readonly DNS_ERROR: 'DNS_ERROR'
}

export const DOMAIN_ALIVE_REASONS: DomainAliveReasons = Object.freeze({
  INVALID_DOMAIN: 'INVALID_DOMAIN',
  NS_RECORDS: 'NS_RECORDS',
  WHOIS_REGISTERED: 'WHOIS_REGISTERED',
  WHOIS_NOT_REGISTERED: 'WHOIS_NOT_REGISTERED',
  WHOIS_UNSUPPORTED: 'WHOIS_UNSUPPORTED',
  WHOIS_ERROR: 'WHOIS_ERROR',
  A_RECORDS: 'A_RECORDS',
  AAAA_RECORDS: 'AAAA_RECORDS',
  NO_ADDRESS_RECORDS: 'NO_ADDRESS_RECORDS',
  DNS_ERROR: 'DNS_ERROR'
} as const);

export type RegisterableDomainAliveReason =
  | typeof DOMAIN_ALIVE_REASONS.INVALID_DOMAIN
  | typeof DOMAIN_ALIVE_REASONS.NS_RECORDS
  | typeof DOMAIN_ALIVE_REASONS.WHOIS_REGISTERED
  | typeof DOMAIN_ALIVE_REASONS.WHOIS_NOT_REGISTERED
  | typeof DOMAIN_ALIVE_REASONS.WHOIS_UNSUPPORTED
  | typeof DOMAIN_ALIVE_REASONS.WHOIS_ERROR;

export type DomainAliveReason =
  | RegisterableDomainAliveReason
  | typeof DOMAIN_ALIVE_REASONS.A_RECORDS
  | typeof DOMAIN_ALIVE_REASONS.AAAA_RECORDS
  | typeof DOMAIN_ALIVE_REASONS.NO_ADDRESS_RECORDS
  | typeof DOMAIN_ALIVE_REASONS.DNS_ERROR;

export type DomainAliveReasonMessages = Readonly<Record<DomainAliveReason, string>>;

export const DOMAIN_ALIVE_REASON_MESSAGES: DomainAliveReasonMessages = Object.freeze({
  INVALID_DOMAIN: 'No registerable domain could be extracted.',
  NS_RECORDS: 'The registerable domain has confirmed NS records.',
  WHOIS_REGISTERED: 'WHOIS/RDAP data indicates that the registerable domain is registered.',
  WHOIS_NOT_REGISTERED: 'WHOIS/RDAP data indicates that the registerable domain is not registered.',
  WHOIS_UNSUPPORTED: 'WHOIS/RDAP is unsupported for the TLD; the registerable domain is assumed alive.',
  WHOIS_ERROR: 'The WHOIS/RDAP lookup failed; the alive value follows whoisErrorCountAsAlive.',
  A_RECORDS: 'The domain has confirmed A records.',
  AAAA_RECORDS: 'The domain has confirmed AAAA records.',
  NO_ADDRESS_RECORDS: 'The domain has no confirmed A or AAAA records.',
  DNS_ERROR: 'DNS resolver errors prevented A/AAAA confirmation.'
});
