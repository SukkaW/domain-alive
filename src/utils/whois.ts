import { getPublicSuffix } from 'tldts';
import asyncRetry from 'async-retry';
import { whoisDomain as whoiserDomain } from 'whoiser';
import { createRetrieKeywordFilter as createKeywordFilter } from 'foxts/retrie';
import { extractErrorMessage } from 'foxts/extract-error-message';
import debug from 'debug';

const log = debug('domain-alive:whois');
const errorLog = debug('domain-alive:error:whois');

export interface WhoisOptions {
  timeout?: number,

  retryCount?: number,
  retryFactor?: number,
  retryMinTimeout?: number,
  retryMaxTimeout?: number,

  family?: 4 | 6 | (number & {}),
  follow?: number,
  /**
     * A mapping of WHOIS servers for different TLDs. This in case you want to supply your own more up-to-date
     * whois server mapping from other source. We will merge yours on top of our built-in mapping.
     *
     * ```ts
     * {
     *   "com": "whois.verisign-grs.com",
     *   "org": "whois.pir.org",
     *   "net": "whois.verisign-grs.com"
     * }
     * ```
     *
     * Some public whois server mapping source:
     *
     * - Fetch the mapping text file from the source code of "WHOIS(1)" and processed it into a JSON:
     *   - https://cdn.jsdelivr.net/gh/rfc1036/whois@next/tld_serv_list (recommended)
     *   - https://raw.githubusercontent.com/rfc1036/whois/next/tld_serv_list
     * - Install the `whois-servers-list` package from "WooMai/whois-servers" project through npm, then update regularly
     * - Fetch the JSON directly from "WooMai/whois-servers" project through one of the following URLs:
     *   - https://cdn.jsdelivr.net/npm/whois-servers-list@latest/list.json (recommended)
     *   - https://raw.githubusercontent.com/WooMai/whois-servers/master/list.json
     *   - https://unpkg.com/whois-servers-list@latest/list.json
     *   - https://esm.sh/whois-servers-list@latest/list.json
     */
  customWhoisServersMapping?: { [tldWithoutDot: string]: string },

  /**
   * WHOIS/RDAP query can easily failed: either the RDAP server is down, or the TLD doesn't support WHOIS/RDAP in the first place
   * The default value is `true` since WHOIS/RDAP is fragile, can easily fail or even not exist.
   */
  whoisErrorCountAsAlive?: boolean
}

const getIcannTldOptions: Parameters<typeof getPublicSuffix>[1] = {
  allowIcannDomains: true,
  // we want to extract "github.io" out of "sukkaw.github.io" even though github.io is in the
  // public suffix list, only "github.io" part is registerable
  allowPrivateDomains: false,
  // tldts can extract a domain from URL. Though technically we only accepts valid FQDN, this
  // is still a nice to have feature that can be helpful with arbitrary URLs. Also we don't
  // care about performance boost here, the overhead would be networking requests of RDAP and DNS
  extractHostname: true,
  // We are working with FQDN here, some hostname validations don't apply
  validateHostname: false,
  detectIp: true,
  mixedInputs: true
};

const cacheTldWhoisServer: Record<string, string> = {
  // very common ccTLDs we just hardcoded them
  com: 'whois.verisign-grs.com',
  net: 'whois.verisign-grs.com',
  org: 'whois.pir.org',

  // ccTLDs
  ai: 'whois.nic.ai',
  au: 'whois.auda.org.au',
  co: 'whois.nic.co',
  ca: 'whois.cira.ca',
  do: 'whois.nic.do',
  eu: 'whois.eu',
  gi: 'whois2.afilias-grs.net',
  gl: 'whois.nic.gl',
  in: 'whois.registry.in',
  io: 'whois.nic.io',
  it: 'whois.nic.it',
  lc: 'whois.afilias-grs.info',
  me: 'whois.nic.me',
  ro: 'whois.rotld.ro',
  rs: 'whois.rnids.rs',
  so: 'whois.nic.so',
  tr: 'whois.nic.tr',
  us: 'whois.nic.us',
  vc: 'whois.identity.digital',
  ws: 'whois.website.ws',
  //
  bf: 'whois.registre.bf',
  bh: 'whois.nic.bh',
  bm: 'whois.afilias-srs.net',
  bz: 'whois.afilias-grs.info',
  cd: 'whois.nic.cd',
  cm: 'whois.netcom.cm',
  gh: 'whois.nic.gh',
  kw: 'whois.nic.kw',
  lk: 'whois.nic.lk',
  mt: 'whois.nic.org.mt',
  ps: 'whois.pnina.ps',
  sd: 'whois.sdnic.sd',
  ga: 'whois.nic.ga',
  'xn--fzc2c9e2c': 'whois.nic.lk',
  'xn--pgbs0dh': 'whois.ati.tn',
  'xn--wgbh1c': 'whois.dotmasr.eg',
  'xn--xkc2al3hye2a': 'whois.nic.lk',

  // gTLDs
  agency: 'whois.nic.agency',
  app: 'whois.nic.google',
  biz: 'whois.nic.biz',
  country: 'whois.uniregistry.net', // hardcoded because `whois.iana.org` sometimes returns 'whois.uniregistry.net' or 'whois.nic.country'
  dev: 'whois.nic.google',
  house: 'whois.nic.house',
  health: 'whois.nic.health',
  info: 'whois.nic.info',
  link: 'whois.uniregistry.net',
  live: 'whois.nic.live',
  nyc: 'whois.nic.nyc',
  one: 'whois.nic.one',
  online: 'whois.nic.online',
  shop: 'whois.nic.shop',
  site: 'whois.nic.site',
  xyz: 'whois.nic.xyz',
  sl: 'whois.nic.sl',
  tube: 'whois.nic.tube'
};

export class WhoisQueryError extends Error {
  name = 'WhoisQueryError';
  constructor(domain: string, rawError: unknown) {
    super(`WHOIS query failed for domain: ${domain}`);
    this.cause = rawError;
  }
}

const whoiserTLDNotSupportedSymbol = Symbol('"whoiser" library returns "TLD not supported" error');
const whoiserNoWhoisSymbol = Symbol('"whoiser" library returns "No WHOIS data found" error');

/**
 * Given a registerable domain, find its registration information from RDAP/WHOIS.
 *
 * We expect this function to only be called within `isRegisterableDomainAlive`. If you are trying
 * to do this yourself, please implement the necessary extraction first, we recommend using both
 * `punycode` & `tldts` library, which we also use in the `isRegisterableDomainAlive` function.
 */
export async function domainHasBeenRegistered(registerableDomain: string, options: WhoisOptions = {}): Promise<boolean> {
  const tld = getPublicSuffix(registerableDomain, getIcannTldOptions);
  if (!tld) {
    throw new TypeError('[domain-alive] Can\'t determine the TLD of the domain: "' + registerableDomain + '", thus we can\'t run WHOIS query');
  }

  const cachedWhoisServer = cacheTldWhoisServer[tld] as string | undefined;
  const { whoisErrorCountAsAlive = true, timeout = 5000, retryCount: retries = 3, retryMinTimeout = 1000, retryFactor = 2, retryMaxTimeout = 16000 } = options;

  // hoist options above
  const retryOption: asyncRetry.Options = { retries, minTimeout: retryMinTimeout, maxTimeout: retryMaxTimeout, factor: retryFactor };

  let whois;
  try {
    whois = await asyncRetry<typeof whoiserTLDNotSupportedSymbol | typeof whoiserNoWhoisSymbol | object>(
      (bail) => whoiserDomain(
        registerableDomain,
        { raw: true, timeout, host: cachedWhoisServer || undefined }
      ).catch((error: unknown) => {
        // TODO: wait for "whoiser" library to expose special error types.
        const errorMessage = extractErrorMessage(error);
        if (errorMessage) {
          if (
            // https://github.com/LayeredStudio/whoiser/blob/3f103843a198468eccef5a9d5a72dd82fbe5316c/src/whoiser.ts#L176
            errorMessage.includes('TLD for "') && errorMessage.includes('" not supported')
          ) {
            return whoiserTLDNotSupportedSymbol;
          }

          if (
            // https://github.com/LayeredStudio/whoiser/blob/3f103843a198468eccef5a9d5a72dd82fbe5316c/src/utils.ts#L36
            (errorMessage.includes('Invalid TLD "'))
            // https://github.com/LayeredStudio/whoiser/blob/3f103843a198468eccef5a9d5a72dd82fbe5316c/src/whoiser.ts#L103
            || (errorMessage.includes('TLD "') && errorMessage.includes('" not found'))
          ) {
            bail(new WhoisQueryError(registerableDomain, error));
            // https://github.com/LayeredStudio/whoiser/blob/3f103843a198468eccef5a9d5a72dd82fbe5316c/src/parsers.ts#L28
          } else if (errorMessage.includes('No WHOIS data found')) {
            return whoiserNoWhoisSymbol; // we will handle this later
          }
        }

        // other errors we just re-throw to retry
        throw error;
      }),
      retryOption
    );
  } catch (e) {
    errorLog('[whois] %s %O', registerableDomain, e);

    return whoisErrorCountAsAlive;
  }

  if (whois === whoiserTLDNotSupportedSymbol) {
    // If TLD doesn't support WHOIS/RDAP, we have no choice but to assume it's registered
    return true;
  }

  if (whois === whoiserNoWhoisSymbol) {
    // If "No WHOIS data found" is returned, the domain must not exist
    return false;
  }

  // TODO: due to https://github.com/LayeredStudio/whoiser/issues/117, we can't trust the "whoiser" parsed object
  // Instead we made our own naive detection based on raw output
  return walkWhois(whois);
}

// TODO: this is a workaround for https://github.com/LayeredStudio/whoiser/issues/117
const whoisNotFoundKeywordTest = createKeywordFilter([
  'no match for',
  'does not exist',
  'not found',
  'no found',
  'no entries',
  'no data found',
  'is available for registration',
  'currently available for application',
  'no matching record',
  'no information available about domain name',
  'not been registered',
  'no match!!',
  'status: available',
  ' is free',
  'no object found',
  'nothing found',
  'status: free',
  // 'pendingdelete',
  ' has been blocked by '
]);
// whois server can redirect, so whoiser might/will get info from multiple whois servers
// some servers (like TLD whois servers) might have cached/outdated results
// we can only make sure a domain is alive once all response from all whois servers demonstrate so
function walkWhois(whois: object): boolean {
  let whoisIsEmpty = true;

  if ('__raw' in whois && typeof whois.__raw === 'string') {
    const lines = whois.__raw.trim().toLowerCase().replaceAll(/[\t ]+/g, ' ').split(/\r?\n/);

    for (const line of lines) {
      if (whoisNotFoundKeywordTest(line)) {
        log('[whois] line %s, %O', line, whois);
        return false;
      }
    }
  }

  // so we can't determine if the domain has been registered or not, that's OK, we can check the referrer/follow/redirected whois output.
  for (const key in whois) {
    if (Object.hasOwn(whois, key)) {
      whoisIsEmpty = false;

      if (key === '__raw') { // skip
        continue;
      }

      const value: unknown = (whois as any)[key];

      if (
        value && typeof value === 'object'
        && !Array.isArray(value) // only known array type are "Name Server", "Domain Status" and "text"
        // we can skip all these properties since we already match against __raw previously
      ) {
        if (walkWhois(value)) {
          return true;
        }
        continue;
      }
    }
  }

  log('[whois] %O', whois);

  return !whoisIsEmpty;
}
