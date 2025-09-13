import { getDomain } from 'tldts';
import { defaultDnsServers, getDnsClients } from './utils/dns-client';
import { toASCII } from 'punycode/';
import { domainHasBeenRegistered } from './utils/whois';
import type { WhoisOptions } from './utils/whois';
import type { DnsOptions } from './utils/dns-client';
import { shuffleArray } from 'foxts/shuffle-array';
import asyncRetry from 'async-retry';
import { cacheApply } from './utils/cache';
import type { CacheImplementation } from './utils/cache';
import { createAsyncMutex } from './utils/mutex';
import debug from 'debug';

const log = debug('domain-alive:is-registerable-domain-alive');
const deadLog = debug('domain-alive:dead-domain');
const errorNsLog = debug('domain-alive:error:ns');

const getRegisterableDomainTldtsOption: Parameters<typeof getDomain>[1] = {
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

export interface RegisterableDomainAliveOptions {
  dns?: DnsOptions,
  whois?: WhoisOptions,
  registerableDomainResultCache?: CacheImplementation<RegisterableDomainAliveResult>
}

export interface RegisterableDomainAliveResult {
  readonly registerableDomain: string | null,
  readonly alive: boolean
}

// a shared null response to decrease GC pressure and increase performance
const sharedNullResponse: RegisterableDomainAliveResult = Object.freeze({
  registerableDomain: null,
  alive: false
});

/**
 * Given any domain, this function extracts the "registerable" part (a.k.a. apex domain or root domain) and checks if that is alive or not.
 *
 * ```ts
 * isRegisterableDomainAlive("sukkaw.github.io"); // this will extract github.io and check that is alive or not
 * ```
 */
export function createRegisterableDomainAliveChecker(options: RegisterableDomainAliveOptions = {}) {
  const {
    dns: dnsOptions = {},
    whois: whoisOptions = {},
    registerableDomainResultCache = new Map<string, RegisterableDomainAliveResult>()
  } = options;

  const {
    dnsServers = defaultDnsServers,
    confirmations: maxConfirmations = 2,
    maxAttempts: _maxAttempts = dnsServers.length,
    retryCount: retries = 3, retryMinTimeout = 1000, retryFactor = 2, retryMaxTimeout = 16000
  } = dnsOptions;

  // each server get atmost one attempt, only less no more
  const maxAttempts = Math.min(_maxAttempts, dnsServers.length);

  const dnsRetryOption: asyncRetry.Options = { retries, minTimeout: retryMinTimeout, maxTimeout: retryMaxTimeout, factor: retryFactor };

  const mutex = createAsyncMutex<RegisterableDomainAliveResult>();

  return async function isRegisterableDomainAlive(domain: string): Promise<RegisterableDomainAliveResult> {
    domain = toASCII(domain);

    return mutex(domain, () => cacheApply(registerableDomainResultCache, domain, async () => {
      // Step 0: we normalize the domain and find the registerable part

      const registerableDomain = getDomain(domain, getRegisterableDomainTldtsOption);

      if (registerableDomain === null) {
        return sharedNullResponse;
      }

      // Step 1: we query NS records first. If there is any NS records, we assume the domain is alive

      /*
; <<>> DiG 9.20.11 <<>> tencentcloud.com NS @1.0.0.1 +tls
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4556
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; PADDING: (362 bytes)
;; QUESTION SECTION:
;tencentcloud.com.           IN  NS

;; AUTHORITY SECTION:
tencentcloud.com.    86400   IN  SOA ns-tel1.qq.com. webmaster.qq.com. 1651110894 300 600 86400 86400

;; Query time: 191 msec
;; SERVER: 1.0.0.1#853(1.0.0.1) (TLS)
;; WHEN: Fri Aug 22 00:26:29 CST 2025
;; MSG SIZE  rcvd: 468
*/
      // dns servers get shuffled every time called
      const shuffledDnsClients = getDnsClients(shuffleArray(dnsServers, { copy: true }));

      let attempts = 0;
      let confirmations = 0;

      while (attempts < maxAttempts) {
        if (confirmations >= maxConfirmations) {
          return { registerableDomain, alive: true };
        }

        const resolve = shuffledDnsClients[attempts % shuffledDnsClients.length];
        try {
          // eslint-disable-next-line no-await-in-loop -- attempt servers one by one
          const resp = await asyncRetry(() => resolve(registerableDomain, 'NS'), dnsRetryOption);
          // if we found any NS records, the domain is alive
          if (resp.answers.length > 0) {
            confirmations++;
          }
        } catch (e) {
          errorNsLog('[NS] %s error %O', domain, e);
        } finally {
          attempts++;

          log('[NS] %s %d %d/%d', domain, confirmations, attempts, maxAttempts);
        }
      }

      // This can only be reached only if we have tried enough DNS servers and not enough satisfactory answers were found
      // In this case, we move on to Step 2.

      // Step 2: we query RDAP whois server
      // This is because some domains are using faulty authoritative nameservers that returns SOA records for NS query
      // Here is NS query for "tencentcloud.com" as an example

      try {
        const registered = await domainHasBeenRegistered(registerableDomain, whoisOptions);

        log('[whois] %s %s', registerableDomain, registered);

        if (!registered) {
          deadLog('[dead] %s %s', '(apex)', registerableDomain);
        }

        return {
          registerableDomain,
          alive: registered
        };
      } catch {
        return {
          registerableDomain,
          alive: whoisOptions.whoisErrorCountAsAlive ?? true
        };
      }
    }));
  };
}
