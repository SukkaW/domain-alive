import { shuffleArray } from 'foxts/shuffle-array';
import { createRegisterableDomainAliveChecker } from './is-registerable-domain-alive';
import type { RegisterableDomainAliveOptions, RegisterableDomainAliveResult } from './is-registerable-domain-alive';
import { defaultDnsServers, getDnsClients } from './utils/dns-client';
import { asyncRetry } from 'foxts/async-retry';
import type { AsyncRetryOptions } from 'foxts/async-retry';
import { extractErrorMessage } from 'foxts/extract-error-message';
import { cacheApply } from './utils/cache';
import type { CacheImplementation } from './utils/cache';
import { createAsyncMutex } from './utils/mutex';
import debug from 'debug';
import { domainToASCII } from 'url';
import type { DecodedPacket } from 'dns-packet';
import { DOMAIN_ALIVE_REASON_MESSAGES, DOMAIN_ALIVE_REASONS } from './reason';
import type { DomainAliveReason } from './reason';

const log = debug('domain-alive:is-domain-alive');
const deadLog = debug('domain-alive:dead-domain');
const errorLog = debug('domain-alive:error:dns');

export interface DomainAliveOptions extends RegisterableDomainAliveOptions {
  resultCache?: CacheImplementation<DomainAliveResult>
}

export interface DomainAliveResult {
  readonly registerableDomain: string | null,
  readonly registerableDomainAlive: boolean,
  readonly alive: boolean,
  /** Machine-readable explanation for the `alive` value. */
  readonly reason: DomainAliveReason
}

const sharedNullishResult: DomainAliveResult = Object.freeze({
  registerableDomain: null,
  registerableDomainAlive: false,
  alive: false,
  reason: DOMAIN_ALIVE_REASONS.INVALID_DOMAIN
});

export function createDomainAliveChecker(options: DomainAliveOptions = {}) {
  const {
    dns: dnsOptions = {},
    resultCache = new Map<string, DomainAliveResult>()
  } = options;

  options.registerableDomainResultCache ??= new Map<string, RegisterableDomainAliveResult>();

  const isRegisterableDomainAlive = createRegisterableDomainAliveChecker(options);

  const {
    dnsServers = defaultDnsServers,
    confirmations: maxConfirmations = 2,
    maxAttempts: _maxAttempts = dnsServers.length,
    retryCount: retries = 3, retryMinTimeout = 1000, retryFactor = 2, retryMaxTimeout = 16000,
    customFetchForDoH
  } = dnsOptions;

  // each server get atmost one attempt, only less no more
  const maxAttempts = Math.min(_maxAttempts, dnsServers.length);

  const dnsRetryOption: AsyncRetryOptions = { retries, minTimeout: retryMinTimeout, maxTimeout: retryMaxTimeout, factor: retryFactor };

  const mutex = createAsyncMutex<DomainAliveResult>();
  const dnsClients = getDnsClients(dnsServers, customFetchForDoH);

  return async function isDomainAlive(domain: string): Promise<DomainAliveResult> {
    domain = domainToASCII(domain);

    const registerableDomainAliveResult = await isRegisterableDomainAlive(domain);

    if (registerableDomainAliveResult.registerableDomain === null) {
      return sharedNullishResult;
    }

    if (!registerableDomainAliveResult.alive) {
      return {
        registerableDomain: registerableDomainAliveResult.registerableDomain,
        registerableDomainAlive: false,
        alive: false,
        reason: registerableDomainAliveResult.reason
      };
    }

    // If the domain has no subdomain, we don't query A/AAAA
    if (registerableDomainAliveResult.registerableDomain === domain) {
      return {
        registerableDomain: registerableDomainAliveResult.registerableDomain,
        registerableDomainAlive: registerableDomainAliveResult.alive,
        alive: registerableDomainAliveResult.alive,
        reason: registerableDomainAliveResult.reason
      };
    }

    return mutex(domain, () => cacheApply(resultCache, domain, async () => {
      // shuffle every time is called
      const shuffledDnsClients = shuffleArray(dnsClients, { copy: true });

      /**
       * Sweep through the (shuffled) DNS servers one-by-one for the given rrtype.
       *
       * On a per-server error (network failure, decode error, etc.) we immediately
       * advance to the *next* server instead of retrying the same one. Only when an
       * entire sweep fails to reach `maxConfirmations` *and* at least one server
       * errored do we throw, letting the outer `asyncRetry` re-run the whole sweep
       * with backoff. A clean sweep (every server answered, just not enough positive
       * answers) resolves to its confirmation count without triggering a retry.
       */
      const sweep = async (rrtype: 'A' | 'AAAA'): Promise<number> => {
        let attempts = 0;
        let confirmations = 0;
        let errored = 0;

        while (attempts < maxAttempts) {
          if (confirmations >= maxConfirmations) {
            break;
          }

          const dnsClient = shuffledDnsClients[attempts % shuffledDnsClients.length];
          try {
            // @ts-expect-error -- force DoHClient to use wireformat over json format
            // eslint-disable-next-line no-await-in-loop -- attempt servers one by one
            const resp = (await dnsClient.lookup(domain, { rrtype, decode: true, json: false })) as DecodedPacket;
            // if we found any answers, count it as one confirmation
            if (resp.answers && resp.answers.length > 0) {
              confirmations++;
            }
          } catch (e) {
            errored++;
            const errorMessage = extractErrorMessage(e, true, false) || 'unknown error';
            errorLog('[%s] %s error (%s) %s', rrtype, domain, dnsClient.server, errorMessage);
          } finally {
            attempts++;

            log('[%s] %s %d %d/%d', rrtype, domain, confirmations, attempts, maxAttempts);
          }
        }

        // The sweep could not confirm and at least one server errored: the result is
        // inconclusive rather than a genuine negative, so throw to let the outer
        // `asyncRetry` re-run the whole rotation with backoff.
        if (confirmations < maxConfirmations && errored > 0) {
          throw new Error(`[${rrtype}] ${domain}: ${errored} server(s) errored, only ${confirmations}/${maxConfirmations} confirmation(s)`);
        }

        return confirmations;
      };

      // IPv4
      let confirmations = 0;
      let dnsErrored = false;
      try {
        confirmations = await asyncRetry(() => sweep('A'), dnsRetryOption);
      } catch (e) {
        dnsErrored = true;
        const errorMessage = extractErrorMessage(e, true, false) || 'unknown error';
        errorLog('[A] %s all servers failed after retries: %s', domain, errorMessage);
      }

      if (confirmations >= maxConfirmations) {
        return {
          registerableDomain: registerableDomainAliveResult.registerableDomain,
          registerableDomainAlive: registerableDomainAliveResult.alive,
          alive: true,
          reason: DOMAIN_ALIVE_REASONS.A_RECORDS
        };
      }

      // IPv6
      confirmations = 0;
      try {
        confirmations = await asyncRetry(() => sweep('AAAA'), dnsRetryOption);
      } catch (e) {
        dnsErrored = true;
        const errorMessage = extractErrorMessage(e, true, false) || 'unknown error';
        errorLog('[AAAA] %s all servers failed after retries: %s', domain, errorMessage);
      }

      if (confirmations >= maxConfirmations) {
        return {
          registerableDomain: registerableDomainAliveResult.registerableDomain,
          registerableDomainAlive: registerableDomainAliveResult.alive,
          alive: true,
          reason: DOMAIN_ALIVE_REASONS.AAAA_RECORDS
        };
      }

      const reason = dnsErrored ? DOMAIN_ALIVE_REASONS.DNS_ERROR : DOMAIN_ALIVE_REASONS.NO_ADDRESS_RECORDS;

      deadLog('[%s] %s: %s', reason, domain, DOMAIN_ALIVE_REASON_MESSAGES[reason]);

      return {
        registerableDomain: registerableDomainAliveResult.registerableDomain,
        registerableDomainAlive: registerableDomainAliveResult.alive,
        alive: false,
        reason
      };
    }));
  };
}
