import { toASCII } from 'punycode/';
import { shuffleArray } from 'foxts/shuffle-array';
import { createRegisterableDomainAliveChecker } from './is-registerable-domain-alive';
import type { RegisterableDomainAliveOptions, RegisterableDomainAliveResult } from './is-registerable-domain-alive';
import { defaultDnsServers, getDnsClients } from './utils/dns-client';
import asyncRetry from 'async-retry';
import { cacheApply } from './utils/cache';
import type { CacheImplementation } from './utils/cache';
import { createAsyncMutex } from './utils/mutex';
import debug from 'debug';

const log = debug('domain-alive:is-domain-alive');

export interface DomainAliveOptions extends RegisterableDomainAliveOptions {
  resultCache?: CacheImplementation<DomainAliveResult>
}

export interface DomainAliveResult {
  readonly registerableDomain: string | null,
  readonly registerableDomainAlive: boolean,
  readonly alive: boolean
}

const sharedNullishResult: DomainAliveResult = Object.freeze({
  registerableDomain: null,
  registerableDomainAlive: false,
  alive: false
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
    retryCount: retries = 3, retryMinTimeout = 1000, retryFactor = 2, retryMaxTimeout
  } = dnsOptions;

  // each server get atmost one attempt, only less no more
  const maxAttempts = Math.min(_maxAttempts, dnsServers.length);

  const dnsRetryOption: asyncRetry.Options = { retries, minTimeout: retryMinTimeout, maxTimeout: retryMaxTimeout, factor: retryFactor };

  const mutex = createAsyncMutex<DomainAliveResult>();

  return async function isDomainAlive(domain: string): Promise<DomainAliveResult> {
    domain = toASCII(domain);

    const registerableDomainAliveResult = await isRegisterableDomainAlive(domain);

    if (registerableDomainAliveResult.registerableDomain === null) {
      return sharedNullishResult;
    }

    if (!registerableDomainAliveResult.alive) {
      return {
        registerableDomain: registerableDomainAliveResult.registerableDomain,
        registerableDomainAlive: false,
        alive: false
      };
    }

    // If the domain has no subdomain, we don't query A/AAAA
    if (registerableDomainAliveResult.registerableDomain === domain) {
      return {
        registerableDomain: registerableDomainAliveResult.registerableDomain,
        registerableDomainAlive: registerableDomainAliveResult.alive,
        alive: registerableDomainAliveResult.alive
      };
    }

    return mutex(domain, () => cacheApply(resultCache, domain, async () => {
      // shuffle every time is called
      const shuffledDnsClients = getDnsClients(shuffleArray(dnsServers, { copy: true }));

      {
      // IPv4
        let attempts = 0;
        let confirmations = 0;

        while (attempts < maxAttempts) {
          if (confirmations >= maxConfirmations) {
            log('[status] %s %s', domain, true);

            return {
              registerableDomain: registerableDomainAliveResult.registerableDomain,
              registerableDomainAlive: registerableDomainAliveResult.alive,
              alive: true
            };
          }

          const resolve = shuffledDnsClients[attempts % shuffledDnsClients.length];
          try {
          // eslint-disable-next-line no-await-in-loop -- attempt servers one by one
            const resp = await asyncRetry(() => resolve(domain, 'A'), dnsRetryOption);
            // if we found any NS records, the domain is alive
            if (resp.answers.length > 0) {
              confirmations++;
            }
          } finally {
            attempts++;

            log('[A] %s %d %d/%d', domain, confirmations, attempts, maxAttempts);
          }
        }
      }

      {
      // IPv6
        let attempts = 0;
        let confirmations = 0;

        while (attempts < maxAttempts) {
          if (confirmations >= maxConfirmations) {
            log('[status] %s %s', domain, true);

            return {
              registerableDomain: registerableDomainAliveResult.registerableDomain,
              registerableDomainAlive: registerableDomainAliveResult.alive,
              alive: true
            };
          }

          const resolve = shuffledDnsClients[attempts % shuffledDnsClients.length];
          try {
          // eslint-disable-next-line no-await-in-loop -- attempt servers one by one
            const resp = await asyncRetry(() => resolve(domain, 'AAAA'), dnsRetryOption);
            // if we found any NS records, the domain is alive
            if (resp.answers.length > 0) {
              confirmations++;
            }
          } finally {
            attempts++;

            log('[AAAA] %s %d %d/%d', domain, confirmations, attempts, maxAttempts);
          }
        }
      }

      // neither A nor AAAA records found
      log('[status] %s %s', domain, false);

      return {
        registerableDomain: registerableDomainAliveResult.registerableDomain,
        registerableDomainAlive: registerableDomainAliveResult.alive,
        alive: false
      };
    }));
  };
}
