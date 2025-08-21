import { shuffleArray } from 'foxts/shuffle-array';
import { isRegisterableDomainAlive } from './is-registerable-domain-alive';
import type { RegisterableDomainAliveOptions } from './is-registerable-domain-alive';
import { defaultDnsServers, getDnsClients } from './utils/dns-client';
import asyncRetry from 'async-retry';

export interface DomainAliveOptions extends RegisterableDomainAliveOptions {}

export async function isDomainAlive(domain: string, options: DomainAliveOptions = {}): Promise<boolean> {
  if (
    !(await isRegisterableDomainAlive(domain, options)).alive
  ) {
    return false;
  }

  const {
    dns: dnsOptions = {}
  } = options;

  const {
    dnsServers = defaultDnsServers,
    confirmations: maxConfirmations = 2,
    maxAttempts: _maxAttempts = dnsServers.length,
    retryCount: retries = 3, retryMinTimeout = 1000, retryFactor = 2, retryMaxTimeout
  } = dnsOptions;
  // each server get atmost one attempt, only less no more
  const maxAttempts = Math.min(_maxAttempts, dnsServers.length);
  const shuffledDnsClients = getDnsClients(shuffleArray(dnsServers, { copy: true }));

  const dnsRetryOption: asyncRetry.Options = { retries, minTimeout: retryMinTimeout, maxTimeout: retryMaxTimeout, factor: retryFactor };

  {
    // IPv4
    let attempts = 0;
    let confirmations = 0;

    while (attempts < maxAttempts) {
      if (confirmations >= maxConfirmations) {
        return true;
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
      }
    }
  }

  {
    // IPv6
    let attempts = 0;
    let confirmations = 0;

    while (attempts < maxAttempts) {
      if (confirmations >= maxConfirmations) {
        return true;
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
      }
    }
  }

  // neither A nor AAAA records found
  return false;
}
