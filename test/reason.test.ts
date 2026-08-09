import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Buffer } from 'node:buffer';
import {
  createDomainAliveChecker,
  createRegisterableDomainAliveChecker,
  DOMAIN_ALIVE_REASON_MESSAGES,
  DOMAIN_ALIVE_REASONS
} from '../src';
import type { RegisterableDomainAliveResult } from '../src';

const RR_TYPE = {
  A: 1,
  NS: 2,
  AAAA: 28
} as const;

const mockDoHAgent = {
  dispatch() {
    throw new Error('The mock fetch should handle every DoH request');
  }
};

function getQuestionType(query: Buffer): number {
  let offset = 12;
  while (query[offset] !== 0) {
    offset += query[offset] + 1;
  }
  return query.readUInt16BE(offset + 1);
}

function createDnsResponse(query: Buffer, includeAnswer: boolean): Uint8Array {
  const responseHeaderAndQuestion = Buffer.from(query);
  responseHeaderAndQuestion[2] = 0x81;
  responseHeaderAndQuestion[3] = 0x80;

  if (!includeAnswer) {
    return responseHeaderAndQuestion;
  }

  responseHeaderAndQuestion.writeUInt16BE(1, 6);
  const rrtype = getQuestionType(query);
  let rdata: Buffer;
  if (rrtype === RR_TYPE.A) {
    rdata = Buffer.from([192, 0, 2, 1]);
  } else if (rrtype === RR_TYPE.AAAA) {
    rdata = Buffer.from([0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
  } else {
    rdata = Buffer.from([0xC0, 0x0C]);
  }
  const answer = Buffer.allocUnsafe(12 + rdata.length);

  answer.writeUInt16BE(0xC00C, 0);
  answer.writeUInt16BE(rrtype, 2);
  answer.writeUInt16BE(1, 4);
  answer.writeUInt32BE(60, 6);
  answer.writeUInt16BE(rdata.length, 10);
  rdata.copy(answer, 12);

  return Buffer.concat([responseHeaderAndQuestion, answer]);
}

function createDnsFetch(positiveTypes: ReadonlySet<number>, errorTypes: ReadonlySet<number> = new Set()): typeof fetch {
  return async (input) => {
    const request = input instanceof Request ? input : new Request(input);
    const query = Buffer.from(await request.arrayBuffer());
    const rrtype = getQuestionType(query);

    if (errorTypes.has(rrtype)) {
      throw new Error('mock resolver failure');
    }

    return new Response(createDnsResponse(query, positiveTypes.has(rrtype)), {
      headers: { 'content-type': 'application/dns-message' }
    });
  };
}

function createDnsOptions(customFetchForDoH: typeof fetch) {
  return {
    dnsServers: ['https://resolver.test/dns-query'],
    confirmations: 1,
    maxAttempts: 1,
    retryCount: 0,
    customFetchForDoH,
    customAgentForDoH: mockDoHAgent
  };
}

test('exports one human-readable message for every reason', () => {
  assert.deepEqual(
    Object.keys(DOMAIN_ALIVE_REASON_MESSAGES).sort(),
    Object.values(DOMAIN_ALIVE_REASONS).sort()
  );
  assert.equal(
    DOMAIN_ALIVE_REASON_MESSAGES[DOMAIN_ALIVE_REASONS.A_RECORDS],
    'The domain has confirmed A records.'
  );
  assert.equal(Object.isFrozen(DOMAIN_ALIVE_REASON_MESSAGES), true);
});

test('reports invalid domains', async () => {
  const result = await createDomainAliveChecker({
    dns: { customAgentForDoH: mockDoHAgent }
  })('');

  assert.deepEqual(result, {
    registerableDomain: null,
    registerableDomainAlive: false,
    alive: false,
    reason: DOMAIN_ALIVE_REASONS.INVALID_DOMAIN
  });
});

test('reports NS records for a registerable domain', async () => {
  const customFetch = createDnsFetch(new Set([RR_TYPE.NS]));
  const result = await createRegisterableDomainAliveChecker({ dns: createDnsOptions(customFetch) })('example.com');

  assert.deepEqual(result, {
    registerableDomain: 'example.com',
    alive: true,
    reason: DOMAIN_ALIVE_REASONS.NS_RECORDS
  });
});

test('propagates a dead registerable-domain reason', async () => {
  const domain = 'www.example.com';
  const registerableDomainResultCache = new Map<string, RegisterableDomainAliveResult>([
    [domain, {
      registerableDomain: 'example.com',
      alive: false,
      reason: DOMAIN_ALIVE_REASONS.WHOIS_NOT_REGISTERED
    }]
  ]);
  const result = await createDomainAliveChecker({
    dns: { customAgentForDoH: mockDoHAgent },
    registerableDomainResultCache
  })(domain);

  assert.deepEqual(result, {
    registerableDomain: 'example.com',
    registerableDomainAlive: false,
    alive: false,
    reason: DOMAIN_ALIVE_REASONS.WHOIS_NOT_REGISTERED
  });
});

test('reports A records for a subdomain', async () => {
  const customFetch = createDnsFetch(new Set([RR_TYPE.NS, RR_TYPE.A]));
  const result = await createDomainAliveChecker({ dns: createDnsOptions(customFetch) })('www.example.com');

  assert.equal(result.alive, true);
  assert.equal(result.reason, DOMAIN_ALIVE_REASONS.A_RECORDS);
});

test('reports AAAA records for a subdomain without A records', async () => {
  const customFetch = createDnsFetch(new Set([RR_TYPE.NS, RR_TYPE.AAAA]));
  const result = await createDomainAliveChecker({ dns: createDnsOptions(customFetch) })('www.example.com');

  assert.equal(result.alive, true);
  assert.equal(result.reason, DOMAIN_ALIVE_REASONS.AAAA_RECORDS);
});

test('distinguishes missing address records from DNS errors', async () => {
  const noAddressFetch = createDnsFetch(new Set([RR_TYPE.NS]));
  const noAddressResult = await createDomainAliveChecker({ dns: createDnsOptions(noAddressFetch) })('www.example.com');

  assert.equal(noAddressResult.alive, false);
  assert.equal(noAddressResult.reason, DOMAIN_ALIVE_REASONS.NO_ADDRESS_RECORDS);

  const dnsErrorFetch = createDnsFetch(
    new Set([RR_TYPE.NS]),
    new Set([RR_TYPE.A, RR_TYPE.AAAA])
  );
  const dnsErrorResult = await createDomainAliveChecker({ dns: createDnsOptions(dnsErrorFetch) })('www.example.com');

  assert.equal(dnsErrorResult.alive, false);
  assert.equal(dnsErrorResult.reason, DOMAIN_ALIVE_REASONS.DNS_ERROR);
});
