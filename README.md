# domain-alive

A Node.js library for checking if an FQDN (Fully Qualified Domain Name) is alive or not.

## Installation

```bash
npm install domain-alive
yarn add domain-alive
pnpm add domain-alive
```

## Usage

```ts
import { createDomainAliveChecker } from 'domain-alive';

const isDomainAlive = createDomainAliveChecker();

(async () => {
  await isDomainAlive('example.com'); // true
})();
```

You can easily customize the dns servers (UDP, TCP, DoH, DoT are supported), pre-cached/pre-populated `Domain TLD -> WHOIS/RDAP server` mapping, retry behaviors, etc., see "Advanced Usage" section below and the TypeScript definitions for all the options.

You can also bring a cache implementation as well:

```ts
import { createDomainAliveChcker } from 'domain-alive';

// There are two separate caches: one for the overall domain alive status and one for the alive status of the "registerable part" of the domain.
const isDomainAlive = createDomainAliveChcker({
  resultCache: new Map(),
  registerableDomainResultCache: new Map()
});
```

## Detect Algorithm

The library uses a combination techniques of `NS` records, WHOIS lookups, `A/AAAA` records to determine if a domain is alive. The detection process involves the following steps:

1. Check if the the "registerable part" of the domain (a.k.a. apex domain or root domain) has any `NS` records.
  - The specified DNS servers will be shuffled, then being attempted. On each attempt, the query would be retried if any error occurs. If any `NS` record is found, a confirmation is made.
  - If confirmations reach the specified threshold (default being `2`), proceed to the `step 3`.
  - If there are not enough confirmations before reaching the maximum attempts, proceed to the `step 2`.
2. Check the registration status of the "registerable part" of the domain via WHOIS/RDAP.
  - If the domain's TLD doesn't support WHOIS, we will not be able to determine its registration status, proceed to the `step 3`.
  - Due to how fragile the WHOIS/RDAP server could be (e.g. reaching rate limits, or the TLD doesn't support WHOIS at all), by default if the WHOIS lookup failed, proceed to the `step 3`.
  - If the WHOIS lookup succeeded, then the WHOIS information will be checked to determine the registration status. If the domain is considered registered, proceed to the `step 3`, otherwise the domain is considered dead.
3. Check if the domain has subdomain or not.
  - If the domain has no subdomain, i.e. the "registerable part" part of the domain is the same as the full domain, no further checks are performed and the domain is considered alive.
  - If the domain has subdomains, proceed to the `step 4`.
4. Check if the domain has any `A` records. The DNS resolving algorithm is similar to the `step 1`.
  - If any `A` record is found, the domain is considered alive.
  - If no `A` record is found, proceed to the `step 5`.
5. Check if the domain has any `AAAA` records. The DNS resolving algorithm is similar to the `step 1` and `step 4`.
  - If any `AAAA` record is found, the domain is considered alive.
  - If no `AAAA` record is found, the domain is considered dead.

Many default behavior can be customized via options. See "Advanced Usage" section below and the TypeScript definitions for all the options.

## Advanced Usage

```ts
import { isDomainAlive } from 'domain-alive';

const options = {
  dns: {
    /**
     * Suported formats:
     *
     * ```ts
     * [
     *   '1.0.0.1', // regular DNS (over UDP)
     *   '208.67.222.222:443', // regular DNS (over UDP) via different port
     *   'udp://1.0.0.1', // regular DNS (over UDP)
     *   'tcp://1.0.0.1', // regular DNS, but over TCP
     *   'tcp://208.67.222.222:443', // regular DNS, but over TCP via different port
     *   'tls://1.0.0.1', // DNS over TLS
     *   'tls://some-dot-server.example.com:8853', // DNS over TLS, via different port
     *   'https://1.0.0.1', // DNS over HTTPS
     *   'https://some-doh-server.example.com/custom-endpoint', // DNS over HTTPS, via different path
     * ]
     * ```
     *
     * Default:
     *
     * ```ts
     * ['https://1.1.1.1', 'https://1.0.0.1', 'https://8.8.8.8', 'https://8.8.4.4']
     * ```
     */
    dnsServers: ['https://1.1.1.1', 'https://1.0.0.1', 'https://8.8.8.8', 'https://8.8.4.4'],
  
    /** How many different DNS servers returning the satisfactory responses before the making the determination */
    confirmations: 2,

    /**
     * Provided dns servers will be shuffled before being attempted. On each attempt, the query would
     * be retried (determined by the retry* options) if any error occurs.
     *
     * The default value of `maxAttempts` is the length of the provided dnsServers array (i.e. each server
     * will get one attempt). You can customize this value by providing a different `maxAttempts` option.
     */
    maxAttempts: dnsOptions.dnsServers.length,

    retryCount: 3,
    retryFactor: 2,
    retryMinTimeout: 1000,
    retryMaxTimeout: 30000
  },
  whois: {
    timeout: 5000,

    retryCount: 3,
    retryFactor: 2,
    retryMinTimeout: 1000,
    retryMaxTimeout: 30000,

    family: undefined,
    follow: 1,
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
    customWhoisServersMapping: undefined,

    /**
     * WHOIS/RDAP query can easily failed: either the RDAP server is down, or the TLD doesn't support WHOIS/RDAP in the first place
     * The default value is `true` since WHOIS/RDAP is fragile, can easily fail or even not exist.
     */
    whoisErrorCountAsAlive: true
  }
}
```

## License

[MIT](./LICENSE).

----

**domain-alive** © [Sukka](https://github.com/SukkaW), Authored and maintained by Sukka with help from contributors ([list](https://github.com/SukkaW/domain-alive/graphs/contributors)).

> [Personal Website](https://skk.moe) · [Blog](https://blog.skk.moe) · GitHub [@SukkaW](https://github.com/SukkaW) · Telegram Channel [@SukkaChannel](https://t.me/SukkaChannel) · Twitter [@isukkaw](https://twitter.com/isukkaw) · Keybase [@sukka](https://keybase.io/sukka)

<p align="center">
  <a href="https://github.com/sponsors/SukkaW/">
    <img src="https://sponsor.cdn.skk.moe/sponsors.svg"/>
  </a>
</p>

