import { DOHClient, TCPClient, UDPClient } from 'dns2';
import type { DnsResolver } from 'dns2';

export interface DnsOptions {
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
  dnsServers?: string[],

  /** How many different DNS servers returning the satisfactory responses before the making the determination */
  confirmations?: number,

  /**
   * Provided dns servers will be shuffled before being attempted. On each attempt, the query would
   * be retried (determined by the retry* options) if any error occurs.
   *
   * The default value of `maxAttempts` is the length of the provided dnsServers array (i.e. each server
   * will get one attempt). You can customize this value by providing a different `maxAttempts` option.
   */
  maxAttempts?: number,

  retryCount?: number,
  retryFactor?: number,
  retryMinTimeout?: number,
  retryMaxTimeout?: number
}

export const defaultDnsServers: string[] = [
  'https://1.1.1.1',
  'https://1.0.0.1',
  'https://8.8.8.8',
  'https://8.8.4.4'
];

export function getDnsClients(servers: string[]): Array<DnsResolver & { server: string }> {
  return servers.map(dns => {
    const protocolIndex = dns.indexOf('://');
    const protocol = protocolIndex === -1 ? '' : dns.slice(0, protocolIndex);

    const rest = dns.slice(protocolIndex + 3);
    const [server, _port] = rest.split(':', 2);
    const port = _port ? Number.parseInt(_port, 10) : 0;

    let client: DnsResolver;

    switch (protocol) {
      case 'https':
        client = DOHClient({ dns });
        break;
      case 'tls':
        client = TCPClient({ dns: server, protocol: 'tls:', port: port || 853 });
        break;
      case 'tcp':
        client = TCPClient({ dns: server, protocol: 'tcp:', port: port || 53 });
        break;
      case '':
      case 'udp':
        client = UDPClient({ dns: server, port: port || 53 });
        break;
      default:
        throw new TypeError('Unsupported DNS protocol "' + protocol + '" for DNS server "' + dns + '"');
    }

    return Object.assign(client, { server });
  });
}
