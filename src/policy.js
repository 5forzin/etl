import { BlockList, isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

const blocked = new BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24],
  ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3],
]) blocked.addSubnet(address, prefix, 'ipv4');
const globalV6 = new BlockList();
globalV6.addSubnet('2000::', 3, 'ipv6');
for (const [address, prefix] of [
  ['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20],
]) blocked.addSubnet(address, prefix, 'ipv6');

export function isPublicAddress(address) {
  const family = isIP(address);
  if (family === 4) return !blocked.check(address, 'ipv4');
  // Mapped IPv4, translation ranges, scoped addresses and local IPv6 are
  // conservatively excluded from the public IPv6 allow range.
  return family === 6 && !address.includes('%') &&
    globalV6.check(address, 'ipv6') && !blocked.check(address, 'ipv6');
}

export function validateDestination(host, port) {
  if (typeof host !== 'string' || host.length < 1 || host.length > 253 ||
      !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Invalid destination');
  }
  if (!isIP(host) && !/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.?$/i.test(host)) {
    throw new Error('Invalid hostname');
  }
}

export async function resolveDestination(host, port, resolver = lookup) {
  validateDestination(host, port);
  const addresses = isIP(host) ? [{ address: host, family: isIP(host) }] :
    await resolver(host, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
    throw new Error('Destination blocked');
  }
  // Dial this validated numeric address, never resolve the hostname again.
  return addresses;
}
