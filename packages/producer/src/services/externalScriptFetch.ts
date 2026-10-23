// fallow-ignore-file code-duplication
// The IPv4 special-use table below intentionally mirrors the one in
// cli/src/capture/publicNetwork.ts: the two policies must agree on what a
// public address is. The CLI depends on the producer, not the other way
// round, so the table cannot be imported from there.
/**
 * Fetch policy for the remote scripts `inlineExternalScripts` inlines into a
 * compiled composition.
 *
 * A composition is untrusted input: it is routinely downloaded (registry
 * blocks, shared projects, templates) and then rendered. The compiler used
 * to fetch every http(s) `<script src>` with a plain `fetch()`, so a
 * composition could make the rendering machine GET loopback, LAN, or
 * cloud-metadata URLs, and the response body was inlined into the compiled
 * page where the composition's own script could read it back.
 *
 * This mirrors the public-network policy the CLI capture resolver already
 * enforces (`cli/src/capture/publicNetwork.ts`): the host must be a public
 * name or literal, EVERY resolved address must be public, and redirects
 * are re-validated hop by hop instead of followed blindly. One deliberate
 * difference from the capture resolver: it dials the validated address
 * itself (pinned-IP dialing), which closes the DNS-rebinding window
 * between validation and connect. Fetch cannot pin the dialed address, so
 * a narrow rebind window remains here; the policy still removes the
 * direct internal-address primitive, which is the reachable case for a
 * static composition.
 */
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

/** A script URL failed the public-network policy. Compilers fail closed. */
export class ScriptFetchPolicyError extends Error {}

function ipv4Number(address: string): number {
  return address.split(".").reduce((value, octet) => value * 256 + Number(octet), 0);
}

// Same special-use table as the capture resolver
// (cli/src/capture/publicNetwork.ts): conservatively exclude special-use
// networks, including all of 192.0/16.
const NON_PUBLIC_IPV4: ReadonlyArray<readonly [string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 16],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 3],
];
const NON_PUBLIC_RANGES = NON_PUBLIC_IPV4.map(([network, prefix]) => ({
  start: ipv4Number(network),
  end: ipv4Number(network) + 2 ** (32 - prefix),
}));

/** Conservative IPv4-only policy: special-use addresses fail closed. */
export function isPublicIPv4(address: string): boolean {
  if (isIP(address) !== 4) return false;
  const value = ipv4Number(address);
  return !NON_PUBLIC_RANGES.some(({ start, end }) => value >= start && value < end);
}

/** Split an embedded IPv4 suffix (the ".d.d.d.d" in "::ffff:8.8.8.8") off an IPv6 literal. */
function splitEmbeddedIPv4(address: string): { head: string; tail: number[] } | null {
  if (!address.includes(".")) return { head: address, tail: [] };
  const lastColon = address.lastIndexOf(":");
  if (lastColon === -1) return null;
  const v4 = address.slice(lastColon + 1);
  if (isIP(v4) !== 4) return null;
  const octets = v4.split(".").map(Number);
  // The embedded form counts as two groups.
  return {
    head: address.slice(0, lastColon),
    tail: [(octets[0]! << 8) | octets[1]!, (octets[2]! << 8) | octets[3]!],
  };
}

function parseIPv6GroupRun(part: string): number[] | null {
  if (part === "") return [];
  const groups = part.split(":").map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  return groups.some(Number.isNaN) ? null : groups;
}

function parseIPv6(address: string): number[] | null {
  const split = splitEmbeddedIPv4(address.toLowerCase());
  if (split === null) return null;
  const halves = split.head.split("::");
  if (halves.length > 2) return null;
  const left = parseIPv6GroupRun(halves[0]!);
  if (left === null) return null;
  if (halves.length === 1) {
    const full = [...left, ...split.tail];
    return full.length === 8 ? full : null;
  }
  const right = parseIPv6GroupRun(halves[1]!);
  if (right === null) return null;
  const zeros = 8 - split.tail.length - left.length - right.length;
  if (zeros < 1) return null; // "::" must compress at least one group
  return [...left, ...new Array<number>(zeros).fill(0), ...right, ...split.tail];
}

function startsWithGroups(groups: number[], prefix: number[]): boolean {
  return prefix.every((value, index) => groups[index] === value);
}

function embeddedIPv4(groups: number[]): string {
  const g6 = groups[6]!;
  const g7 = groups[7]!;
  return `${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`;
}

/** Global-unicast IPv6 (2000::/3) with the special-use carve-outs inside it removed. */
function isGlobalUnicastIPv6(groups: number[]): boolean {
  const g0 = groups[0]!;
  const g1 = groups[1]!;
  if ((g0 & 0xe000) !== 0x2000) return false; // not global unicast
  if (g0 !== 0x2001) return true;
  if (g1 === 0x0000) return false; // Teredo
  if (g1 === 0x0db8) return false; // documentation
  if (g1 === 0x0002 && groups[2] === 0) return false; // benchmarking
  if ((g1 & 0xfff0) === 0x0010) return false; // ORCHID
  return true;
}

/** Conservative IPv6 policy: only global unicast with no special-use carve-outs is public. */
export function isPublicIPv6(address: string): boolean {
  const groups = parseIPv6(address);
  if (!groups) return false;
  // IPv4-mapped (::ffff:a.b.c.d) and NAT64 well-known (64:ff9b::/96)
  // addresses reach whatever IPv4 they embed, so judge that address.
  if (startsWithGroups(groups, [0, 0, 0, 0, 0, 0xffff])) {
    return isPublicIPv4(embeddedIPv4(groups));
  }
  if (startsWithGroups(groups, [0x0064, 0xff9b, 0, 0, 0, 0])) {
    return isPublicIPv4(embeddedIPv4(groups));
  }
  return isGlobalUnicastIPv6(groups);
}

export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return isPublicIPv4(address);
  if (family === 6) return isPublicIPv6(address);
  return false;
}

export type ScriptHostResolver = (hostname: string) => Promise<string[]>;

async function defaultResolveScriptHost(hostname: string): Promise<string[]> {
  const answers = await lookup(hostname, { all: true, verbatim: true });
  return answers.map((answer) => answer.address);
}

let resolveScriptHost: ScriptHostResolver = defaultResolveScriptHost;

/** Test seam, following the `__resetMaxFrameIndexCacheForTests` precedent. */
export function __setScriptHostResolverForTests(resolver: ScriptHostResolver | null): void {
  resolveScriptHost = resolver ?? defaultResolveScriptHost;
}

const LOCAL_HOST_SUFFIX = /(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid|example)$/;

/**
 * Validate one script URL against the public-network policy. Throws
 * ScriptFetchPolicyError on any refusal, including DNS failure: a host
 * that cannot be resolved to provably public addresses is not fetched.
 */
export async function assertPublicScriptUrl(url: URL): Promise<void> {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ScriptFetchPolicyError(`Script URL must be http(s): ${url.href}`);
  }
  // WHATWG URL keeps the brackets on IPv6 hostnames.
  const host = url.hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
  const family = isIP(host);
  if (family !== 0) {
    if (!isPublicAddress(host)) {
      throw new ScriptFetchPolicyError(`Script URL host is not a public address: ${url.href}`);
    }
    return;
  }
  if (
    !host.includes(".") ||
    !/^[a-z0-9.-]+$/.test(host) ||
    LOCAL_HOST_SUFFIX.test(host) ||
    host.split(".").some((label) => !label || label.startsWith("-") || label.endsWith("-"))
  ) {
    throw new ScriptFetchPolicyError(`Script URL host is not a public hostname: ${url.href}`);
  }
  let addresses: string[];
  try {
    addresses = await resolveScriptHost(host);
  } catch {
    throw new ScriptFetchPolicyError(`Script URL host did not resolve: ${url.href}`);
  }
  if (addresses.length === 0 || !addresses.every(isPublicAddress)) {
    throw new ScriptFetchPolicyError(
      `Script URL host resolves to a non-public address: ${url.href}`,
    );
  }
}

const MAX_SCRIPT_REDIRECTS = 5;

/**
 * Fetch a remote script under the public-network policy. Redirects are
 * followed manually (at most 5) and every hop is re-validated, because a
 * public URL that redirects to an internal one is the same primitive.
 */
export async function fetchPublicScript(url: string, signal?: AbortSignal): Promise<Response> {
  let current = url;
  for (let hop = 0; ; hop++) {
    await assertPublicScriptUrl(new URL(current));
    const response = await fetch(current, { signal, redirect: "manual" });
    if (response.status < 300 || response.status >= 400) return response;
    const location = response.headers.get("location");
    if (!location) return response;
    if (hop >= MAX_SCRIPT_REDIRECTS) {
      throw new ScriptFetchPolicyError(`Too many redirects fetching script: ${url}`);
    }
    await response.body?.cancel().catch(() => undefined);
    current = new URL(location, current).toString();
  }
}
