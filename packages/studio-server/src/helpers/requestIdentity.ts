/**
 * The one answer to "is this write same origin", shared by the CLI server
 * and the studio API.
 *
 * Lifted out of the CLI server so both import this one definition: the CLI's
 * open-in-desktop route and the studio API's write guard ask the same
 * question, and two copies of the check would drift into two different
 * answers. The split also keeps the predicate unit-testable without pulling
 * in either server's heavier dependencies.
 */
import { hostname, networkInterfaces } from "node:os";

/**
 * Is this request's `Host` a loopback name the studio server could have been
 * reached on directly?
 *
 * A bare `[::1]`/`localhost`/dotted-quad check rather than a full parse: the
 * port is irrelevant (any port on loopback is us), and anything exotic enough
 * to miss here should be refused rather than guessed at.
 *
 * Scope, stated precisely: this is a **DNS-rebinding mitigation for browsers**,
 * not access control. A browser sets `Host` from the URL it was given, so a
 * page that rebinds its own hostname to 127.0.0.1 arrives carrying that
 * hostname and is refused. A non-browser client sets `Host` to whatever it
 * likes, so this stops nothing there — but on a loopback-bound server such a
 * client is already local, and on a LAN-bound one it can read the project
 * files through the unauthenticated studio API anyway. See `identityAllowed`.
 */
export function isLoopbackHost(host: string | undefined): boolean {
  if (!host) return false;
  // Strip the port. IPv6 literals are bracketed (`[::1]:1234`), so take the
  // bracketed part when present and only split on ":" otherwise.
  const bracketed = /^\[([^\]]+)\]/.exec(host);
  const hostname = (bracketed ? bracketed[1] : host.split(":")[0])?.toLowerCase() ?? "";
  if (hostname === "localhost" || hostname === "::1" || hostname === "0:0:0:0:0:0:0:1") return true;
  // 127.0.0.0/8 — the whole loopback block, not just 127.0.0.1.
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

/** Hostname of a `Host` header, port and IPv6 brackets removed. */
function hostnameOf(host: string | undefined): string {
  if (!host) return "";
  const bracketed = /^\[([^\]]+)\]/.exec(host);
  return (bracketed ? bracketed[1] : host.split(":")[0])?.toLowerCase() ?? "";
}

/**
 * Names this machine legitimately answers to on a wildcard bind: every
 * interface address, plus its own hostname and the `.local` mDNS form people
 * actually type. Fail closed — a throw yields an empty set, which denies.
 */
function localNames(): Set<string> {
  const names = new Set<string>();
  try {
    for (const entries of Object.values(networkInterfaces())) {
      for (const entry of entries ?? []) names.add(entry.address.toLowerCase());
    }
    const self = hostname().toLowerCase();
    if (self !== "") {
      names.add(self);
      // `my-box` is reachable as `my-box.local`, and a `my-box.lan.example`
      // FQDN is reachable by its short form. Register both directions.
      names.add(`${self}.local`);
      const short = self.split(".")[0];
      if (short !== undefined && short !== "") {
        names.add(short);
        names.add(`${short}.local`);
      }
    }
  } catch {
    /* fail closed */
  }
  return names;
}

/**
 * Wildcard binds answer on every local name; a specific bind on itself only.
 *
 * This is the part that was missing: the previous rule accepted ANY Host once
 * the env var was set, so a rebinding page could name itself `evil.example.com`
 * and still be handed the CLI identity.
 */
function hostMatchesBind(host: string | undefined, bind: string): boolean {
  const requested = hostnameOf(host);
  if (requested === "") return false;
  const bound = bind.toLowerCase();
  if (requested === bound) return true;
  return bound === "0.0.0.0" || bound === "::" || bound === "*"
    ? localNames().has(requested)
    : false;
}

/**
 * May a request carrying this `Host` be treated as addressed to this server?
 *
 * The server binds loopback by DEFAULT and exposes the LAN only when an
 * operator sets `HYPERFRAMES_PREVIEW_HOST` (portUtils.ts, F-001). A loopback
 * `Host` is always fine: whatever reached us came via loopback, and the only
 * interesting attacker is a rebinding browser page — which the Host check
 * catches, because a browser cannot forge `Host`.
 *
 * For anything else the bind decides:
 *
 *  - **Unset, or bound to loopback.** No LAN exposure was requested, so the
 *    Host check is a live rebinding mitigation and a non-loopback Host is
 *    refused. Previously ANY non-empty value disabled the check, so even
 *    `HYPERFRAMES_PREVIEW_HOST=127.0.0.1` — which exposes nothing — turned the
 *    loopback service from hostile-Host refusal into accept-everything.
 *  - **Bound to a LAN address.** The operator opted into exposure, so identity
 *    has to reach the LAN name the user browses or the CLI-to-Studio stitch
 *    breaks and Studio mints a second person for the same human. But it is
 *    still checked: the Host must name an address this machine actually
 *    answers on, not any attacker-chosen name a rebinding page supplies.
 */
export function identityAllowed(host: string | undefined): boolean {
  if (isLoopbackHost(host)) return true;
  const bind = (process.env["HYPERFRAMES_PREVIEW_HOST"] ?? "").trim();
  if (bind === "" || isLoopbackHost(bind)) return false;
  return hostMatchesBind(host, bind);
}

/**
 * A bodiless POST is a simple request, so any page can send one to localhost:
 * it has to come from this Studio. Both write guards apply this one function,
 * the CLI server's open-in-desktop route and the studio API's write
 * middleware, so the two servers cannot drift into different answers.
 */
export function sameOriginPost(headers: {
  host?: string;
  origin?: string;
  fetchSite?: string;
}): boolean {
  const { host, origin, fetchSite } = headers;
  if (!host || !identityAllowed(host)) return false;
  if (fetchSite && fetchSite !== "same-origin") return false;
  return origin === undefined || origin === `http://${host}`;
}
