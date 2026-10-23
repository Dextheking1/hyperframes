import { describe, expect, it, beforeEach, afterEach } from "bun:test";
import {
  __setScriptHostResolverForTests,
  assertPublicScriptUrl,
  fetchPublicScript,
  isPublicAddress,
  isPublicIPv4,
  isPublicIPv6,
  ScriptFetchPolicyError,
} from "./externalScriptFetch.js";

describe("isPublicIPv4", () => {
  it("rejects loopback, private, link-local and other special-use ranges", () => {
    for (const address of [
      "127.0.0.1",
      "127.53.0.9",
      "10.0.0.5",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "169.254.169.254", // cloud metadata
      "100.64.0.1", // CGNAT
      "0.0.0.0",
      "192.0.2.1", // documentation TEST-NET-1 (inside 192.0.0.0/16)
      "198.51.100.1", // documentation TEST-NET-2
      "203.0.113.1", // documentation TEST-NET-3
      "198.18.0.1", // benchmarking
      "224.0.0.1", // multicast
      "240.0.0.1", // reserved, inside 224.0.0.0/3
    ]) {
      expect(isPublicIPv4(address)).toBe(false);
    }
  });

  it("accepts ordinary public addresses", () => {
    for (const address of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "193.0.0.1"]) {
      expect(isPublicIPv4(address)).toBe(true);
    }
  });

  it("rejects non-IPv4 input", () => {
    expect(isPublicIPv4("::1")).toBe(false);
    expect(isPublicIPv4("example.com")).toBe(false);
    expect(isPublicIPv4("999.1.1.1")).toBe(false);
  });
});

describe("isPublicIPv6", () => {
  it("rejects loopback, ULA, link-local and other special-use ranges", () => {
    for (const address of [
      "::1",
      "::",
      "fe80::1",
      "fd00::1",
      "fc00::1",
      "ff02::1", // multicast
      "2001:db8::1", // documentation
      "2001:0000::1", // Teredo
      "64:ff9b::a9fe:a9fe", // NAT64 embedding 169.254.169.254
      "::ffff:127.0.0.1", // IPv4-mapped loopback
      "::ffff:10.0.0.1", // IPv4-mapped private
    ]) {
      expect(isPublicIPv6(address)).toBe(false);
    }
  });

  it("accepts global unicast, judging IPv4-mapped forms by the embedded address", () => {
    expect(isPublicIPv6("2606:4700:4700::1111")).toBe(true);
    expect(isPublicIPv6("::ffff:8.8.8.8")).toBe(true);
    expect(isPublicIPv6("64:ff9b::808:808")).toBe(true); // NAT64 embedding 8.8.8.8
  });

  it("rejects unparseable input", () => {
    expect(isPublicIPv6("not-an-address")).toBe(false);
    expect(isPublicIPv6("12345::1")).toBe(false);
    expect(isPublicIPv6("8.8.8.8")).toBe(false);
  });
});

describe("assertPublicScriptUrl", () => {
  beforeEach(() => {
    __setScriptHostResolverForTests(async (hostname) => {
      if (hostname === "cdn.example.com") return ["93.184.216.34"];
      if (hostname === "mixed.example.com") return ["93.184.216.34", "10.0.0.5"];
      if (hostname === "internal.example.com") return ["192.168.0.20"];
      if (hostname === "v6.example.com") return ["2606:4700:4700::1111"];
      throw new Error("ENOTFOUND");
    });
  });
  afterEach(() => {
    __setScriptHostResolverForTests(null);
  });

  it("rejects non-http(s) schemes", async () => {
    await expect(assertPublicScriptUrl(new URL("file:///etc/passwd"))).rejects.toBeInstanceOf(
      ScriptFetchPolicyError,
    );
    await expect(assertPublicScriptUrl(new URL("gopher://example.com/x"))).rejects.toBeInstanceOf(
      ScriptFetchPolicyError,
    );
  });

  it("rejects literal non-public addresses without any DNS lookup", async () => {
    await expect(assertPublicScriptUrl(new URL("http://127.0.0.1/x.js"))).rejects.toBeInstanceOf(
      ScriptFetchPolicyError,
    );
    await expect(
      assertPublicScriptUrl(new URL("http://169.254.169.254/latest/meta-data")),
    ).rejects.toBeInstanceOf(ScriptFetchPolicyError);
    await expect(assertPublicScriptUrl(new URL("http://[::1]/x.js"))).rejects.toBeInstanceOf(
      ScriptFetchPolicyError,
    );
  });

  it("rejects local-looking hostnames", async () => {
    await expect(assertPublicScriptUrl(new URL("http://localhost/x.js"))).rejects.toBeInstanceOf(
      ScriptFetchPolicyError,
    );
    await expect(
      assertPublicScriptUrl(new URL("http://printer.local/x.js")),
    ).rejects.toBeInstanceOf(ScriptFetchPolicyError);
    await expect(
      assertPublicScriptUrl(new URL("http://metadata.google.internal/x.js")),
    ).rejects.toBeInstanceOf(ScriptFetchPolicyError);
    await expect(assertPublicScriptUrl(new URL("http://intranet/x.js"))).rejects.toBeInstanceOf(
      ScriptFetchPolicyError,
    );
  });

  it("rejects hosts that resolve to non-public or mixed addresses, and unresolvable hosts", async () => {
    await expect(
      assertPublicScriptUrl(new URL("https://internal.example.com/x.js")),
    ).rejects.toBeInstanceOf(ScriptFetchPolicyError);
    await expect(
      assertPublicScriptUrl(new URL("https://mixed.example.com/x.js")),
    ).rejects.toBeInstanceOf(ScriptFetchPolicyError);
    await expect(
      assertPublicScriptUrl(new URL("https://missing.example.com/x.js")),
    ).rejects.toBeInstanceOf(ScriptFetchPolicyError);
  });

  it("accepts public literals and hosts resolving only to public addresses", async () => {
    await assertPublicScriptUrl(new URL("https://8.8.8.8/x.js"));
    await assertPublicScriptUrl(new URL("https://cdn.example.com/x.js"));
    await assertPublicScriptUrl(new URL("https://v6.example.com/x.js"));
  });
});

describe("fetchPublicScript", () => {
  const realFetch = globalThis.fetch;

  beforeEach(() => {
    __setScriptHostResolverForTests(async (hostname) => {
      if (hostname === "cdn.example.com") return ["93.184.216.34"];
      throw new Error("ENOTFOUND");
    });
  });
  afterEach(() => {
    __setScriptHostResolverForTests(null);
    globalThis.fetch = realFetch;
  });

  it("refuses a loopback URL before any fetch happens", async () => {
    let fetchCalls = 0;
    globalThis.fetch = (async () => {
      fetchCalls++;
      return new Response("should never be returned");
    }) as typeof fetch;
    await expect(fetchPublicScript("http://127.0.0.1:9999/secret.js")).rejects.toBeInstanceOf(
      ScriptFetchPolicyError,
    );
    expect(fetchCalls).toBe(0);
  });

  it("follows a redirect between public URLs", async () => {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "https://cdn.example.com/a.js") {
        return new Response(null, {
          status: 302,
          headers: { location: "https://cdn.example.com/b.js" },
        });
      }
      return new Response("script body", { status: 200 });
    }) as typeof fetch;
    const res = await fetchPublicScript("https://cdn.example.com/a.js");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("script body");
  });

  it("refuses a redirect from a public URL to a loopback URL", async () => {
    const fetched: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      fetched.push(url);
      return new Response(null, {
        status: 302,
        headers: { location: "http://127.0.0.1:9999/secret.js" },
      });
    }) as typeof fetch;
    await expect(fetchPublicScript("https://cdn.example.com/a.js")).rejects.toBeInstanceOf(
      ScriptFetchPolicyError,
    );
    expect(fetched).toEqual(["https://cdn.example.com/a.js"]);
  });

  it("gives up after too many redirects", async () => {
    globalThis.fetch = (async () =>
      new Response(null, {
        status: 302,
        headers: { location: "https://cdn.example.com/loop.js" },
      })) as unknown as typeof fetch;
    await expect(fetchPublicScript("https://cdn.example.com/loop.js")).rejects.toBeInstanceOf(
      ScriptFetchPolicyError,
    );
  });
});

describe("isPublicAddress", () => {
  it("dispatches on family and fails closed on garbage", () => {
    expect(isPublicAddress("8.8.8.8")).toBe(true);
    expect(isPublicAddress("10.0.0.1")).toBe(false);
    expect(isPublicAddress("2606:4700:4700::1111")).toBe(true);
    expect(isPublicAddress("fe80::1")).toBe(false);
    expect(isPublicAddress("")).toBe(false);
    expect(isPublicAddress("example.com")).toBe(false);
  });
});
