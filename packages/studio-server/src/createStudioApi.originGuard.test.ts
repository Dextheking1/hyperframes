// @vitest-environment node
// Node environment on purpose: the package default (happy-dom) implements
// the browser fetch spec, which drops forbidden request headers such as
// Origin and Sec-Fetch-Site when a Request is constructed. A test that
// simulates cross-origin browser traffic has to set exactly those headers,
// so it needs Node's fetch classes, which keep them.
import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createStudioApi } from "./createStudioApi";
import { stubAdapter } from "./routes/stubAdapter.test-helpers";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function createApp(): { app: ReturnType<typeof createStudioApi>; projectDir: string } {
  const projectDir = mkdtempSync(join(tmpdir(), "hf-origin-guard-"));
  tempDirs.push(projectDir);
  return { app: createStudioApi(stubAdapter(projectDir)), projectDir };
}

const EVIL_ORIGIN = "http://evil.example:9999";

function createFile(
  app: ReturnType<typeof createStudioApi>,
  headers: Record<string, string>,
  name = "planted.html",
): Promise<Response> {
  // A real browser request always carries a Host header; app.request does
  // not derive one in this environment, so send it explicitly. That keeps
  // every case exercising the Origin comparison itself.
  return app.request(`http://localhost/projects/demo/files/${name}`, {
    method: "POST",
    headers: { Host: "localhost", ...headers },
    body: "<html>planted</html>",
  });
}

describe("createStudioApi cross-origin write guard", () => {
  it("rejects a cross-origin POST file create and writes nothing", async () => {
    const { app, projectDir } = createApp();
    const res = await createFile(app, { Origin: EVIL_ORIGIN, "Content-Type": "text/plain" });
    expect(res.status).toBe(403);
    expect(existsSync(join(projectDir, "planted.html"))).toBe(false);
  });

  it("rejects a cross-origin multipart upload", async () => {
    const { app, projectDir } = createApp();
    const form = new FormData();
    form.append("files", new File(["planted"], "planted.html", { type: "text/html" }));
    const res = await app.request("http://localhost/projects/demo/upload", {
      method: "POST",
      headers: { Host: "localhost", Origin: EVIL_ORIGIN },
      body: form,
    });
    expect(res.status).toBe(403);
    expect(existsSync(join(projectDir, "planted.html"))).toBe(false);
  });

  it("rejects a write whose Origin is the opaque literal null", async () => {
    const { app } = createApp();
    const res = await createFile(app, { Origin: "null", "Content-Type": "text/plain" });
    expect(res.status).toBe(403);
  });

  it("rejects a write marked cross-site by Fetch Metadata even without Origin", async () => {
    const { app } = createApp();
    const res = await createFile(app, { "Sec-Fetch-Site": "cross-site" });
    expect(res.status).toBe(403);
  });

  it("rejects a cross-origin PUT overwrite", async () => {
    const { app } = createApp();
    const res = await app.request("http://localhost/projects/demo/files/planted.html", {
      method: "PUT",
      headers: { Host: "localhost", Origin: EVIL_ORIGIN, "If-None-Match": "*" },
      body: "overwritten",
    });
    expect(res.status).toBe(403);
  });

  it("allows a same-origin write (Origin host matches Host)", async () => {
    const { app, projectDir } = createApp();
    const res = await createFile(app, {
      Origin: "http://localhost",
      "Content-Type": "text/plain",
    });
    expect(res.status).toBe(201);
    expect(existsSync(join(projectDir, "planted.html"))).toBe(true);
  });

  it("allows a write with no Origin header (non-browser callers)", async () => {
    const { app, projectDir } = createApp();
    const res = await createFile(app, { "Content-Type": "text/plain" });
    expect(res.status).toBe(201);
    expect(existsSync(join(projectDir, "planted.html"))).toBe(true);
  });

  it("does not block reads from any origin", async () => {
    const { app } = createApp();
    await createFile(app, { "Content-Type": "text/plain" });
    const res = await app.request("http://localhost/projects/demo/files/planted.html", {
      headers: { Origin: EVIL_ORIGIN },
    });
    expect(res.status).toBe(200);
  });
});
