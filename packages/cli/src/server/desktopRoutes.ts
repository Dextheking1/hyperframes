import type { Hono } from "hono";
import {
  HANDOFF_READY,
  desktopDownloadUrl,
  desktopInstalled,
  openInDesktop,
} from "../utils/desktopApp.js";
import { sameOriginPost } from "@hyperframes/studio-server/request-identity";

// Re-exported for this module's tests; the definition is shared with
// the studio API's write guard.
export { sameOriginPost };

const CTA_ID = /^[A-Za-z0-9-]{1,64}$/;

/** The desktop-app button's route: show it or not, the download, and whether the app here takes the project. */
export function mountDesktopRoutes(
  app: Hono,
  projectDir: string,
  {
    ready = HANDOFF_READY,
    open = (dir: string, cta?: string) => openInDesktop(dir, { cta }),
    platform = process.platform,
    installed = () => desktopInstalled({ platform }),
  } = {},
): void {
  const downloadUrl = desktopDownloadUrl(platform);
  app.get("/api/open-in-desktop", (c) => {
    const here = installed();
    return c.json({
      available: downloadUrl !== null || here,
      handoff: ready && here,
      downloadUrl,
      os: platform,
      installed: here,
    });
  });
  app.post("/api/open-in-desktop", async (c) => {
    const allowed = sameOriginPost({
      host: c.req.header("host"),
      origin: c.req.header("origin"),
      fetchSite: c.req.header("sec-fetch-site"),
    });
    if (!allowed) return c.json({ error: "forbidden" }, 403);
    if (!ready)
      return c.json({
        opened: false,
        reason: "handoff-unavailable",
        downloadUrl,
      });
    const body: unknown = await c.req.json().catch(() => null);
    const cta = (body as { cta?: unknown } | null)?.cta;
    return c.json(open(projectDir, typeof cta === "string" && CTA_ID.test(cta) ? cta : undefined));
  });
}
