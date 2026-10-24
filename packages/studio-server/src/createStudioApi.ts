import { Hono } from "hono";
import type { StudioApiAdapter } from "./types.js";
import { registerProjectRoutes } from "./routes/projects.js";
import { registerFileRoutes } from "./routes/files.js";
import { registerPreviewRoutes } from "./routes/preview.js";
import { registerLintRoutes } from "./routes/lint.js";
import { registerRenderRoutes } from "./routes/render.js";
import { registerImageThumbnailRoutes } from "./routes/imageThumbnail.js";
import { registerThumbnailRoutes } from "./routes/thumbnail.js";
import { registerWaveformRoutes } from "./routes/waveform.js";
import { registerFreezeFrameRoutes } from "./routes/freezeFrame.js";
import { registerLoudnessRoutes } from "./routes/loudness.js";
import { registerPeakRoutes } from "./routes/peaks.js";
import { registerFontRoutes } from "./routes/fonts.js";
import { registerRegistryRoutes } from "./routes/registry.js";
import { registerSelectionRoutes } from "./routes/selection.js";
import { registerMediaRoutes } from "./routes/media.js";
import { registerGlobalAssetRoutes } from "./routes/globalAssets.js";
import { registerHistoryRoutes } from "./routes/history.js";
import { replaceWithProjectDirMissing } from "./helpers/projectDirMissing.js";
import { folderGone, isProjectRootMissing } from "./helpers/safePath.js";
import { sameOriginPost } from "./helpers/requestIdentity.js";

/** Host named by a request URL, or undefined when it does not parse. */
function urlHost(url: string): string | undefined {
  try {
    return new URL(url).host || undefined;
  } catch {
    return undefined;
  }
}

/**
 * Create a Hono sub-app with all studio API routes.
 *
 * Both the vite dev server and CLI embedded server mount this app
 * under /api, each providing their own adapter for host-specific behavior.
 */
export function createStudioApi(adapter: StudioApiAdapter): Hono {
  const api = new Hono();
  // The studio API is unauthenticated and its only legitimate caller is the
  // Studio page this same server serves. A state-changing request that did
  // not come from that page is a cross-origin request from some other
  // website open in the user's browser. CORS does not stop such requests
  // from being SENT: POST with a text/plain or form body is "simple" and
  // needs no preflight. It only stops the page reading the response, which
  // a fire-and-forget file write or render trigger does not need. Reject
  // those writes outright. Reads are unaffected: the guard covers state
  // changes only.
  //
  // The predicate is the CLI server's own `sameOriginPost`, shared from
  // helpers/requestIdentity so both servers give one answer. Comparing the
  // Origin host to the Host header alone is not enough: a page whose own
  // DNS name resolves to 127.0.0.1 sends a matching pair and walks through.
  // `sameOriginPost` also requires the Host to be an identity this server
  // answers to (a loopback literal, or the LAN name it was bound with) and
  // refuses any Sec-Fetch-Site other than "same-origin". Callers with no
  // Origin header (curl, tests, in-process) still pass on a loopback Host,
  // which is the only Host a loopback-bound server can be reached on. When
  // the Host header is absent the request never came over the wire
  // (in-process callers address the app by URL, and a real server builds
  // that URL from the Host header), so the URL's host is the same value.
  api.use(async function rejectCrossOriginWrites(c, next) {
    if (c.req.method === "GET" || c.req.method === "HEAD" || c.req.method === "OPTIONS") {
      return next();
    }
    const allowed = sameOriginPost({
      host: c.req.header("host") ?? urlHost(c.req.url),
      origin: c.req.header("origin"),
      fetchSite: c.req.header("sec-fetch-site"),
    });
    if (!allowed) return c.json({ error: "forbidden" }, 403);
    return next();
  });
  api.use(async function answerProjectDirMissingAfterErrorHandlers(c, next) {
    const hostHeaders = new Headers(c.res.headers);
    await next();
    if (isProjectRootMissing(c.error)) replaceWithProjectDirMissing(c, hostHeaders);
  });
  api.use("/projects/:id/*", async function answerProjectDirMissingForVanishedFolder(c, next) {
    const hostHeaders = new Headers(c.res.headers);
    const dirBeforeRoute = await Promise.resolve()
      .then(() => adapter.resolveProject(c.req.param("id")))
      .then(
        (project) => project?.dir,
        () => undefined,
      );
    await next();
    if (c.res.status >= 403 && dirBeforeRoute && folderGone(dirBeforeRoute))
      replaceWithProjectDirMissing(c, hostHeaders);
  });
  api.use("/projects/:id/*", async function forgetSignatureAfterWrite(c, next) {
    await next();
    if (c.req.method === "GET" || c.req.method === "HEAD") return;
    const project = await Promise.resolve()
      .then(() => adapter.resolveProject(c.req.param("id")))
      .catch(() => null);
    if (project) adapter.invalidateProjectSignature?.(project.dir);
  });
  api.use("/projects/:id/*", async function openHistorySoNoWriteBecomesItsBaseline(c, next) {
    if (c.req.method !== "GET" && c.req.method !== "HEAD" && adapter.history) {
      await Promise.resolve()
        .then(() => adapter.resolveProject(c.req.param("id")))
        .then((project) => project && adapter.history?.(project))
        .catch(() => null);
    }
    await next();
  });

  registerProjectRoutes(api, adapter);
  registerFileRoutes(api, adapter);
  registerPreviewRoutes(api, adapter);
  registerLintRoutes(api, adapter);
  registerRenderRoutes(api, adapter);
  registerThumbnailRoutes(api, adapter);
  registerImageThumbnailRoutes(api, adapter);
  registerSelectionRoutes(api, adapter);
  registerMediaRoutes(api, adapter);
  registerWaveformRoutes(api, adapter);
  registerFreezeFrameRoutes(api, adapter);
  registerLoudnessRoutes(api, adapter);
  registerPeakRoutes(api, adapter);
  registerFontRoutes(api);
  registerRegistryRoutes(api, adapter);
  registerGlobalAssetRoutes(api);
  registerHistoryRoutes(api, adapter);

  return api;
}
