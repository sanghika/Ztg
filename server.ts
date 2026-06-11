import express, { Request, Response, NextFunction } from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import multer, { FileFilterCallback } from "multer";
import AdmZip from "adm-zip";
import { Octokit } from "@octokit/rest";
import * as dotenv from "dotenv";

dotenv.config();

// ─────────────────────────────────────────────────────────────────────────────
// Config — fail fast if secrets are absent
// ─────────────────────────────────────────────────────────────────────────────
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID ?? "";
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET ?? "";

// parseInt with radix is safer than Number() — Number("") === 0,
// parseInt("", 10) falls through to the default cleanly.
const PORT = (parseInt(process.env.PORT ?? "", 10) || 3000);
const IS_PROD = process.env.NODE_ENV === "production";

if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
  console.error(
    "FATAL: GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set in the environment."
  );
  process.exit(1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validates a GitHub owner or repository name.
 * Rules: 1–100 chars, alphanumeric / hyphen / underscore / dot only.
 * Rejects path separators, null bytes, and dot-only names ("..", ".") that
 * could be misused in path construction.
 *
 * FIX A: The previous regex /^[a-zA-Z0-9._-]{1,100}$/ accepted "." and ".."
 * as valid names. These are not legal GitHub names and could cause issues in
 * path construction. Added an explicit rejection for dot-only names.
 */
function isValidGitHubName(value: string): boolean {
  if (!value) return false;
  // Reject dot-only names: ".", "..", "...", etc.
  if (/^\.+$/.test(value)) return false;
  return /^[a-zA-Z0-9._-]{1,100}$/.test(value);
}

/**
 * Validates a branch name.
 * Branches CAN contain forward slashes (e.g. feature/my-thing) but must not
 * start/end with one, contain consecutive slashes, or contain shell-special chars.
 */
function isValidBranchName(value: string): boolean {
  if (!value || value.length > 255) return false;
  // Reject obvious path traversal and control chars
  if (/[\\^~: *?[\]@{}\x00-\x1f\x7f]/.test(value)) return false;
  // Must not start or end with / or .
  if (/^[/.]|[/.]$/.test(value)) return false;
  // No consecutive slashes or dots
  if (/\/\/|\.\./.test(value)) return false;
  return true;
}

/**
 * Sanitises a ZIP entry path so it cannot escape the repository root.
 * Returns null for paths that should be skipped entirely.
 */
function sanitiseZipPath(raw: string): string | null {
  // Normalise backslashes (Windows zips)
  const normalised = raw.replace(/\\/g, "/");
  // Resolve any . / .. segments without using the real filesystem
  const parts: string[] = [];
  for (const seg of normalised.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      parts.pop();
    } else {
      parts.push(seg);
    }
  }
  if (parts.length === 0) return null;
  // Reject absolute paths that survived normalisation
  const clean = parts.join("/");
  if (clean.startsWith("/")) return null;
  return clean;
}

/**
 * Detects the common root directory prefix shared by every path in the list.
 * Uses ALL paths (not just the first) for correctness.
 *
 * A common root only exists when every path has AT LEAST two segments AND they
 * all share the same first segment.
 */
function detectCommonRoot(paths: string[]): string {
  if (paths.length === 0) return "";

  const firstSegments = paths.map((p) => p.split("/")[0]);
  const allSameFirstSegment = firstSegments.every((s) => s === firstSegments[0]);

  if (!allSameFirstSegment) return "";

  const allHaveSubPath = paths.every((p) => p.indexOf("/") !== -1);
  if (!allHaveSubPath) return "";

  return firstSegments[0] + "/";
}

// ─────────────────────────────────────────────────────────────────────────────
// Multer — 50 MB hard limit, ZIP MIME filter, memory storage
// ─────────────────────────────────────────────────────────────────────────────
const ALLOWED_MIME_TYPES = new Set([
  "application/zip",
  "application/x-zip-compressed",
  "application/octet-stream", // some browsers send this for .zip
  "multipart/x-zip",
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (
    _req: Request,
    file: Express.Multer.File,
    cb: FileFilterCallback
  ) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ALLOWED_MIME_TYPES.has(file.mimetype) || ext === ".zip") {
      cb(null, true);
    } else {
      // Use a named error code so the global handler can identify
      // multer rejections structurally rather than by fragile string matching.
      const err = new Error("Only .zip files are accepted") as Error & { code: string };
      err.code = "INVALID_FILE_TYPE";
      cb(err);
    }
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// In-memory rate limiter (per IP + action namespace, no external dependency)
// ─────────────────────────────────────────────────────────────────────────────
interface RateLimitEntry {
  count: number;
  resetAt: number;
}
const rateLimitStore = new Map<string, RateLimitEntry>();
const RATE_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_PUSH = 10;    // max push operations per IP per window
const RATE_LIMIT_AUTH = 20;    // max auth attempts per IP per window
const RATE_LIMIT_REPOS = 30;   // max repo-list requests per IP per window

/**
 * Rate limit buckets are namespaced by action so that auth and push
 * limits don't bleed into each other.
 */
function checkRateLimit(ip: string, action: string, limit: number): boolean {
  const key = `${action}:${ip}`;
  const now = Date.now();
  const entry = rateLimitStore.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return true;
  }
  if (entry.count >= limit) return false;
  entry.count += 1;
  return true;
}

// Periodically prune the store to avoid unbounded memory growth.
// FIX B: Call .unref() on the interval so it does not prevent the Node.js
// process from exiting cleanly when all other work is done (e.g. during tests
// or graceful shutdown). The interval still fires normally while the server is
// running — unref only means it won't *keep* the process alive by itself.
const pruneInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
  }
}, RATE_WINDOW_MS);
pruneInterval.unref();

function rateLimit(action: string, limit: number) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const ip = req.ip ?? req.socket.remoteAddress ?? "unknown";
    if (!checkRateLimit(ip, action, limit)) {
      res.status(429).json({ error: "Too many requests. Please try again later." });
      return;
    }
    next();
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Trusted-origin helper
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true for origins that are allowed to receive OAuth tokens via
 * postMessage or to supply OAuth redirect URIs.
 * Only allows http(s) for localhost and HTTPS only for Cloud Run.
 */
function isTrustedOrigin(origin: string): boolean {
  try {
    const { protocol, hostname } = new URL(origin);
    const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1";
    const isCloudRun = /^[a-z0-9-]+\.run\.app$/.test(hostname);

    if (isLocalhost) {
      return protocol === "http:" || protocol === "https:";
    }
    if (isCloudRun) {
      return protocol === "https:";
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Validates a redirect URI for OAuth: must be a trusted origin AND the path
 * must be exactly "/auth/callback" (no open redirects via path manipulation).
 */
function isValidRedirectUri(uri: string): boolean {
  try {
    const parsed = new URL(uri);
    if (!isTrustedOrigin(`${parsed.protocol}//${parsed.host}`)) return false;
    // Only permit the single known callback path; reject anything else.
    const normalised = parsed.pathname.replace(/\/+$/, ""); // strip trailing slashes
    return normalised === "/auth/callback";
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Extract Bearer token from Authorization header
// ─────────────────────────────────────────────────────────────────────────────
function extractBearerToken(req: Request): string | null {
  const header = req.headers.authorization ?? "";
  const spaceIdx = header.indexOf(" ");
  if (spaceIdx === -1) return null;
  const scheme = header.slice(0, spaceIdx);
  const token = header.slice(spaceIdx + 1).trim();
  return scheme === "Bearer" && token.length > 0 ? token : null;
}

// ─────────────────────────────────────────────────────────────────────────────
// ZIP safety limits
// ─────────────────────────────────────────────────────────────────────────────
// Protect against ZIP bombs by enforcing entry count and total
// uncompressed size limits before doing any real work.
const ZIP_MAX_ENTRIES = 10_000;
const ZIP_MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024; // 500 MB

// ─────────────────────────────────────────────────────────────────────────────
// Server bootstrap
// ─────────────────────────────────────────────────────────────────────────────
async function startServer(): Promise<void> {
  const app = express();

  // Body size guard — API endpoints use JSON payloads only (file uploads use multipart)
  app.use(express.json({ limit: "1mb" }));

  // Minimal security headers (no external dep)
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    next();
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Auth Routes
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * GET /api/auth/url
   * Returns the GitHub OAuth authorisation URL for the given redirectUri.
   */
  app.get(
    "/api/auth/url",
    rateLimit("auth", RATE_LIMIT_AUTH),
    (req: Request, res: Response) => {
      const redirectUri = req.query.redirectUri as string | undefined;

      if (!redirectUri) {
        res.status(400).json({ error: "Missing redirectUri parameter" });
        return;
      }

      // Use the stricter isValidRedirectUri instead of isTrustedOrigin so
      // open-redirect attacks via path manipulation are blocked and only the
      // exact callback path is accepted.
      if (!isValidRedirectUri(redirectUri)) {
        res.status(400).json({ error: "Untrusted redirectUri" });
        return;
      }

      const params = new URLSearchParams({
        client_id: GITHUB_CLIENT_ID,
        redirect_uri: redirectUri,
        scope: "repo user",
      });

      res.json({
        url: `https://github.com/login/oauth/authorize?${params.toString()}`,
      });
    }
  );

  /**
   * GET /auth/callback  (and /auth/callback/)
   * Exchanges the GitHub OAuth code for an access token and relays it to the
   * opener via postMessage.
   */
  app.get(
    ["/auth/callback", "/auth/callback/"],
    rateLimit("auth", RATE_LIMIT_AUTH),
    async (req: Request, res: Response) => {
      const code = req.query.code;

      if (!code || typeof code !== "string") {
        res.status(400).send("No code provided.");
        return;
      }

      try {
        const ghResponse = await fetch(
          "https://github.com/login/oauth/access_token",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Accept: "application/json",
            },
            body: JSON.stringify({
              client_id: GITHUB_CLIENT_ID,
              client_secret: GITHUB_CLIENT_SECRET,
              code,
            }),
            signal: AbortSignal.timeout(15_000),
          }
        );

        if (!ghResponse.ok) {
          res.status(502).send("GitHub token exchange failed.");
          return;
        }

        const payload = (await ghResponse.json()) as Record<string, unknown>;
        const accessToken = payload.access_token;

        if (typeof accessToken !== "string" || !accessToken) {
          res.status(400).send("Failed to retrieve access token.");
          return;
        }

        const requestOrigin = req.headers.origin ?? "";
        const targetOrigin =
          isTrustedOrigin(requestOrigin) ? requestOrigin : null;

        if (!targetOrigin) {
          res.redirect("/");
          return;
        }

        const safeToken = JSON.stringify(accessToken);
        const safeOrigin = JSON.stringify(targetOrigin);

        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.setHeader(
          "Content-Security-Policy",
          "default-src 'none'; script-src 'unsafe-inline'"
        );
        res.send(
          `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Authenticating…</title></head>
<body>
<p>Authentication successful. This window will close automatically.</p>
<script>
(function(){
  var t=${safeToken};
  if(window.opener){
    window.opener.postMessage({type:'OAUTH_AUTH_SUCCESS',token:t},${safeOrigin});
    window.close();
  } else {
    window.location.href='/';
  }
})();
</script>
</body>
</html>`
        );
      } catch (error) {
        console.error("[/auth/callback]", error);
        res.status(500).send("Authentication failed.");
      }
    }
  );

  // ───────────────────────────────────────────────────────────────────────────
  // API Routes
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * GET /api/github/repos
   * Returns the authenticated user's repositories (up to 100, sorted by last update).
   */
  app.get(
    "/api/github/repos",
    rateLimit("repos", RATE_LIMIT_REPOS),
    async (req: Request, res: Response) => {
      const token = extractBearerToken(req);
      if (!token) {
        res.status(401).json({ error: "Unauthorized" });
        return;
      }

      const octokit = new Octokit({ auth: token });

      try {
        const { data } = await octokit.rest.repos.listForAuthenticatedUser({
          visibility: "all",
          sort: "updated",
          per_page: 100,
        });
        const slim = data.map(({ id, full_name, private: isPrivate }) => ({
          id,
          full_name,
          private: isPrivate,
        }));
        res.json(slim);
      } catch (error: unknown) {
        // "error.status" only exists on Octokit RequestError; plain network
        // errors (TypeError, etc.) don't have it. Cast safely.
        const err = error as { status?: number; message?: string };
        console.error("[/api/github/repos]", err.message);
        res.status(err.status ?? 500).json({ error: err.message ?? "Failed to fetch repositories" });
      }
    }
  );

  /**
   * POST /api/github/push
   * Accepts a ZIP file and atomically pushes its contents to a GitHub repository.
   */
  app.post(
    "/api/github/push",
    rateLimit("push", RATE_LIMIT_PUSH),
    upload.single("file"),
    async (req: Request, res: Response) => {
      const token = extractBearerToken(req);
      if (!token) {
        res.status(401).json({ error: "Unauthorized" });
        return;
      }

      const body = req.body as Record<string, string>;
      const owner = body.owner?.trim();
      const repo = body.repo?.trim();
      const branch = (body.branch?.trim()) || "main";
      const commitMessage =
        (body.commitMessage ?? "").trim().slice(0, 500) ||
        "Update from Zip Sync";
      const file = req.file;

      // ── Input validation ───────────────────────────────────────────────────
      if (!owner || !repo || !file) {
        res.status(400).json({ error: "Missing required fields: owner, repo, or file" });
        return;
      }
      if (!isValidGitHubName(owner)) {
        res.status(400).json({ error: "Invalid owner name" });
        return;
      }
      if (!isValidGitHubName(repo)) {
        res.status(400).json({ error: "Invalid repository name" });
        return;
      }
      if (!isValidBranchName(branch)) {
        res.status(400).json({ error: "Invalid branch name" });
        return;
      }

      const octokit = new Octokit({ auth: token });

      try {
        // ── 1. Parse ZIP, enforce safety limits, and sanitise paths ──────
        let zip: AdmZip;
        try {
          zip = new AdmZip(file.buffer);
        } catch {
          // AdmZip throws synchronously on corrupt / non-ZIP data.
          // Catch here specifically to return a 400 (user error) rather than
          // letting it bubble to the 500 handler.
          res.status(400).json({ error: "Invalid or corrupt ZIP file" });
          return;
        }

        const entries = zip.getEntries();

        // ZIP bomb protection — reject before extracting data.
        if (entries.length > ZIP_MAX_ENTRIES) {
          res.status(400).json({ error: `ZIP exceeds the maximum of ${ZIP_MAX_ENTRIES} entries` });
          return;
        }

        let totalUncompressed = 0;
        for (const entry of entries) {
          totalUncompressed += entry.header.size;
          if (totalUncompressed > ZIP_MAX_UNCOMPRESSED_BYTES) {
            res.status(400).json({ error: "ZIP uncompressed size exceeds the 500 MB limit" });
            return;
          }
        }

        const rawFiles: { path: string; content: Buffer }[] = [];

        for (const entry of entries) {
          if (entry.isDirectory) continue;

          const safePath = sanitiseZipPath(entry.entryName);
          if (!safePath) {
            console.warn(`[push] Skipping unsafe zip entry: ${entry.entryName}`);
            continue;
          }

          // FIX C: entry.getData() throws synchronously on password-encrypted
          // or individually corrupt entries (CRC mismatch). Wrapping per-entry
          // in a try/catch allows the rest of the archive to be processed rather
          // than crashing the entire request with a misleading 500 error.
          let content: Buffer;
          try {
            content = entry.getData();
          } catch (e) {
            console.warn(`[push] Skipping unreadable zip entry "${entry.entryName}":`, e);
            continue;
          }

          rawFiles.push({ path: safePath, content });
        }

        if (rawFiles.length === 0) {
          res.status(400).json({ error: "ZIP contains no valid files" });
          return;
        }

        // ── 2. Strip common root directory ──────────────────────────────
        const commonRoot = detectCommonRoot(rawFiles.map((f) => f.path));
        const filesToCommit = rawFiles
          .map((f) => ({
            ...f,
            path: commonRoot ? f.path.slice(commonRoot.length) : f.path,
          }))
          .filter((f) => f.path.length > 0);

        if (filesToCommit.length === 0) {
          res.status(400).json({ error: "ZIP contains no committable files after path normalisation" });
          return;
        }

        // ── 3. Resolve current branch tip (gracefully handles empty repos) ──
        let baseTreeSha = "";
        let parentCommitSha: string | null = null;

        try {
          const { data: refData } = await octokit.rest.git.getRef({
            owner,
            repo,
            ref: `heads/${branch}`,
          });
          parentCommitSha = refData.object.sha;

          const { data: commitData } = await octokit.rest.git.getCommit({
            owner,
            repo,
            commit_sha: parentCommitSha,
          });
          baseTreeSha = commitData.tree.sha;
        } catch (e: unknown) {
          const err = e as { status?: number };
          if (err.status === 404 || err.status === 409) {
            baseTreeSha = "";
          } else {
            throw e;
          }
        }

        // ── 4. Upload blobs in parallel batches ────────────────────────────
        const BATCH_SIZE = 5;
        const treeEntries: Array<{
          path: string;
          mode: "100644";
          type: "blob";
          sha: string;
        }> = [];

        for (let i = 0; i < filesToCommit.length; i += BATCH_SIZE) {
          const batch = filesToCommit.slice(i, i + BATCH_SIZE);
          const blobs = await Promise.all(
            batch.map((f) =>
              octokit.rest.git.createBlob({
                owner,
                repo,
                content: f.content.toString("base64"),
                encoding: "base64",
              })
            )
          );

          for (let j = 0; j < batch.length; j++) {
            treeEntries.push({
              path: batch[j].path,
              mode: "100644",
              type: "blob",
              sha: blobs[j].data.sha,
            });
          }
        }

        // ── 5. Create Git tree ─────────────────────────────────────────────
        const { data: newTree } = await octokit.rest.git.createTree({
          owner,
          repo,
          tree: treeEntries,
          ...(baseTreeSha ? { base_tree: baseTreeSha } : {}),
        });

        // ── 6. Create commit ───────────────────────────────────────────────
        const { data: newCommit } = await octokit.rest.git.createCommit({
          owner,
          repo,
          message: commitMessage,
          tree: newTree.sha,
          parents: parentCommitSha ? [parentCommitSha] : [],
        });

        // ── 7. Update or create branch ref ────────────────────────────────
        // FIX D: Pass force: false explicitly on updateRef so the API call
        // is guaranteed to be a fast-forward only. Without this flag the
        // GitHub API defaults to false, but being explicit documents intent
        // and guards against a future API change or library default shift.
        if (parentCommitSha) {
          await octokit.rest.git.updateRef({
            owner,
            repo,
            ref: `heads/${branch}`,
            sha: newCommit.sha,
            force: false,
          });
        } else {
          await octokit.rest.git.createRef({
            owner,
            repo,
            ref: `refs/heads/${branch}`,
            sha: newCommit.sha,
          });
        }

        // FIX E: Return a direct link to the specific commit (immutable)
        // rather than the branch HEAD (which changes on every push). The
        // branch URL is also returned for convenience.
        res.json({
          success: true,
          commitSha: newCommit.sha,
          branch,
          url: `https://github.com/${owner}/${repo}/commit/${newCommit.sha}`,
          branchUrl: `https://github.com/${owner}/${repo}/tree/${branch}`,
        });
      } catch (error: unknown) {
        // Safe cast instead of "any" for predictable status extraction.
        const err = error as { status?: number; message?: string };
        console.error("[/api/github/push]", err.message);
        res.status(err.status ?? 500).json({
          error: err.message || "Failed to push to GitHub",
        });
      }
    }
  );

  // ───────────────────────────────────────────────────────────────────────────
  // Static / Vite dev middleware
  // ───────────────────────────────────────────────────────────────────────────
  if (!IS_PROD) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath, { maxAge: "1d" }));
    // SPA fallback — must NOT match /api/* routes so missing API paths
    // return 404 JSON rather than silently serving index.html
    app.get(/^(?!\/api\/).*/, (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Global error handler (catches multer errors + unhandled route errors)
  // ───────────────────────────────────────────────────────────────────────────
  app.use((err: Error & { code?: string }, _req: Request, res: Response, _next: NextFunction) => {
    // Identify multer rejections via the structured error code
    // rather than brittle message-string matching.
    if (err.code === "INVALID_FILE_TYPE") {
      res.status(400).json({ error: err.message });
      return;
    }
    // Multer's built-in file-size error uses the code "LIMIT_FILE_SIZE".
    if (err.code === "LIMIT_FILE_SIZE") {
      res.status(413).json({ error: "File exceeds the 50 MB size limit" });
      return;
    }
    console.error("[unhandled error]", err);
    res.status(500).json({ error: "Internal server error" });
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT} [${IS_PROD ? "production" : "development"}]`);
  });
}

startServer().catch((err: Error) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
