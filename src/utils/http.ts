import { spawn } from "node:child_process";
import { mkdir, mkdtemp, open, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

// APKMirror sits behind Cloudflare, which challenges automated traffic by
// fingerprinting the client's TLS handshake. Node's fetch (undici) is
// reliably flagged, while curl passes, so all requests go through curl.
const USER_AGENT =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

const CHALLENGE_MARKER = "Enable JavaScript and cookies to continue";

const HTML_ACCEPT =
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";

type CurlResponse = {
  status: number;
  url: string;
  redirected: boolean;
  bodyPath: string;
};

type CurlOptions = {
  headers?: string[];
  timeoutSeconds?: number;
};

type CurlTextOptions = CurlOptions & {
  attempts?: number;
  backoffMs?: number;
};

type CurlDownloadOptions = CurlTextOptions & {
  workDir: string;
};

let cookieJar: string | undefined;

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function getCookieJar() {
  if (!cookieJar) {
    const dir = await mkdtemp(join(tmpdir(), "apkmd-"));
    cookieJar = join(dir, "cookies.txt");
  }
  return cookieJar;
}

function runCurl(args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("curl", args, {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", chunk => (stdout += chunk));
    child.stderr.on("data", chunk => (stderr += chunk));

    child.on("error", err => {
      reject(
        new Error(
          "curl command not found. It is required to fetch pages from APKMirror (their Cloudflare protection blocks other HTTP clients).",
          { cause: err },
        ),
      );
    });

    child.on("close", code => {
      if (code === 0) {
        resolve(stdout);
      } else {
        reject(new Error(`curl exited with code ${code}: ${stderr.trim()}`));
      }
    });
  });
}

async function curlOnce(
  url: string,
  { headers = [], timeoutSeconds = 120 }: CurlOptions = {},
): Promise<CurlResponse> {
  const jar = await getCookieJar();
  const dir = await mkdtemp(join(tmpdir(), "apkmd-"));
  const bodyPath = join(dir, "body");

  const meta = await runCurl([
    "--silent",
    "--show-error",
    "--location",
    "--compressed",
    "--cookie",
    jar,
    "--cookie-jar",
    jar,
    "--user-agent",
    USER_AGENT,
    ...headers.flatMap(header => ["--header", header]),
    "--max-time",
    String(timeoutSeconds),
    "--output",
    bodyPath,
    "--write-out",
    "%{http_code}\\t%{url_effective}\\t%{num_redirects}",
    url,
  ]);

  const metaLine = meta.trim().split("\n").pop() ?? "";
  const [statusField, effectiveUrl, redirectsField] = metaLine.split("\t");
  const status = Number(statusField);
  const numRedirects = Number(redirectsField);

  return {
    status,
    url: effectiveUrl || url,
    redirected: Number.isFinite(numRedirects)
      ? numRedirects > 0
      : effectiveUrl !== url,
    bodyPath,
  };
}

async function readFirstBytes(path: string, length: number): Promise<string> {
  const handle = await open(path, "r");
  try {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, 0);
    return buffer.toString("latin1", 0, bytesRead);
  } finally {
    await handle.close();
  }
}

function cleanupBody(bodyPath: string) {
  return rm(dirname(bodyPath), { recursive: true, force: true });
}

function isBlocked(status: number, body: string) {
  return status === 403 || body.includes(CHALLENGE_MARKER);
}

/**
 * Fetch a page as text through curl, retrying when Cloudflare serves a
 * challenge. Retries share the process-wide cookie jar, so a cleared
 * challenge is kept for later requests.
 */
export async function curlText(
  url: string,
  { attempts = 3, backoffMs = 5000, ...options }: CurlTextOptions = {},
): Promise<{
  status: number;
  url: string;
  redirected: boolean;
  text: string;
}> {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    let res: CurlResponse;
    try {
      res = await curlOnce(url, {
        ...options,
        headers: [
          `Accept: ${HTML_ACCEPT}`,
          "Accept-Language: en-US,en;q=0.9",
          ...(options.headers ?? []),
        ],
      });
    } catch (err) {
      if (attempt === attempts) throw err;
      await sleep(backoffMs);
      continue;
    }

    const text = await readFile(res.bodyPath, "utf8");
    await cleanupBody(res.bodyPath);

    if (!isBlocked(res.status, text)) {
      if (res.status >= 400) {
        throw new Error(`HTTP ${res.status} while fetching ${res.url}`);
      }
      return {
        status: res.status,
        url: res.url,
        redirected: res.redirected,
        text,
      };
    }

    if (attempt === attempts) {
      throw new Error(
        `Blocked by Cloudflare (HTTP ${res.status}) while fetching ${res.url} after ${attempts} attempts. Try again later or from a different network.`,
      );
    }
    await sleep(backoffMs);
  }

  throw new Error(`Could not fetch ${url}`);
}

/**
 * Download a file through curl into a temporary directory inside `workDir`
 * (same filesystem as the final destination, so it can be renamed into
 * place). Returns the effective (post-redirect) URL and the temp file path.
 */
export async function curlDownloadFile(
  url: string,
  { workDir, attempts = 3, backoffMs = 5000, ...options }: CurlDownloadOptions,
): Promise<{ url: string; bodyPath: string }> {
  await mkdir(workDir, { recursive: true });

  for (let attempt = 1; attempt <= attempts; attempt++) {
    let res: CurlResponse;
    try {
      res = await curlOnce(url, {
        ...options,
        timeoutSeconds: options.timeoutSeconds ?? 600,
      });
    } catch (err) {
      if (attempt === attempts) throw err;
      await sleep(backoffMs);
      continue;
    }

    if (res.status >= 200 && res.status < 300) {
      // A challenge page can be served with a 200 status; a real APK never
      // starts like HTML.
      const head = await readFirstBytes(res.bodyPath, 4096);
      if (
        !head.trimStart().startsWith("<") &&
        !head.includes(CHALLENGE_MARKER)
      ) {
        return { url: res.url, bodyPath: res.bodyPath };
      }
      await cleanupBody(res.bodyPath);
    } else {
      await cleanupBody(res.bodyPath);
      if (res.status >= 400 && res.status < 500 && res.status !== 403) {
        throw new Error(
          `Download failed with HTTP ${res.status} for ${res.url}`,
        );
      }
    }

    if (attempt === attempts) {
      throw new Error(
        `Download blocked by Cloudflare (HTTP ${res.status}) after ${attempts} attempts: ${res.url}`,
      );
    }
    await sleep(backoffMs);
  }

  throw new Error(`Could not download ${url}`);
}
