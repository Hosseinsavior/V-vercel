export const config = {
  runtime: "edge",
};

const TARGET_BASE = (process.env.TARGET_DOMAIN || "").replace(/\/$/, "");
const PLATFORM_HEADER_PREFIX = `x-${String.fromCharCode(118, 101, 114, 99, 101, 108)}-`;
const RELAY_PATH = normalizeRelayPath(process.env.RELAY_PATH || "");
const RELAY_KEY = (process.env.RELAY_KEY || "").trim();
const UPSTREAM_TIMEOUT_MS = parsePositiveInt(process.env.UPSTREAM_TIMEOUT_MS, 120000);
const ALLOWED_METHODS = new Set(["GET", "HEAD", "POST"]);
const FORWARD_HEADER_EXACT = new Set([
  "accept",
  "accept-encoding",
  "accept-language",
  "cache-control",
  "content-length",
  "content-type",
  "pragma",
  "range",
  "referer",
  "user-agent",
]);
const FORWARD_HEADER_PREFIXES = ["sec-ch-", "sec-fetch-"];

const STRIP_HEADERS = new Set([
  "host",
  "connection",
  "proxy-connection",
  "keep-alive",
  "via",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "forwarded",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-forwarded-for",
  "x-real-ip",
]);

export default async function handler(req) {
  if (!TARGET_BASE) {
    return new Response("Misconfigured: TARGET_DOMAIN is not set", { status: 500 });
  }
  if (!RELAY_PATH) {
    return new Response("Misconfigured: RELAY_PATH is not set", { status: 500 });
  }
  if (RELAY_PATH === "/") {
    return new Response("Misconfigured: RELAY_PATH cannot be '/'", { status: 500 });
  }
  if (RELAY_KEY && RELAY_KEY.length < 16) {
    return new Response("Misconfigured: RELAY_KEY is too short", { status: 500 });
  }

  const url = new URL(req.url);
  if (!isAllowedRelayPath(url.pathname)) {
    return new Response("Not Found", { status: 404 });
  }

  if (!ALLOWED_METHODS.has(req.method)) {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { allow: "GET, HEAD, POST" },
    });
  }

  if (RELAY_KEY) {
    const token = req.headers.get("x-relay-key") || "";
    if (token !== RELAY_KEY) {
      return new Response("Forbidden", { status: 403 });
    }
  }

  try {
    const upstreamQuery = new URLSearchParams(url.search);
    const query = upstreamQuery.toString();
    const targetUrl = `${TARGET_BASE}${url.pathname}${query ? `?${query}` : ""}`;

    const headers = new Headers();
    const clientIp = req.headers.get("x-real-ip") || req.headers.get("x-forwarded-for");
    for (const [key, value] of req.headers) {
      const k = key.toLowerCase();
      if (STRIP_HEADERS.has(k)) continue;
      if (k.startsWith(PLATFORM_HEADER_PREFIX)) continue;
      if (k === "x-relay-key") continue;
      if (!shouldForwardHeader(k)) continue;
      headers.set(k, value);
    }
    if (clientIp) headers.set("x-forwarded-for", clientIp);

    const method = req.method;
    const hasBody = method !== "GET" && method !== "HEAD";
    const abortCtrl = new AbortController();
    const timeout = setTimeout(() => abortCtrl.abort("upstream_timeout"), UPSTREAM_TIMEOUT_MS);

    const fetchOpts = {
      method,
      headers,
      redirect: "manual",
      signal: abortCtrl.signal,
    };
    if (hasBody) {
      fetchOpts.body = req.body;
      fetchOpts.duplex = "half";
    }

    const upstream = await fetch(targetUrl, fetchOpts).finally(() => clearTimeout(timeout));

    const respHeaders = new Headers();
    for (const [k, v] of upstream.headers) {
      if (k.toLowerCase() === "transfer-encoding") continue;
      respHeaders.set(k, v);
    }

    return new Response(upstream.body, {
      status: upstream.status,
      headers: respHeaders,
    });
  } catch (err) {
    if (err?.name === "AbortError") {
      console.error("relay timeout", { path: url.pathname, method: req.method });
      return new Response("Gateway Timeout: Upstream Timeout", { status: 504 });
    }
    console.error("relay error", { path: url.pathname, method: req.method, error: String(err) });
    return new Response("Bad Gateway: Tunnel Failed", { status: 502 });
  }
}

function shouldForwardHeader(headerName) {
  if (FORWARD_HEADER_EXACT.has(headerName)) return true;
  for (const prefix of FORWARD_HEADER_PREFIXES) {
    if (headerName.startsWith(prefix)) return true;
  }
  return false;
}

function isAllowedRelayPath(pathname) {
  return pathname === RELAY_PATH || pathname.startsWith(`${RELAY_PATH}/`);
}

function normalizeRelayPath(rawPath) {
  if (!rawPath) return "";
  const path = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;
  if (path.length > 1 && path.endsWith("/")) return path.slice(0, -1);
  return path;
}

function parsePositiveInt(rawValue, fallbackValue) {
  const value = Number(rawValue);
  if (!Number.isFinite(value)) return fallbackValue;
  if (value < 1000) return fallbackValue;
  return Math.trunc(value);
}
