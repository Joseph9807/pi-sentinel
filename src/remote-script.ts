import { lookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";
import { Readable } from "node:stream";
import { withAbort } from "./abort.ts";

const MAX_BYTES = 64 * 1024;
const MAX_REDIRECTS = 5;
const blocked = new BlockList();

for (const [address, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
  ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(address, prefix, "ipv4");
for (const [address, prefix] of [
  ["::", 128], ["::1", 128], ["64:ff9b:1::", 48], ["100::", 64],
  ["2001:db8::", 32], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8],
] as const) blocked.addSubnet(address, prefix, "ipv6");

export interface RemoteScriptInspection {
  preview?: string;
  truncated?: boolean;
  description: string;
  unavailableReason?: string;
}

interface RequestOptions {
  signal: AbortSignal;
  redirect: "manual";
  headers: { accept: string };
  address: string;
  family: 4 | 6;
}

export interface InspectionOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  request?: (url: string, options: RequestOptions) => Promise<Response>;
}

export async function inspectRemoteScript(url: string, options: InspectionOptions = {}): Promise<RemoteScriptInspection> {
  const timeout = AbortSignal.timeout(options.timeoutMs ?? 5_000);
  const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;
  const request = options.request ?? requestPinned;
  let current: URL;
  try {
    current = new URL(url);
  } catch {
    return unavailable("the URL is invalid");
  }

  try {
    for (let redirects = 0; ; redirects++) {
      const destination = await requirePublicHttpAddress(current, signal);
      const response = await request(current.href, {
        signal,
        redirect: "manual",
        headers: { accept: "text/*, application/javascript, application/x-sh;q=0.9" },
        ...destination,
      });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        if (redirects >= MAX_REDIRECTS) return unavailable(`more than ${MAX_REDIRECTS} redirects were returned`);
        const location = response.headers.get("location");
        if (!location) return unavailable("a redirect did not include a destination");
        await response.body?.cancel();
        current = new URL(location, current);
        continue;
      }
      if (!response.ok) return unavailable(`the server returned HTTP ${response.status}`);
      if (!isTextContent(response.headers.get("content-type"))) return unavailable("the response was not text content");
      return await readPreview(response);
    }
  } catch (error) {
    if (options.signal?.aborted) throw options.signal.reason;
    if (timeout.aborted || (error instanceof DOMException && error.name === "TimeoutError")) return unavailable("the request timed out");
    return unavailable(error instanceof Error ? error.message : "the download failed");
  }
}

async function requirePublicHttpAddress(url: URL, signal: AbortSignal): Promise<{ address: string; family: 4 | 6 }> {
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("the destination is not a public HTTP(S) address");
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (hostname.toLowerCase() === "localhost") throw new Error("the destination is not a public address");
  const family = isIP(hostname);
  const addresses = family
    ? [{ address: hostname, family }]
    : await withAbort(lookup(hostname, { all: true, verbatim: true }), signal);
  if (addresses.length === 0 || addresses.some(({ address, family: addressFamily }) => blocked.check(address, addressFamily === 6 ? "ipv6" : "ipv4"))) {
    throw new Error("the destination is not a public address");
  }
  return addresses[0] as { address: string; family: 4 | 6 };
}

function requestPinned(url: string, options: RequestOptions): Promise<Response> {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const request = target.protocol === "https:" ? httpsRequest : httpRequest;
    const req = request(target, {
      signal: options.signal,
      headers: options.headers,
      lookup: (_hostname, _lookupOptions, callback) => callback(null, options.address, options.family),
    }, (response) => {
      const headers = new Headers();
      for (const [key, value] of Object.entries(response.headers)) {
        if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
      }
      resolve(new Response(Readable.toWeb(response) as ReadableStream<Uint8Array>, {
        status: response.statusCode,
        statusText: response.statusMessage,
        headers,
      }));
    });
    req.on("error", reject);
    req.end();
  });
}

function isTextContent(value: string | null): boolean {
  const type = value?.split(";", 1)[0].trim().toLowerCase();
  return !!type && (type.startsWith("text/") || ["application/javascript", "application/x-javascript", "application/x-sh"].includes(type));
}

async function readPreview(response: Response): Promise<RemoteScriptInspection> {
  const reader = response.body?.getReader();
  if (!reader) return { preview: "", truncated: false, description: "The empty script was inspected." };
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  let truncated = Number(response.headers.get("content-length")) > MAX_BYTES;
  while (bytes < MAX_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    const remaining = MAX_BYTES - bytes;
    chunks.push(value.subarray(0, remaining));
    bytes += Math.min(value.byteLength, remaining);
    if (value.byteLength > remaining || bytes === MAX_BYTES) {
      if (value.byteLength > remaining) truncated = true;
      else if (!truncated) truncated = !(await reader.read()).done;
      await reader.cancel();
      break;
    }
  }
  const preview = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), bytes).toString("utf8");
  return {
    preview,
    truncated,
    description: truncated
      ? `Only the first ${MAX_BYTES} bytes were partially inspected.`
      : `The first ${bytes} bytes were inspected.`,
  };
}

function unavailable(reason: string): RemoteScriptInspection {
  return { description: `Inspection unavailable: ${reason}.`, unavailableReason: reason };
}
