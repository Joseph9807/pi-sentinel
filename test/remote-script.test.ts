import assert from "node:assert/strict";
import test from "node:test";
import { inspectRemoteScript } from "../src/remote-script.ts";

const publicUrl = "https://93.184.216.34/install.sh";

test("remote script inspection rejects private destinations and revalidates redirects", async () => {
  let requests = 0;
  const request = async () => {
    requests++;
    return new Response(null, { status: 302, headers: { location: "http://127.0.0.1/install.sh" } });
  };

  assert.match((await inspectRemoteScript("http://127.0.0.1/install.sh", { request })).unavailableReason ?? "", /public/i);
  assert.equal(requests, 0);
  assert.match((await inspectRemoteScript(publicUrl, { request })).unavailableReason ?? "", /public/i);
  assert.equal(requests, 1);
});

test("remote script inspection handles timeout and non-text content", async () => {
  const timeout = await inspectRemoteScript(publicUrl, {
    timeoutMs: 1,
    request: async (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
    }),
  });
  assert.match(timeout.unavailableReason ?? "", /timed out/i);

  const binary = await inspectRemoteScript(publicUrl, {
    request: async () => new Response("binary", { headers: { "content-type": "application/octet-stream" } }),
  });
  assert.match(binary.unavailableReason ?? "", /text content/i);
});

test("remote script inspection returns at most 64KB and marks larger scripts as partial", async () => {
  const result = await inspectRemoteScript(publicUrl, {
    request: async () => new Response(`#!/bin/sh\n${"x".repeat(64 * 1024)}`, { headers: { "content-type": "text/plain" } }),
  });

  assert.equal(result.preview?.length, 64 * 1024);
  assert.equal(result.truncated, true);
  assert.match(result.description, /partially inspected/i);

  const exact = await inspectRemoteScript(publicUrl, {
    request: async () => new Response("x".repeat(64 * 1024), { headers: { "content-type": "text/plain" } }),
  });
  assert.equal(exact.preview?.length, 64 * 1024);
  assert.equal(exact.truncated, false);
});
