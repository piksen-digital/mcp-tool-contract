import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { fetchText } from "../src/fetch.js";

async function start(handler) {
  const server = http.createServer(handler);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

function stop(server) {
  return new Promise((r) => server.close(r));
}

function twoHop(req, res) {
  if (req.url === "/start") return res.writeHead(302, { location: "/middle" }).end();
  if (req.url === "/middle") return res.writeHead(302, { location: "/final" }).end();
  if (req.url === "/final") return res.writeHead(200, { "content-type": "text/plain" }).end("ok");
  res.writeHead(404).end();
}

test("follows 2 redirects when maxRedirects=2", async () => {
  const { server, baseUrl } = await start(twoHop);
  try {
    const r = await fetchText(`${baseUrl}/start`, 2000, 2);
    assert.equal(r.text, "ok");
    assert.equal(r.redirectsFollowed, 2);
    assert.equal(r.finalUrl, `${baseUrl}/final`);
  } finally {
    await stop(server);
  }
});

test("rejects when maxRedirects=1 on a 2-hop chain", async () => {
  const { server, baseUrl } = await start(twoHop);
  try {
    await assert.rejects(
      fetchText(`${baseUrl}/start`, 2000, 1),
      /Exceeded maxRedirects \(1\)/
    );
  } finally {
    await stop(server);
  }
});

test("rejects when maxRedirects=0 on a 1-hop chain", async () => {
  const { server, baseUrl } = await start((req, res) => {
    res.writeHead(302, { location: "/final" }).end();
  });
  try {
    await assert.rejects(
      fetchText(`${baseUrl}/start`, 2000, 0),
      /Exceeded maxRedirects \(0\)/
    );
  } finally {
    await stop(server);
  }
});

test("rejects redirect without Location header", async () => {
  const { server, baseUrl } = await start((req, res) => {
    res.writeHead(302).end();
  });
  try {
    await assert.rejects(
      fetchText(`${baseUrl}/x`, 2000, 5),
      /Redirect 302 without Location header/
    );
  } finally {
    await stop(server);
  }
});

test("rejects HTTP 4xx from final URL", async () => {
  const { server, baseUrl } = await start((req, res) => {
    res.writeHead(404).end();
  });
  try {
    await assert.rejects(
      fetchText(`${baseUrl}/missing`, 2000, 5),
      /HTTP 404/
    );
  } finally {
    await stop(server);
  }
});

test("0 redirects on a direct 200", async () => {
  const { server, baseUrl } = await start((req, res) => {
    res.writeHead(200, { "content-type": "text/plain" }).end("direct");
  });
  try {
    const r = await fetchText(`${baseUrl}/direct`, 2000, 5);
    assert.equal(r.text, "direct");
    assert.equal(r.redirectsFollowed, 0);
  } finally {
    await stop(server);
  }
});
