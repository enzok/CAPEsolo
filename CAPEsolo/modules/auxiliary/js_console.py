import hashlib
import json
import logging
import os
import subprocess

from lib.common.abstracts import Auxiliary
from lib.common.constants import OPT_CURDIR, PATHS
from lib.common.defines import SHELL32
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)
INTERCEPTOR_FILE_NAME = "js_interceptor.js"

INTERCEPTOR_TEMPLATE = """ (() => {
  // Suppress Node.js internal deprecation warnings at the process level
  if (typeof process !== "undefined" && typeof process.on === "function") {
    process.on("warning", (warning) => {
      if (warning.code === "DEP0040" || warning.code === "DEP0190") return;
    });
  }

  const fs = require("fs");
  const path = require("path");
  const zlib = require("zlib");
  const MAX_BODY_CHARS = 4096;
  const MAX_INLINE_BYTES = 4096;   // small text TCP payloads log inline; larger/binary go to a file
  let bufferSeq = 0;
  const bufferBytesWritten = Object.create(null);   // buffer file path -> bytes written so far
  const streamToFile = Object.create(null);   // stream name -> true once it has committed to a file
  // Per-process tag so buffer files can't collide across processes when Windows reuses a PID.
  const bufferRunTag = Math.random().toString(36).slice(2, 10);

  // Store the original functions
  const originalSetTimeout = global.setTimeout;
  const originalSetInterval = global.setInterval;

  // NODE_OPTIONS reaches every node process, npm and friends included, and overriding
  // global.setTimeout reaches a bare setTimeout inside any required module. A package
  // manager races its request timeout against the HTTP response, so a 1ms delay makes
  // the timer always win and every registry fetch dies as "network timeout" in
  // milliseconds. A delay threshold cannot separate the two cases - npm's default
  // fetch-timeout is 300000ms, squarely inside the range of sleeps worth skipping - so
  // exempt the package managers by name and leave their timers alone. Everything else
  // in this interceptor still applies to them.
  const isPackageManager = /(npm-cli|npx-cli|yarn|pnpm)\\.[cm]?js$/i.test(
    (typeof process !== "undefined" && process.argv && process.argv[1]) || ""
  );

  if (!isPackageManager) {
    // Override setTimeout
    global.setTimeout = (callback, delay, ...args) => {
        // Force all delays to 1ms regardless of what the script asks for
        return originalSetTimeout(callback, 1, ...args);
    };

    // Override setInterval
    global.setInterval = (callback, delay, ...args) => {
        return originalSetInterval(callback, 1, ...args);
    };
  }
  const logPath = "@LOG_PATH@";

  function safeAppendJson(obj) {
    try {
      fs.mkdirSync(path.dirname(logPath), { recursive: true });
      fs.appendFileSync(logPath, JSON.stringify(obj) + "\\n", "utf8");
    } catch (_) {}
  }

  function nowIso() { return new Date().toISOString(); }

  function safeToString(v) {
    if (typeof v === "string") return v;
    try {
      // Render Buffers/typed arrays as a short marker instead of the giant integer array
      // JSON.stringify would emit ({"type":"Buffer","data":[...]}), which bloats the log.
      return JSON.stringify(v, (k, val) => {
        if (typeof Buffer !== "undefined" && Buffer.isBuffer(val)) return `<Buffer ${val.length} bytes>`;
        if (val && val.type === "Buffer" && Array.isArray(val.data)) return `<Buffer ${val.data.length} bytes>`;
        return val;
      });
    } catch { return String(v); }
  }

  function truncate(s, limit = MAX_BODY_CHARS) {
    if (typeof s !== "string") s = safeToString(s);
    if (s.length <= limit) return { text: s, truncated: false };
    return { text: s.slice(0, limit), truncated: true };
  }

  function normalizeHeaders(headersLike) {
    try {
      if (!headersLike) return {};
      if (typeof Headers !== "undefined" && headersLike instanceof Headers) return Object.fromEntries(headersLike.entries());
      if (Array.isArray(headersLike)) return Object.fromEntries(headersLike);
      return { ...headersLike };
    } catch {
      return {};
    }
  }

  function normalizeUrl(url) {
    try { return url.toString(); } catch { return String(url); }
  }

  function safeCall(fn, fallback = null) {
    try { return fn(); } catch { return fallback; }
  }

  function toBodyLog(value) {
    if (value === undefined || value === null) return null;
    const t = truncate(safeToString(value));
    return { text: t.text, truncated: t.truncated };
  }

  function headerValue(headers, name) {
    // Case-insensitive header lookup. Node's res.headers are lowercased, but request headers set by
    // the sample can be any case.
    if (!headers) return "";
    const want = name.toLowerCase();
    for (const k in headers) {
      if (k.toLowerCase() === want) return headers[k];
    }
    return "";
  }

  function decodeBody(buffer, encoding) {
    // Decompress a raw HTTP body by Content-Encoding so it logs as readable text rather than
    // compressed bytes. require("http")/https hand back the raw body (fetch/axios auto-decode).
    // Unknown/empty encoding or any failure -> return the buffer unchanged.
    try {
      const enc = safeToString(encoding || "").toLowerCase();
      if (enc.includes("gzip")) return zlib.gunzipSync(buffer);
      if (enc.includes("br")) return zlib.brotliDecompressSync(buffer);
      if (enc.includes("deflate")) {
        try { return zlib.inflateSync(buffer); } catch (_) { return zlib.inflateRawSync(buffer); }
      }
    } catch (_) {}
    return buffer;
  }

  function appendBuffer(streamName, chunk) {
    // Append raw bytes to the per-stream working file and return a compact descriptor for the log
    // (stream id + this chunk's size + its offset in the stream) instead of the huge integer array
    // JSON.stringify(Buffer) would produce. finish() hashes the completed file and uploads it as a
    // dropped file named by sha256; the host links events to that hash via the stream id.
    let buf;
    try { buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); }
    catch (e) { return { error: safeToString(e) }; }
    const full = path.join(path.dirname(logPath), "js_buffers", streamName);
    try {
      const offset = bufferBytesWritten[full] || 0;
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.appendFileSync(full, buf);
      bufferBytesWritten[full] = offset + buf.length;
      return { stream: streamName, bytes: buf.length, offset };
    } catch (e) {
      return { error: safeToString(e), bytes: buf.length };
    }
  }

  function isProbablyText(buf) {
    // Cheap heuristic: a NUL byte or a high ratio of control chars (allowing \\t\\n\\v\\f\\r) means binary.
    const n = buf.length;
    if (n === 0) return true;
    let suspicious = 0;
    for (let i = 0; i < n; i++) {
      const c = buf[i];
      if (c === 0) return false;
      if (c < 0x09 || (c > 0x0d && c < 0x20)) suspicious++;
    }
    return suspicious / n < 0.1;
  }

  function tcpBody(streamName, chunk) {
    // Route a whole stream-direction to at most one file, decided per stream (not per chunk): once any
    // chunk is large or binary the stream "commits" to its file and every later chunk - including a
    // small text tail like a gzip trailer - is appended there too, so the reassembled file is never
    // truncated. A stream that stays small and text-only never creates a file, which keeps a sample
    // that opens many tiny connections from dropping hundreds of buffer files. Committed streams still
    // carry an inline text preview for small chunks so the log stays readable.
    if (chunk === undefined || chunk === null) return null;
    let buf;
    try { buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); }
    catch (e) { return { error: safeToString(e) }; }

    const smallText = buf.length <= MAX_INLINE_BYTES && isProbablyText(buf);
    if (smallText && !streamToFile[streamName]) {
      const t = truncate(buf.toString("utf8"));
      return { text: t.text, truncated: t.truncated };
    }

    const ref = appendBuffer(streamName, buf);
    if (ref.error) {
      // File append failed; fall back to inline for small text so the payload is not lost entirely.
      if (smallText) {
        const t = truncate(buf.toString("utf8"));
        return { text: t.text, truncated: t.truncated };
      }
      return ref;
    }
    streamToFile[streamName] = true;
    if (smallText) {
      const t = truncate(buf.toString("utf8"));
      ref.text = t.text;
      ref.truncated = t.truncated;
    }
    return ref;
  }

  function nodeRequestMeta(input, options) {
    let url = "";
    let method = "GET";
    let headers = {};
    try {
      if (typeof input === "string" || (typeof URL !== "undefined" && input instanceof URL)) {
        url = normalizeUrl(input);
      } else if (input && typeof input === "object") {
        method = input.method || method;
        headers = input.headers || headers;
        const protocol = input.protocol || "http:";
        const host = input.hostname || input.host || "localhost";
        const port = input.port ? `:${input.port}` : "";
        const path = input.path || input.pathname || "/";
        url = `${protocol}//${host}${port}${path}`;
      }

      if (options && typeof options === "object") {
        method = options.method || method;
        headers = options.headers || headers;
      }
    } catch (_) {}
    return { url, method, headers };
  }

  let seq = 0;

  function installEvalHook() {
    if (typeof globalThis.eval !== "function") return;
    if (globalThis.eval.__jsInterceptorWrapped) return;
    const originalEval =globalThis.eval;
    const wrappedEval = function(code) {
      safeAppendJson({
        ts: nowIso(),
        source: "js_interceptor",
        event: "eval",
        body: toBodyLog(code),
      });
      return originalEval(code);
    };
    wrappedEval.__jsInterceptorWrapped = true;
    globalThis.eval = wrappedEval;
  }

  function installHttpLikeHook(mod, modName) {
    if (!mod || typeof mod.request !== "function" || mod.__jsInterceptorWrapped) return;
    mod.__jsInterceptorWrapped = true;

    const originalRequest = mod.request.bind(mod);
    mod.request = function(input, options, callback) {
      const request_id = ++seq;
      const meta = nodeRequestMeta(input, options);
      const started = Date.now();
      const reqBodyChunks = [];

      safeAppendJson({
        ts: nowIso(),
        source: "js_interceptor",
        event: "http_request",
        request_id,
        method: meta.method,
        url: meta.url,
        transport: modName,
        headers: normalizeHeaders(meta.headers),
        body: null,
      });

      const req = originalRequest(input, options, callback);
      const originalWrite = typeof req.write === "function" ? req.write.bind(req) : null;
      const originalEnd = typeof req.end === "function" ? req.end.bind(req) : null;

      if (originalWrite) {
        req.write = function(chunk, encoding, cb) {
          if (chunk !== undefined && chunk !== null) reqBodyChunks.push(Buffer.from(chunk));
          return originalWrite(chunk, encoding, cb);
        };
      }

      if (originalEnd) {
        req.end = function(chunk, encoding, cb) {
          if (chunk !== undefined && chunk !== null) reqBodyChunks.push(Buffer.from(chunk));
          let bodyText = null;
          if (reqBodyChunks.length) {
            const reqEnc = headerValue(meta.headers, "content-encoding");
            bodyText = decodeBody(Buffer.concat(reqBodyChunks), reqEnc).toString("utf8");
          }
          safeAppendJson({
            ts: nowIso(),
            source: "js_interceptor",
            event: "http_request_body",
            request_id,
            body: toBodyLog(bodyText),
          });
          return originalEnd(chunk, encoding, cb);
        };
      }

      req.on("response", (res) => {
        const chunks = [];
        res.on("data", (c) => {
          if (c !== undefined && c !== null) chunks.push(Buffer.from(c));
        });
        res.on("end", () => {
          const raw = chunks.length ? Buffer.concat(chunks) : Buffer.alloc(0);
          const text = decodeBody(raw, res.headers && res.headers["content-encoding"]).toString("utf8");
          const t = truncate(text);
          safeAppendJson({
            ts: nowIso(),
            source: "js_interceptor",
            event: "http_response",
            request_id,
            transport: modName,
            status: res.statusCode,
            status_text: res.statusMessage || "",
            headers: normalizeHeaders(res.headers),
            body: { text: t.text, truncated: t.truncated, unreadable: false },
            elapsed_ms: Date.now() - started,
          });
        });
      });

      req.on("error", (err) => {
        safeAppendJson({
          ts: nowIso(),
          source: "js_interceptor",
          event: "http_error",
          request_id,
          transport: modName,
          elapsed_ms: Date.now() - started,
          error: safeToString(err),
        });
      });

      return req;
    };

    if (typeof mod.get === "function") {
      const originalGet = mod.get.bind(mod);
      mod.get = function(...args) {
        const req = mod.request(...args);
        req.end();
        return req;
      };
      mod.get.__jsInterceptorWrapped = !!originalGet;
    }
  }

  function installAxiosHook(axiosMod) {
    if (!axiosMod || axiosMod.__jsInterceptorWrapped) return;
    axiosMod.__jsInterceptorWrapped = true;

    function wrapAxiosInstance(instance) {
      if (!instance || typeof instance.request !== "function" || instance.__jsInterceptorWrapped) return;
      instance.__jsInterceptorWrapped = true;
      const originalRequest = instance.request.bind(instance);
      instance.request = async function(config = {}) {
        const request_id = ++seq;
        const method = (config.method || "get").toUpperCase();
        const url = config.url || "";
        const started = Date.now();
        safeAppendJson({
          ts: nowIso(),
          source: "js_interceptor",
          event: "http_request",
          request_id,
          method,
          url,
          transport: "axios",
          headers: normalizeHeaders(config.headers),
          body: toBodyLog(config.data),
        });
        try {
          const res = await originalRequest(config);
          safeAppendJson({
            ts: nowIso(),
            source: "js_interceptor",
            event: "http_response",
            request_id,
            transport: "axios",
            status: res.status,
            status_text: res.statusText || "",
            headers: normalizeHeaders(res.headers),
            body: toBodyLog(res.data),
            elapsed_ms: Date.now() - started,
          });
          return res;
        } catch (err) {
          safeAppendJson({
            ts: nowIso(),
            source: "js_interceptor",
            event: "http_error",
            request_id,
            transport: "axios",
            elapsed_ms: Date.now() - started,
            error: safeToString(err),
          });
          throw err;
        }
      };
    }

    wrapAxiosInstance(axiosMod);
    if (typeof axiosMod.create === "function") {
      const originalCreate = axiosMod.create.bind(axiosMod);
      axiosMod.create = function(...args) {
        const instance = originalCreate(...args);
        wrapAxiosInstance(instance);
        return instance;
      };
    }
  }

  function installRequestHook(mod, modName) {
    if (!mod || mod.__jsInterceptorWrapped) return mod;

    function wrap(fn) {
      if (typeof fn !== "function" || fn.__jsInterceptorWrapped) return fn;
      const wrapped = function (...args) {
        const request_id = ++seq;
        const started = Date.now();
        let uri = args[0];
        let options = args[1];
        let params = {};

        if (typeof uri === "string") params.url = uri;
        else if (uri && typeof uri === "object") params = uri;
        if (options && typeof options === "object") Object.assign(params, options);

        safeAppendJson({
          ts: nowIso(),
          source: "js_interceptor",
          event: "http_request",
          request_id,
          method: (params.method || (params.url ? "GET" : "??")).toUpperCase(),
          url: params.url || params.uri || "",
          transport: modName,
          headers: normalizeHeaders(params.headers),
          body: toBodyLog(params.body || params.json || null),
        });

        let cbIdx = -1;
        for (let i = args.length - 1; i >= 0; i--) {
          if (typeof args[i] === "function") {
            cbIdx = i;
            break;
          }
        }

        if (cbIdx !== -1) {
          const originalCb = args[cbIdx];
          args[cbIdx] = function (err, res, body) {
            if (res) {
              safeAppendJson({
                ts: nowIso(),
                source: "js_interceptor",
                event: "http_response",
                request_id,
                transport: modName,
                status: res.statusCode,
                status_text: res.statusMessage || "",
                headers: normalizeHeaders(res.headers),
                body: toBodyLog(body),
                elapsed_ms: Date.now() - started,
              });
            }
            return originalCb.apply(this, arguments);
          };
        }
        return fn.apply(this, args);
      };
      wrapped.__jsInterceptorWrapped = true;
      Object.assign(wrapped, fn);
      return wrapped;
    }

    const finalMod = wrap(mod);
    ["get", "post", "put", "delete", "patch", "head"].forEach((m) => {
      if (typeof finalMod[m] === "function") finalMod[m] = wrap(finalMod[m]);
    });
    finalMod.__jsInterceptorWrapped = true;
    return finalMod;
  }

  function installSocketHook(socket) {
    if (!socket || socket.__jsInterceptorWrapped) return;
    socket.__jsInterceptorWrapped = true;

    if (typeof socket.emit === "function") {
      const originalEmit = socket.emit.bind(socket);
      socket.emit = function(eventName, ...args) {
        safeAppendJson({
          ts: nowIso(),
          source: "js_interceptor",
          event: "socket_emit",
          socket_event: safeToString(eventName),
          args: toBodyLog(args),
        });
        return originalEmit(eventName, ...args);
      };
    }

    if (typeof socket.on === "function") {
      const originalOn = socket.on.bind(socket);
      socket.on = function(eventName, handler) {
        if (typeof handler !== "function") return originalOn(eventName, handler);
        const wrapped = function(...cbArgs) {
          safeAppendJson({
            ts: nowIso(),
            source: "js_interceptor",
            event: "socket_on_event",
            socket_event: safeToString(eventName),
            args: toBodyLog(cbArgs),
          });
          return handler.apply(this, cbArgs);
        };
        return originalOn(eventName, wrapped);
      };
    }
  }

  function installSocketIoClientHook(ioModule) {
    if (!ioModule) return;
    const ioFn =
      (typeof ioModule === "function" && ioModule) ||
      (ioModule.default && typeof ioModule.default === "function" && ioModule.default) ||
      (ioModule.io && typeof ioModule.io === "function" && ioModule.io) ||
      null;

    if (!ioFn || ioFn.__jsInterceptorWrapped) return;
    const wrappedIo = function(...args) {
      const socket = ioFn(...args);
      installSocketHook(socket);
      return socket;
    };
    wrappedIo.__jsInterceptorWrapped = true;

    if (ioModule.io === ioFn) ioModule.io = wrappedIo;
    if (ioModule.default === ioFn) ioModule.default = wrappedIo;
    if (typeof ioModule === "function") {
      // Can't rebind module value by reference; callers that hold original symbol
      // will still work and can be wrapped by module loader hook below.
    }
  }

  function installDnsHook(dnsMod) {
    if (!dnsMod || dnsMod.__jsInterceptorWrapped) return;
    dnsMod.__jsInterceptorWrapped = true;

    ["lookup", "resolve", "resolve4", "resolve6"].forEach((fnName) => {
      if (typeof dnsMod[fnName] !== "function" || dnsMod[fnName].__jsInterceptorWrapped) return;
      const original = dnsMod[fnName].bind(dnsMod);
      dnsMod[fnName] = function(...args) {
        const request_id = ++seq;
        const started = Date.now();
        const host = args.length ? safeToString(args[0]) : "";

        safeAppendJson({
          ts: nowIso(),
          source: "js_interceptor",
          event: "dns_query",
          request_id,
          query_type: fnName,
          host,
        });

        if (args.length && typeof args[args.length - 1] === "function") {
          const cb = args[args.length - 1];
          args[args.length - 1] = function(err, ...rest) {
            if (err) {
              safeAppendJson({
                ts: nowIso(),
                source: "js_interceptor",
                event: "dns_error",
                request_id,
                query_type: fnName,
                host,
                elapsed_ms: Date.now() - started,
                error: safeToString(err),
              });
            } else {
              safeAppendJson({
                ts: nowIso(),
                source: "js_interceptor",
                event: "dns_result",
                request_id,
                query_type: fnName,
                host,
                elapsed_ms: Date.now() - started,
                result: toBodyLog(rest),
              });
            }
            return cb.apply(this, [err, ...rest]);
          };
          return original(...args);
        }

        const ret = original(...args);
        if (ret && typeof ret.then === "function") {
          return ret.then((value) => {
            safeAppendJson({
              ts: nowIso(),
              source: "js_interceptor",
              event: "dns_result",
              request_id,
              query_type: fnName,
              host,
              elapsed_ms: Date.now() - started,
              result: toBodyLog(value),
            });
            return value;
          }).catch((err) => {
            safeAppendJson({
              ts: nowIso(),
              source: "js_interceptor",
              event: "dns_error",
              request_id,
              query_type: fnName,
              host,
              elapsed_ms: Date.now() - started,
              error: safeToString(err),
            });
            throw err;
          });
        }
        return ret;
      };
      dnsMod[fnName].__jsInterceptorWrapped = true;
    });
  }

  function endpointFromArgs(args, defaultProto) {
    let host = "";
    let port = "";
    let proto = defaultProto || "tcp";
    try {
      if (args.length && typeof args[0] === "object" && args[0] !== null) {
        const o = args[0];
        host = o.host || o.hostname || "";
        port = o.port || "";
        if (o.protocol) proto = safeToString(o.protocol).replace(":", "");
      } else {
        if (typeof args[0] === "number" || typeof args[0] === "string") port = args[0];
        if (typeof args[1] === "string") host = args[1];
      }
    } catch (_) {}
    return { host: safeToString(host), port: safeToString(port), proto };
  }

  function installSocketTrafficHook(socket, transport) {
    if (!socket || socket.__jsInterceptorTrafficWrapped) return;
    socket.__jsInterceptorTrafficWrapped = true;

    // Raw TCP payloads are binary and can be large; stream them to per-direction working files and
    // log a reference (stream id + offset + length) instead of the byte-by-byte integer array.
    // finish() hashes each completed file and uploads it as a dropped file named by its sha256.
    const streamId = ++bufferSeq;
    const pid = safeCall(() => (typeof process !== "undefined" ? process.pid : 0), 0);
    const sendName = `sock_${pid}_${bufferRunTag}_${streamId}_send`;
    const recvName = `sock_${pid}_${bufferRunTag}_${streamId}_recv`;

    // conn_id ties every send/receive/error back to this socket so the host can separate concurrent
    // connections and rebuild each conversation; it doubles as the stream id already in the file names.
    const originalWrite = typeof socket.write === "function" ? socket.write.bind(socket) : null;
    if (originalWrite) {
      socket.write = function(chunk, ...rest) {
        safeAppendJson({
          ts: nowIso(),
          source: "js_interceptor",
          event: "tcp_send",
          transport,
          conn_id: streamId,
          body: tcpBody(sendName, chunk),
        });
        return originalWrite(chunk, ...rest);
      };
    }

    socket.on("data", (chunk) => {
      safeAppendJson({
        ts: nowIso(),
        source: "js_interceptor",
        event: "tcp_receive",
        transport,
        conn_id: streamId,
        body: tcpBody(recvName, chunk),
      });
    });
    socket.on("error", (err) => {
      safeAppendJson({
        ts: nowIso(),
        source: "js_interceptor",
        event: "tcp_error",
        transport,
        conn_id: streamId,
        error: safeToString(err),
      });
    });
    return streamId;
  }

  function installNetLikeHook(mod, modName) {
    if (!mod || mod.__jsInterceptorNetWrapped) return;
    mod.__jsInterceptorNetWrapped = true;

    ["connect", "createConnection"].forEach((fnName) => {
      if (typeof mod[fnName] !== "function" || mod[fnName].__jsInterceptorWrapped) return;
      const original = mod[fnName].bind(mod);
      mod[fnName] = function(...args) {
        const ep = endpointFromArgs(args, modName);
        const socket = original(...args);
        // Install the traffic hook first so conn_id is known before tcp_connect is logged.
        const connId = installSocketTrafficHook(socket, modName);
        safeAppendJson({
          ts: nowIso(),
          source: "js_interceptor",
          event: "tcp_connect",
          transport: modName,
          conn_id: connId,
          host: ep.host,
          port: ep.port,
          protocol: ep.proto,
        });
        // The real local/remote addresses are only known once connected; log them as the src/dst
        // the host uses for the conversation.
        if (typeof socket.on === "function") {
          socket.on("connect", () => {
            safeAppendJson({
              ts: nowIso(),
              source: "js_interceptor",
              event: "tcp_endpoints",
              transport: modName,
              conn_id: connId,
              local_address: safeCall(() => socket.localAddress, ""),
              local_port: safeCall(() => socket.localPort, ""),
              remote_address: safeCall(() => socket.remoteAddress, ""),
              remote_port: safeCall(() => socket.remotePort, ""),
            });
          });
        }
        return socket;
      };
      mod[fnName].__jsInterceptorWrapped = true;
    });
  }

  function installModuleLoadHook() {
    if (typeof require !== "function") return;
    const Module = safeCall(() => require("module"), null);
    if (!Module || typeof Module._load !== "function" || Module._load.__jsInterceptorWrapped) return;

    const originalLoad = Module._load;
    Module._load = function(requestName, parent, isMain) {
      // Intercept 'punycode' module requests and provide the userland alternative
      if (requestName === "punycode" || requestName === "punycode/") {
        try {
          // Attempt to load the userland punycode module.
          // This assumes the 'punycode' npm package is installed and resolvable
          // through the standard Node.js module resolution for non-built-in modules.
          const userlandPunycode = originalLoad("punycode", parent, isMain);
          safeAppendJson({
            ts: nowIso(),
            source: "js_interceptor",
            event: "module_intercept",
            module_name: "punycode",
            status: "replaced_with_userland",
          });
          return userlandPunycode;
        } catch (e) {
          // If loading the userland module fails, log the error and fall back to original behavior
          safeAppendJson({
            ts: nowIso(),
            source: "js_interceptor",
            event: "module_intercept_error",
            module_name: "punycode",
            error: safeToString(e),
            message: "Failed to load userland punycode, falling back to original behavior.",
          });
          return originalLoad(requestName, parent, isMain);
        }
      }

      let loaded = originalLoad.apply(this, arguments);
      try {
        if (requestName === "http") installHttpLikeHook(loaded, "http");
        else if (requestName === "https") installHttpLikeHook(loaded, "https");
        else if (requestName === "axios") installAxiosHook(loaded);
        else if (requestName === "request" || requestName === "requests") loaded = installRequestHook(loaded, requestName);
        else if (requestName === "socket.io-client") installSocketIoClientHook(loaded);
        else if (requestName === "dns") installDnsHook(loaded);
        else if (requestName === "net") installNetLikeHook(loaded, "tcp");
        else if (requestName === "tls") installNetLikeHook(loaded, "tls");
      } catch (_) {}
      return loaded;
    };
    Module._load.__jsInterceptorWrapped = true;
  }

  function installOptionalKnownModules() {
    if (typeof require !== "function") return;
    const httpMod = safeCall(() => require("http"), null);
    const httpsMod = safeCall(() => require("https"), null);
    const dnsMod = safeCall(() => require("dns"), null);
    const netMod = safeCall(() => require("net"), null);
    const tlsMod = safeCall(() => require("tls"), null);
    const requestMod = safeCall(() => require("request"), null);
    const requestsMod = safeCall(() => require("requests"), null);
    installHttpLikeHook(httpMod, "http");
    installHttpLikeHook(httpsMod, "https");
    installDnsHook(dnsMod);
    installNetLikeHook(netMod, "tcp");
    installNetLikeHook(tlsMod, "tls");
    if (requestMod) installRequestHook(requestMod, "request");
    if (requestsMod) installRequestHook(requestsMod, "requests");
  }

  ["log", "info", "warn", "error", "debug"].forEach((level) => {
    const original = typeof console[level] === "function" ? console[level].bind(console) : null;
    console[level] = (...args) => {
      const message = args.map(safeToString).join(" ");

      // Filter out specific deprecation warnings coming from the target script
      if (message.includes("[DEP0040]") || message.includes("[DEP0190]")) return;

      safeAppendJson({
        ts: nowIso(),
        source: "js_interceptor",
        event: "console",
        level,
        message,
      });
      if (original) return original(...args);
    };
  });

  safeAppendJson({
    ts: nowIso(),
    source: "js_interceptor",
    event: "init",
    log_path: logPath,
    pid: safeCall(() => (typeof process !== "undefined" ? process.pid : null), null),
    ppid: safeCall(() => (typeof process !== "undefined" ? process.ppid : null), null),
    cwd: safeCall(() => (typeof process !== "undefined" ? process.cwd() : null), null),
    exec_path: safeCall(() => (typeof process !== "undefined" ? process.execPath : null), null),
    argv: safeCall(() => (typeof process !== "undefined" && Array.isArray(process.argv) ? process.argv : null), null),
    bun_version: safeCall(() => (typeof Bun !== "undefined" ? Bun.version : null), null),
    has_fetch: typeof globalThis.fetch === "function",
    fetch_type: safeCall(() => typeof globalThis.fetch, null),
    // Whether setTimeout/setInterval were forced to 1ms in this process. Without it the
    // log gives no way to tell whether the timings in it are the sample's own.
    timers_accelerated: !isPackageManager,
  });

  installEvalHook();
  installModuleLoadHook();
  installOptionalKnownModules();

  if (typeof globalThis.fetch !== "function") {
    safeAppendJson({
      ts: nowIso(),
      source: "js_interceptor",
      event: "warning",
      message: "fetch not available on globalThis; fetch interceptor not installed",
    });
    return;
  }

  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (url, options = {}) => {
    const request_id = ++seq;
    const method = options.method || "GET";
    const requestUrl = normalizeUrl(url);
    const reqHeaders = normalizeHeaders(options.headers);

    let reqBody = null;
    if (options.body !== undefined && options.body !== null) {
      const b = truncate(options.body);
      reqBody = { text: b.text, truncated: b.truncated };
    }

    safeAppendJson({
      ts: nowIso(),
      source: "js_interceptor",
      event: "http_request",
      request_id,
      method,
      url: requestUrl,
      headers: reqHeaders,
      body: reqBody,
    });

    const started = Date.now();
    try {
      const response = await originalFetch(url, options);
      const cloned = response.clone();

      const resHeaders = normalizeHeaders(response.headers);
      let resBody = { text: null, truncated: false, unreadable: false };

      try {
        const text = await cloned.text();
        const t = truncate(text);
        resBody = { text: t.text, truncated: t.truncated, unreadable: false };
      } catch {
        resBody = { text: null, truncated: false, unreadable: true };
      }

      safeAppendJson({
        ts: nowIso(),
        source: "js_interceptor",
        event: "http_response",
        request_id,
        status: response.status,
        status_text: response.statusText,
        headers: resHeaders,
        body: resBody,
        elapsed_ms: Date.now() - started,
      });

      return response;
    } catch (err) {
      safeAppendJson({
        ts: nowIso(),
        source: "js_interceptor",
        event: "http_error",
        request_id,
        elapsed_ms: Date.now() - started,
        error: safeToString(err),
      });
      throw err;
    }
  };
})();
"""


class JsConsole(Auxiliary):
    start_priority = 10
    stop_priority = 10

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        super().__init__(options, config)

        self.file_name = self.options.get("js_console_file", "js_console.log")
        self.log_path = os.path.join(PATHS["logs"], self.file_name)
        self.interceptor_name = INTERCEPTOR_FILE_NAME
        self.interceptor_path = os.path.join(
            self._target_directory(), self.interceptor_name
        )
        # Any package can end up spawning node.exe - a .bat that shells out, an exe that
        # drops a script - and CreateProcessW inherits the environment block all the way
        # down the chain, so the interceptor is installed for the whole analysis rather
        # than for one package. The js_console key in analysis.conf is the on/off switch.
        self.enabled = True
        self.do_run = self.enabled

    def _target_directory(self):
        # Where move_curdir put the sample, which is the directory node runs from and the
        # only place nodejs.py looks for the interceptor. Deriving it from config.file_name
        # instead pointed at the submission directory: that value is a full path, and
        # os.path.join discards curdir when the second argument is absolute.
        curdir = self.options.get(OPT_CURDIR) or os.environ.get(
            "TEMP", r"C:\Windows\Temp"
        )
        return os.path.expandvars(curdir)

    def _persist_env(self, name, value):
        """Set an environment variable for this process and for later-launched ones.

        The in-process assignment reaches the Win32 environment block, and the analyzer
        launches the package with CreateProcessW(lpEnvironment=NULL), so every descendant
        inherits it - a .bat that shells out to node.exe included. setx additionally
        writes HKCU\\Environment and broadcasts WM_SETTINGCHANGE, which is the only thing
        that reaches a node.exe started through ShellExecute by an explorer.exe that was
        already running when the analysis began.
        """
        os.environ[name] = value
        commands = [["setx", name, value]]
        if SHELL32.IsUserAnAdmin():
            # Machine scope, so processes running as another user or as a service see it.
            commands.append(["setx", name, value, "/M"])

        for command in commands:
            scope = "machine" if "/M" in command else "user"
            try:
                result = subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    check=False,
                )
            except Exception as e:
                log.debug("js_console: failed to persist %s (%s): %s", name, scope, e)
                continue

            if result.returncode:
                # Previously discarded, so a failure to persist looked identical to
                # success while silently leaving later processes uninstrumented.
                log.warning(
                    "js_console: setx %s (%s) failed with %s: %s",
                    name,
                    scope,
                    result.returncode,
                    result.stderr.decode("utf-8", "replace").strip(),
                )
            else:
                log.info("js_console: set %s (%s) to %s", name, scope, value)

    def start(self):
        if not self.do_run:
            return
        try:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

            # Substitute log path in interceptor script dynamically
            templated_log_path = self.log_path.replace("\\", "\\\\")
            templated_script = INTERCEPTOR_TEMPLATE.replace( "@LOG_PATH@", templated_log_path )

            with open(self.interceptor_path, "w", encoding="utf-8") as f:
                f.write(templated_script)
            log.info(
                "js_console: wrote interceptor script to %s", self.interceptor_path
            )

            # Absolute: NODE_OPTIONS is read by every node.exe wherever it starts, and a
            # relative path would resolve against the child's working directory. Forward
            # slashes because node splits the value on whitespace honouring double quotes
            # and passes backslashes through literally.
            preload_path = os.path.abspath(self.interceptor_path).replace("\\", "/")
            self._persist_env("NODE_OPTIONS", f'--require "{preload_path}"')
            self._persist_env("BUN_OPTIONS", f'--preload "{preload_path}"')
        except Exception as e:
            log.warning("js_console: failed to prepare js artifacts: %s", e)

    def stop(self):
        self.do_run = False

    def finish(self):
        # stop() clears do_run, so the enabled flag is what distinguishes "ran and
        # produced nothing" from "never ran": without it every non-nodejs analysis logs
        # a missing-log warning.
        if not self.enabled:
            return

        if not os.path.exists(self.log_path):
            log.warning("js_console: log file %s not found", self.log_path)
            return

        # Hash each per-stream TCP buffer and record a stream->sha256 manifest so the processing
        # module can link tcp_send/tcp_receive events to the dropped file. The manifest is a SEPARATE
        # file (not appended to the log) so it can't be lost to the processing module's max_entries
        # cap on log events. The buffers themselves are uploaded as standard dropped files
        # (files/<sha256>) so they ride the existing dropped-file YARA/signature pipeline.
        buffers = []
        manifest = []
        buffers_dir = os.path.join(os.path.dirname(self.log_path), "js_buffers")
        if os.path.isdir(buffers_dir):
            for name in os.listdir(buffers_dir):
                fpath = os.path.join(buffers_dir, name)
                if not os.path.isfile(fpath):
                    continue
                try:
                    digest = hashlib.sha256()
                    with open(fpath, "rb") as fd:
                        for chunk in iter(lambda: fd.read(1024 * 1024), b""):
                            digest.update(chunk)
                    sha256 = digest.hexdigest()
                    size = os.path.getsize(fpath)
                except Exception as e:
                    log.warning("js_console: failed to hash buffer %s: %s", fpath, e)
                    continue

                buffers.append((fpath, sha256))
                manifest.append({"stream": name, "sha256": sha256, "bytes": size})

        if manifest:
            # aux/js_console is already whitelisted in resultserver.RESULT_UPLOADABLE, so no server
            # change is needed for the manifest file.
            manifest_path = os.path.join(os.path.dirname(self.log_path), "js_buffers.json")
            try:
                with open(manifest_path, "w", encoding="utf-8") as fd:
                    json.dump(manifest, fd)
                upload_to_host(manifest_path, os.path.join("aux", "js_console", "js_buffers.json"))
            except Exception as e:
                log.warning("js_console: failed to write/upload buffer manifest: %s", e)

        try:
            # Upload to aux directory for the processing module to pick up and parse into report.json
            upload_to_host(
                self.log_path, os.path.join("aux", "js_console", self.file_name)
            )
        except Exception as e:
            log.warning("js_console: upload failed for %s: %s", self.log_path, e)

        # Upload each buffer as a dropped file named by sha256. The result server dedups identical
        # content via open_exclusive (EEXIST -> skipped), matching CAPE's content-addressed store.
        for fpath, sha256 in buffers:
            try:
                upload_to_host(fpath, f"files/{sha256}", metadata="js_console tcp buffer", category="files")
            except Exception as e:
                log.warning("js_console: buffer upload failed for %s: %s", fpath, e)
