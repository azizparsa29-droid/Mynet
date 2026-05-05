import { createServer } from "http";

const PSK = "mwhidparsa29";

const STRIP_HEADERS = new Set([
  "host", "connection", "content-length", "transfer-encoding",
  "proxy-connection", "proxy-authorization", "x-forwarded-for",
  "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port",
  "x-real-ip", "forwarded", "via"
]);

function decodeBase64ToBytes(input) {
  const bin = atob(input);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function encodeBytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function sanitizeHeaders(h) {
  const out = {};
  if (!h || typeof h !== "object") return out;
  for (const [k, v] of Object.entries(h)) {
    if (STRIP_HEADERS.has(k.toLowerCase())) continue;
    out[k] = String(v ?? "");
  }
  return out;
}

async function handler(req, res) {
  if (req.method !== "POST") {
    res.statusCode = 405;
    return res.end(JSON.stringify({ e: "method_not_allowed" }));
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.statusCode = 401;
    return res.end(JSON.stringify({ e: "unauthorized" }));
  }
  
  const token = authHeader.slice(7);
  if (token !== PSK) {
    res.statusCode = 401;
    return res.end(JSON.stringify({ e: "unauthorized" }));
  }

  let body = "";
  req.on("data", chunk => body += chunk);
  req.on("end", async () => {
    try {
      const { url, method, headers, body: reqBody, bodyBase64 } = JSON.parse(body);

      if (!url) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ e: "missing_url" }));
      }

      const fetchOptions = {
        method: method || "GET",
        headers: sanitizeHeaders(headers),
      };

      if (reqBody) {
        fetchOptions.body = reqBody;
      } else if (bodyBase64) {
        fetchOptions.body = decodeBase64ToBytes(bodyBase64);
      }

      const response = await fetch(url, fetchOptions);
      const responseBody = await response.arrayBuffer();
      const responseHeaders = {};
      response.headers.forEach((value, key) => {
        if (!STRIP_HEADERS.has(key.toLowerCase())) {
          responseHeaders[key] = value;
        }
      });

      res.statusCode = 200;
      res.end(JSON.stringify({
        status: response.status,
        headers: responseHeaders,
        bodyBase64: encodeBytesToBase64(new Uint8Array(responseBody))
      }));
      
    } catch (err) {
      console.error("Exit node error:", err);
      res.statusCode = 500;
      res.end(JSON.stringify({ e: "internal_error", msg: String(err) }));
    }
  });
}

const server = createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json");
  if (req.method === "POST") {
    await handler(req, res);
  } else {
    res.statusCode = 405;
    res.end(JSON.stringify({ e: "method_not_allowed" }));
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Exit node running on port ${PORT}`);
});
