import { app } from "@azure/functions";
import crypto from "crypto";

/**
 * base64url → Buffer
 */
function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}

/**
 * SHA256 hex digest
 */
function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function joseToDer(signature) {
  const r = signature.slice(0, 32);
  const s = signature.slice(32);

  function trim(buf) {
    let i = 0;
    while (i < buf.length && buf[i] === 0) i++;
    buf = buf.slice(i);
    if (buf[0] & 0x80) {
      buf = Buffer.concat([Buffer.from([0]), buf]);
    }
    return buf;
  }

  const rTrim = trim(r);
  const sTrim = trim(s);

  const totalLength = 2 + rTrim.length + 2 + sTrim.length;

  return Buffer.concat([
    Buffer.from([0x30, totalLength]),
    Buffer.from([0x02, rTrim.length]),
    rTrim,
    Buffer.from([0x02, sTrim.length]),
    sTrim,
  ]);
}

app.http("verifyJWT", {
  methods: ["POST"],
  authLevel: "function",
  handler: async (request, context) => {
    try {
      const { jwt, publicKey, rawBody } = await request.json();

      if (!jwt || !publicKey || rawBody === undefined) {
        return {
          status: 400,
          jsonBody: {
            valid: false,
            reason: "Missing jwt, publicKey, or rawBody",
          },
        };
      }

      // 1. Split JWT
      const [headerB64, payloadB64, signatureB64] = jwt.split(".");
      if (!headerB64 || !payloadB64 || !signatureB64) {
        return {
          status: 400,
          jsonBody: { valid: false, reason: "Malformed JWT" },
        };
      }

      // 2. Decode header + payload
      const header = JSON.parse(base64UrlDecode(headerB64).toString());
      const payload = JSON.parse(base64UrlDecode(payloadB64).toString());

      if (header.alg !== "ES256") {
        return {
          status: 400,
          jsonBody: { valid: false, reason: "Unsupported JWT algorithm" },
        };
      }

      // 3. Verify signature (ES256)
      const signingInput = `${headerB64}.${payloadB64}`;
      const rawSignature = base64UrlDecode(signatureB64);
      const derSignature = joseToDer(rawSignature);

      const keyObject = crypto.createPublicKey({
        key: JSON.parse(Buffer.from(publicKey, "base64").toString("utf8")),
        format: "jwk",
      });

      const signatureValid = crypto.verify(
        "sha256",
        Buffer.from(signingInput),
        keyObject,
        derSignature
      );

      if (!signatureValid) {
        return {
          status: 401,
          jsonBody: { valid: false, reason: "Invalid JWT signature" },
        };
      }

      // 4. Verify body hash
      const expectedHash = payload.request_body_sha256;
      const actualHash = sha256Hex(rawBody);

      context.log("rawBody type:", typeof rawBody);
      context.log("rawBody length:", rawBody.length);
      context.log("rawBody (escaped):", JSON.stringify(rawBody));
      context.log("expectedHash (JWT):", expectedHash);
      context.log("actualHash (computed):", actualHash);
      const rawBodyBuffer = Buffer.from(rawBody, "utf8");
      context.log("rawBody bytes (hex):", rawBodyBuffer.toString("hex"));
      context.log("rawBody byte length:", rawBodyBuffer.length);

      if (expectedHash !== actualHash) {
        return {
          status: 401,
          jsonBody: { valid: false, reason: "Request body hash mismatch" },
        };
      }

      // ✅ All checks passed
      return {
        status: 200,
        jsonBody: {
          valid: true,
        },
      };
    } catch (err) {
      context.error(err);
      return {
        status: 500,
        jsonBody: {
          valid: false,
          error: "Verification failed",
        },
      };
    }
  },
});
