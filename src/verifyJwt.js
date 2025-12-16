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
function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function joseToDer(signature) {
  const r = signature.slice(0, 32);
  const s = signature.slice(32);

  function trim(buf) {
    let i = 0;
    while (i < buf.length && buf[i] === 0) i++;
    buf = buf.slice(i);
    if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0]), buf]);
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

      // 3. Verify signature
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

      // 4. Decode rawBody from Base64
      const decodedRawBody = Buffer.from(rawBody, "base64").toString("utf8");

      // 5. Parse JSON and re-serialize with 2-space indentation
      const normalizedBody = JSON.stringify(
        JSON.parse(decodedRawBody),
        null,
        2
      );

      // 6. Hash and verify
      const expectedHash = payload.request_body_sha256;
      const actualHash = sha256Hex(Buffer.from(normalizedBody, "utf8"));

      context.log("Normalized body for hashing:\n", normalizedBody);
      context.log("Expected hash:", expectedHash);
      context.log("Actual hash:", actualHash);

      if (expectedHash !== actualHash) {
        return {
          status: 401,
          jsonBody: { valid: false, reason: "Request body hash mismatch" },
        };
      }

      return {
        status: 200,
        jsonBody: { valid: true },
      };
    } catch (err) {
      context.error(err);
      return {
        status: 500,
        jsonBody: { valid: false, error: "Verification failed" },
      };
    }
  },
});
