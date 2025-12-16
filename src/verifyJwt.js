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

app.http("verifyJWT", {
  methods: ["POST"],
  authLevel: "function",
  handler: async (request, context) => {
    try {
      const { jwt, publicKey, rawBody } = await request.json();

      if (!jwt || !publicKey || !rawBody) {
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

      // 3. Verify signature (ES256)
      const signingInput = `${headerB64}.${payloadB64}`;
      const signature = base64UrlDecode(signatureB64);

      const keyObject = crypto.createPublicKey({
        key: JSON.parse(Buffer.from(publicKey, "base64").toString("utf8")),
        format: "jwk",
      });

      const signatureValid = crypto.verify(
        "sha256",
        Buffer.from(signingInput),
        keyObject,
        signature
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
