
import { createHash, timingSafeEqual } from "node:crypto";

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });

function codesMatch(received, expected) {
  if (!expected || typeof received !== "string") return false;

  const hashA = createHash("sha256").update(received).digest();
  const hashB = createHash("sha256").update(expected).digest();

  return timingSafeEqual(hashA, hashB);
}

export default async function handler(request) {
  if (request.method !== "POST") {
    return json({ success: false, message: "Method not allowed" }, 405);
  }

  try {
    const body = await request.json();
    const type = body?.type;
    const code = body?.code;

    if (
      !["admin", "puzzles"].includes(type) ||
      typeof code !== "string" ||
      code.length === 0 ||
      code.length > 256
    ) {
      return json({ success: false, message: "Invalid request" }, 400);
    }

    const variable =
      type === "admin" ? "AR_ADMIN_CODE" : "AR_PUZZLES_CODE";

    const expectedCode = process.env[variable];

    if (!expectedCode) {
      console.error("Missing access configuration:", variable);
      return json({ success: false, message: "Access unavailable" }, 503);
    }

    if (!codesMatch(code, expectedCode)) {
      return json({ success: false, message: "Invalid access code" }, 401);
    }

    const allowedArtworks = type === "admin"
      ? [
          "Anatomia de una isla",
          "Seths Dreams",
          "El Lunatico",
          "Unfolding the Sky",
          "Birth of Being",
          "A Dream of Wings",
          "What Clouds Cannot Dim"
        ]
      : [
          "Seths Dreams",
          "Birth of Being",
          "El Lunatico"
        ];

    return json({
      success: true,
      accessType: type,
      allowedArtworks
    });

  } catch (error) {
    console.error("AR access validation failed:", error);
    return json({ success: false, message: "Invalid request" }, 400);
  }
}
