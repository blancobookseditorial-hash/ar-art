
import { createHmac, timingSafeEqual } from "node:crypto";

const SECRET = process.env.AR_REMEMBER_SECRET;
const TOKEN_DURATION = 365 * 24 * 60 * 60;

function respond(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

function sign(payload) {
  return createHmac("sha256", SECRET)
    .update(payload)
    .digest("base64url");
}

async function getRegistry() {
  const base = process.env.DEPLOY_URL || process.env.URL;
  if (!base) throw new Error("Site URL unavailable");

  const url = new URL("/verify/registry.json", base);
  const response = await fetch(url, { cache: "no-store" });

  if (!response.ok) {
    throw new Error("Certificate registry unavailable");
  }

  const data = await response.json();
  if (!Array.isArray(data.records)) {
    throw new Error("Invalid certificate registry");
  }

  return data.records;
}

function findCertificate(records, work, edition) {
  return records.find(record =>
    record.status === "registered" &&
    typeof record.work === "string" &&
    typeof record.edition === "string" &&
    record.work.trim().toLowerCase() ===
      work.trim().toLowerCase() &&
    record.edition.trim() === edition.trim()
  );
}

function verifyToken(token) {
  if (typeof token !== "string" || token.length > 2048) {
    return null;
  }

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [payload, signature] = parts;
  const expected = sign(payload);

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return null;
  }

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (
      typeof data.w !== "string" ||
      typeof data.e !== "string" ||
      !Number.isSafeInteger(data.exp) ||
      data.exp <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

export default async function handler(request) {
  if (request.method !== "POST") {
    return respond({ success: false }, 405);
  }

  if (!SECRET || SECRET.length < 32) {
    return respond({
      success: false,
      message: "Saved access is not configured"
    }, 503);
  }

  try {
    const body = await request.json();
    const action = body?.action;

    if (action !== "issue" && action !== "verify") {
      return respond({ success: false }, 400);
    }

    let work;
    let edition;

    if (action === "issue") {
      work = body.work;
      edition = body.edition;

      if (
        typeof work !== "string" ||
        typeof edition !== "string" ||
        !work.trim() ||
        !edition.trim() ||
        work.length > 200 ||
        edition.length > 200
      ) {
        return respond({ success: false }, 400);
      }
    } else {
      const saved = verifyToken(body.token);

      if (!saved) {
        return respond({
          success: false,
          message: "Saved access is invalid or expired"
        }, 401);
      }

      work = saved.w;
      edition = saved.e;
    }

    const records = await getRegistry();
    const record = findCertificate(records, work, edition);

    if (!record) {
      return respond({
        success: false,
        message: "Certificate not found or inactive"
      }, 401);
    }

    if (action === "verify") {
      return respond({
        success: true,
        work: record.work,
        allowedArtworks: [record.work]
      });
    }

    const payload = Buffer.from(JSON.stringify({
      w: record.work,
      e: record.edition,
      exp: Math.floor(Date.now() / 1000) + TOKEN_DURATION
    })).toString("base64url");

    return respond({
      success: true,
      work: record.work,
      token: payload + "." + sign(payload)
    });
  } catch (error) {
    console.error("Remember AR access:", error.message);

    return respond({
      success: false,
      message: "Unable to verify saved AR access"
    }, 503);
  }
}
