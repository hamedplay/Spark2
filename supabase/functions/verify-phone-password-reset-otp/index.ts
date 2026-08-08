import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

async function hmacHash(value: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join("");
}

function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function getClientIP(req: Request): string {
  const xff = req.headers.get("x-forwarded-for") || "";
  const first = xff.split(",")[0]?.trim();
  if (!first) return "unknown";
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(first)) return first;
  if (/^[0-9a-fA-F:]+$/.test(first) && first.includes(":")) return first;
  return "unknown";
}

function corsHeaders(allowedOrigin: string | null): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": allowedOrigin || "null",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}

const TARGET_MIN_MS = 1500;
const TARGET_MAX_MS = 1700;

const GENERIC_ERROR = JSON.stringify({ ok: false, error: "INVALID_OR_EXPIRED_CODE" });

async function finishResponse(
  startedAt: number,
  response: Response,
  cors: Record<string, string>,
): Promise<Response> {
  const elapsed = Date.now() - startedAt;
  const jitter = Math.floor(Math.random() * (TARGET_MAX_MS - TARGET_MIN_MS + 1));
  const target = TARGET_MIN_MS + jitter;
  if (elapsed < target) {
    await new Promise(resolve => setTimeout(resolve, target - elapsed));
  }
  return new Response(response.body, {
    status: response.status,
    headers: { ...response.headers, ...cors },
  });
}

function genericErrorResponse(cors: Record<string, string>): Response {
  return new Response(GENERIC_ERROR,
    { status: 400, headers: { "Content-Type": "application/json", ...cors } });
}

Deno.serve(async (req: Request) => {
  const startedAt = Date.now();

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { autoRefreshToken: false, persistSession: false } },
  );

  // ── Phase 7 Canonical Readiness: return 410 if unified recovery is enabled ──
  if (req.method === "POST" || req.method === "OPTIONS") {
    try {
      const { data: settings } = await supabase
        .from("auth_security_settings")
        .select("unified_recovery_enabled")
        .eq("id", 1)
        .maybeSingle();
      if (settings?.unified_recovery_enabled === true) {
        const cors = corsHeaders(req.headers.get("Origin") || null);
        return new Response(
          JSON.stringify({ ok: false, error: "ROUTE_REPLACED", replacement: "unified-recovery" }),
          { status: 410, headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" } },
        );
      }
    } catch { /* fail-open: allow legacy route if settings unreadable */ }
  }

  // ── Load allowed origins from system_config ─────────────────────────────────
  let allowedOrigins: string[] = [];
  try {
    const { data: originsRow } = await supabase
      .from("system_config").select("value")
      .eq("section", "security").eq("key", "phone_login_allowed_origins")
      .maybeSingle();
    if (originsRow?.value) {
      allowedOrigins = originsRow.value
        .split(",").map((s: string) => s.trim()).filter((s: string) => s.length > 0);
    }
  } catch { /* fail-closed */ }

  const origin = req.headers.get("Origin") || "";
  const allowedOrigin = allowedOrigins.includes(origin) ? origin : null;
  const cors = corsHeaders(allowedOrigin);

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: cors });
  }

  if (req.method !== "POST") {
    return await finishResponse(startedAt, genericErrorResponse(cors), cors);
  }

  // Reject disallowed origin before processing body
  if (!allowedOrigin) {
    return await finishResponse(startedAt, genericErrorResponse(cors), cors);
  }

  const contentType = req.headers.get("Content-Type") || "";
  if (!contentType.includes("application/json")) {
    return await finishResponse(startedAt, genericErrorResponse(cors), cors);
  }

  let bodyText: string;
  try {
    bodyText = await req.text();
  } catch {
    return await finishResponse(startedAt, genericErrorResponse(cors), cors);
  }
  if (bodyText.length > 4096) {
    return await finishResponse(startedAt, genericErrorResponse(cors), cors);
  }

  try {
    let body: { challenge_id?: string; otp?: string };
    try {
      body = JSON.parse(bodyText);
    } catch {
      return await finishResponse(startedAt, genericErrorResponse(cors), cors);
    }

    const challengeId: string | undefined = body.challenge_id;
    const otp: string | undefined = body.otp;

    // OTP must be exactly 6 digits
    if (!challengeId || !otp || !/^\d{6}$/.test(otp)) {
      return await finishResponse(startedAt, genericErrorResponse(cors), cors);
    }

    // Only PHONE_PASSWORD_RESET_SECRET — never read pepper from DB
    const secret = Deno.env.get("PHONE_PASSWORD_RESET_SECRET") || "";
    if (!secret || secret.length < 32) {
      return await finishResponse(startedAt, genericErrorResponse(cors), cors);
    }

    // Atomic IP rate limit
    const clientIP = getClientIP(req);
    const ipHash = await hmacHash(clientIP, secret);
    const { data: rlData, error: rlErr } = await supabase.rpc(
      "consume_phone_password_recovery_verify_limit",
      {
        p_ip_hash: ipHash,
        p_purpose: "phone_password_recovery_verify",
        p_ip_limit: 10,
        p_window_seconds: 900,
      },
    );
    if (rlErr || !rlData) {
      return await finishResponse(startedAt, genericErrorResponse(cors), cors);
    }
    const rlRow = Array.isArray(rlData) ? rlData[0] : rlData;
    if (!rlRow?.allowed) {
      return await finishResponse(startedAt, genericErrorResponse(cors), cors);
    }

    // Revalidate using RPC with challenge_id
    const { data: revData, error: revErr } = await supabase.rpc(
      "revalidate_phone_password_reset_target",
      { p_challenge_id: challengeId },
    );
    if (revErr || !revData) {
      return await finishResponse(startedAt, genericErrorResponse(cors), cors);
    }
    const revRow = Array.isArray(revData) ? revData[0] : revData;
    if (!revRow?.valid || !revRow?.normalized_phone || !revRow?.phone_hash) {
      return await finishResponse(startedAt, genericErrorResponse(cors), cors);
    }

    // Compute HMAC of normalized_phone and compare timing-safe with challenge phone_hash
    const computedPhoneHash = await hmacHash(revRow.normalized_phone, secret);
    if (!timingSafeCompare(computedPhoneHash, revRow.phone_hash)) {
      return await finishResponse(startedAt, genericErrorResponse(cors), cors);
    }

    // Compute provided OTP hash — uses the SAME challenge_id that was used at request time
    const providedOtpHash = await hmacHash(
      `${challengeId}:${revRow.user_id}:${revRow.normalized_phone}:${otp}`,
      secret,
    );

    // Generate reset token (32 bytes)
    const resetTokenBytes = new Uint8Array(32);
    crypto.getRandomValues(resetTokenBytes);
    const resetToken = Array.from(resetTokenBytes).map(b => b.toString(16).padStart(2, '0')).join("");
    const resetTokenHash = await hmacHash(resetToken, secret);
    const resetExpiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    // Atomic verify via RPC
    const { data: verifyData, error: verifyErr } = await supabase.rpc(
      "verify_phone_password_reset_challenge",
      {
        p_challenge_id: challengeId,
        p_provided_otp_hash: providedOtpHash,
        p_reset_token_hash: resetTokenHash,
        p_reset_expires_at: resetExpiresAt,
      },
    );
    if (verifyErr || !verifyData) {
      return await finishResponse(startedAt, genericErrorResponse(cors), cors);
    }
    const verifyRow = Array.isArray(verifyData) ? verifyData[0] : verifyData;
    if (!verifyRow?.success) {
      return await finishResponse(startedAt, genericErrorResponse(cors), cors);
    }

    // Success — return reset token to browser (only time it's ever sent)
    return await finishResponse(startedAt,
      new Response(JSON.stringify({ ok: true, reset_token: resetToken }),
        { status: 200, headers: { "Content-Type": "application/json", ...cors } }), cors);

  } catch {
    return await finishResponse(startedAt, genericErrorResponse(cors), cors);
  }
});
