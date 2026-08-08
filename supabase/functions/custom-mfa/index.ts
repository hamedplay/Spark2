import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-store", "Pragma": "no-cache" },
});

interface JwtPayload { sub?: string; session_id?: string; amr?: Array<{ method?: string }>; }
interface AuthUser { id: string; email?: string | null; email_confirmed_at?: string | null; phone?: string | null; phone_confirmed_at?: string | null; }

function adminClient() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
}

function jwtPayload(token: string): JwtPayload | null {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    return JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/"))) as JwtPayload;
  } catch { return null; }
}

function randomOtp(): string {
  const bytes = new Uint32Array(1);
  crypto.getRandomValues(bytes);
  return String(100000 + (bytes[0] % 900000));
}

function randomBytes(n: number): string {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmac(value: string, context: string): Promise<string> {
  const pepper = Deno.env.get("MFA_PEPPER");
  if (!pepper) throw new Error("MFA_NOT_READY");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(`${context}:${pepper}`), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return Array.from(new Uint8Array(signature)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function sessionIdFrom(token: string): string | null {
  return jwtPayload(token)?.session_id ?? null;
}

function isPhoneOtpPrimary(token: string): boolean {
  return (jwtPayload(token)?.amr ?? []).some((entry) => entry.method === "phone_otp");
}

function clientIp(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "0.0.0.0";
}

async function authenticate(req: Request): Promise<{ token: string; user: AuthUser; sessionId: string } | null> {
  const header = req.headers.get("Authorization") ?? "";
  if (!header.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  const sessionId = sessionIdFrom(token);
  if (!sessionId) return null;
  const { data, error } = await adminClient().auth.getUser(token);
  if (error || !data.user) return null;
  return { token, user: data.user as AuthUser, sessionId };
}

// ── SMS via auth_otp (redacted, no plaintext OTP in DB logs) ─────────────────
async function sendSmsOtp(userId: string, phone: string, otp: string): Promise<boolean> {
  const response = await fetch(`${Deno.env.get("SUPABASE_URL")!}/functions/v1/send-sms`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!}` },
    body: JSON.stringify({
      mode: "auth_otp",
      mobiles: [phone],
      message: `کد احراز هویت شما: ${otp}`,
    }),
  });
  if (!response.ok) return false;
  const result = await response.json() as { ok?: boolean };
  return result.ok === true;
}

// ── Bale via edge secret bot token (never reads DB config) ──
async function sendBaleOtp(userId: string, otp: string): Promise<boolean> {
  const botToken = Deno.env.get("BALE_BOT_TOKEN");
  if (!botToken) return false;

  const admin = adminClient();
  const { data: mapping } = await admin.from("user_bale_mapping")
    .select("bale_chat_id_enc, bale_mfa_codes_enabled")
    .eq("user_id", userId).maybeSingle();

  if (!mapping?.bale_mfa_codes_enabled || !mapping.bale_chat_id_enc) return false;

  const { data: chatId, error } = await admin.rpc("mfa_decrypt", { p_ciphertext: mapping.bale_chat_id_enc });
  if (error || typeof chatId !== "string" || !chatId) return false;

  const response = await fetch(`https://tapi.bale.ai/bot${botToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text: `کد احراز هویت شما: ${otp}` }),
  });
  return response.ok;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);

  const caller = await authenticate(req);
  if (!caller) return json({ ok: false, error: "UNAUTHORIZED" }, 401);

  try {
    const body = await req.json() as {
      mode?: string;
      factor_type?: string;
      challenge_id?: string;
      code?: string;
      // enrollment
      phone?: string;
      email?: string;
      bale_nonce?: string;
      bale_chat_id?: string;
      // recovery regenerate
      recovery_codes?: string[];
    };
    const mode = body.mode ?? "create";
    const admin = adminClient();

    // ── Readiness gate: check secret + settings before any operation ──────────
    const { data: readiness } = await admin.rpc("get_custom_mfa_readiness");
    if (!readiness?.mfa_enabled) return json({ ok: false, error: "MFA_DISABLED" }, 409);
    if (readiness.readiness === "not_ready") return json({ ok: false, error: "MFA_NOT_READY" }, 503);

    // ══════════════════════════════════════════════════════════════════════════
    // MODE: enroll — activate SMS/Bale/Recovery factors
    // ══════════════════════════════════════════════════════════════════════════
    if (mode === "enroll") {
      const factorType = body.factor_type;
      if (factorType !== "sms" && factorType !== "bale" && factorType !== "email") {
        return json({ ok: false, error: "FACTOR_UNAVAILABLE" }, 409);
      }
      if (!Array.isArray(readiness.allowed_factors) || !readiness.allowed_factors.includes(factorType)) {
        return json({ ok: false, error: "FACTOR_NOT_ALLOWED" }, 403);
      }
      if (factorType === "sms" && isPhoneOtpPrimary(caller.token)) {
        return json({ ok: false, error: "FACTOR_INDEPENDENCE_REQUIRED" }, 409);
      }
      if (factorType === "email") return json({ ok: false, error: "EMAIL_TRANSPORT_UNAVAILABLE" }, 503);

      let phoneHash: string | null = null;
      let baleChatIdEnc: Uint8Array | null = null;
      let baleChatIdHmac: string | null = null;

      if (factorType === "sms") {
        const phone = body.phone ?? caller.user.phone ?? "";
        if (!phone || phone.length < 10) return json({ ok: false, error: "PHONE_REQUIRED" }, 400);
        phoneHash = await hmac(phone, "mfa_factor_phone");
      } else if (factorType === "bale") {
        // Bale linking: consume nonce, store encrypted chat_id
        if (!body.bale_nonce || !body.bale_chat_id) return json({ ok: false, error: "BALE_LINK_REQUIRED" }, 400);
        if (body.bale_nonce.length < 64) return json({ ok: false, error: "BALE_NONCE_TOO_SHORT" }, 400);

        const nonceHash = await hmac(body.bale_nonce, "bale_nonce");
        baleChatIdHmac = await hmac(body.bale_chat_id, "bale_chat_id");

        // Encrypt chat_id via mfa_encrypt RPC
        const { data: encResult, error: encError } = await admin.rpc("mfa_encrypt", { p_plaintext: body.bale_chat_id });
        if (encError || !encResult) return json({ ok: false, error: "ENCRYPTION_FAILED" }, 500);
        // encResult is bytea — convert to Uint8Array for RPC
        const encHex = encResult as string;
        baleChatIdEnc = new Uint8Array(encHex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));

        const { data: consumeResult, error: consumeError } = await admin.rpc("consume_bale_link_nonce", {
          p_nonce_hash: nonceHash,
          p_user_id: caller.user.id,
          p_bale_chat_id_enc: Array.from(baleChatIdEnc),
          p_bale_chat_id_hmac: baleChatIdHmac,
        });
        if (consumeError || !consumeResult?.ok) {
          return json({ ok: false, error: consumeResult?.error ?? "BALE_LINK_FAILED" }, 400);
        }
      }

      const { data: enrollResult, error: enrollError } = await admin.rpc("enroll_custom_mfa_factor", {
        p_user_id: caller.user.id,
        p_factor_type: factorType,
        p_phone_hash: phoneHash,
        p_bale_chat_id_enc: baleChatIdEnc ? Array.from(baleChatIdEnc) : null,
        p_bale_chat_id_hmac: baleChatIdHmac,
      });
      if (enrollError || !enrollResult?.ok) {
        return json({ ok: false, error: "ENROLLMENT_FAILED" }, 500);
      }
      return json({ ok: true, factor_id: enrollResult.factor_id });
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MODE: disable — deactivate a factor
    // ══════════════════════════════════════════════════════════════════════════
    if (mode === "disable") {
      if (!body.factor_type) return json({ ok: false, error: "FACTOR_TYPE_REQUIRED" }, 400);
      const { data, error } = await admin.rpc("disable_custom_mfa_factor", {
        p_user_id: caller.user.id,
        p_factor_type: body.factor_type,
      });
      if (error || !data?.ok) return json({ ok: false, error: data?.error ?? "DISABLE_FAILED" }, 400);
      return json({ ok: true });
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MODE: regenerate_recovery — revoke old codes, issue new (requires FULL + step-up)
    // ══════════════════════════════════════════════════════════════════════════
    if (mode === "regenerate_recovery") {
      // Verify step-up grant
      const { data: grantCheck } = await admin.rpc("has_active_custom_mfa_grant", {
        p_user_id: caller.user.id,
        p_session_id: caller.sessionId,
      });
      if (!grantCheck) return json({ ok: false, error: "STEP_UP_REQUIRED" }, 403);

      if (!body.recovery_codes || !Array.isArray(body.recovery_codes) || body.recovery_codes.length === 0) {
        return json({ ok: false, error: "RECOVERY_CODES_REQUIRED" }, 400);
      }

      const codeHashes: string[] = [];
      for (const code of body.recovery_codes) {
        if (code.length < 16 || code.length > 64) return json({ ok: false, error: "INVALID_RECOVERY_CODE" }, 400);
        codeHashes.push(await hmac(code, "mfa_recovery"));
      }

      const { data, error } = await admin.rpc("regenerate_custom_mfa_recovery_codes_v2", {
        p_user_id: caller.user.id,
        p_code_hashes: codeHashes,
      });
      if (error || !data?.ok) return json({ ok: false, error: "REGENERATE_FAILED" }, 500);
      return json({ ok: true, code_count: data.code_count });
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MODE: create — issue MFA challenge (with rate-limit + resend)
    // ══════════════════════════════════════════════════════════════════════════
    if (mode === "create") {
      const factorType = body.factor_type;
      if (factorType !== "sms" && factorType !== "bale" && factorType !== "email") return json({ ok: false, error: "FACTOR_UNAVAILABLE" }, 409);
      if (!Array.isArray(readiness.allowed_factors) || !readiness.allowed_factors.includes(factorType)) return json({ ok: false, error: "FACTOR_NOT_ALLOWED" }, 403);
      if (factorType === "sms" && isPhoneOtpPrimary(caller.token)) return json({ ok: false, error: "FACTOR_INDEPENDENCE_REQUIRED" }, 409);
      if (factorType === "email" && !caller.user.email_confirmed_at) return json({ ok: false, error: "EMAIL_NOT_VERIFIED" }, 409);
      if (factorType === "email") return json({ ok: false, error: "EMAIL_TRANSPORT_UNAVAILABLE" }, 503);

      // Rate-limit: per user/session/IP
      const ipHash = await hmac(clientIp(req), "mfa_ip");
      const { data: rlResult } = await admin.rpc("consume_mfa_challenge_rate_limit", {
        p_user_id: caller.user.id,
        p_session_id: caller.sessionId,
        p_ip_hash: ipHash,
      });
      if (!rlResult?.allowed) {
        return json({ ok: false, error: "RATE_LIMITED", retry_after_seconds: rlResult?.retry_after_seconds ?? 900 }, 429);
      }

      const otp = randomOtp();
      const otpHash = await hmac(otp, "mfa_otp");
      const { data: challenge, error } = await admin.rpc("create_custom_mfa_challenge_service", {
        p_user_id: caller.user.id, p_factor_type: factorType, p_session_id: caller.sessionId, p_otp_hash: otpHash,
      });
      if (error || !challenge?.ok) return json({ ok: false, error: "CHALLENGE_CREATE_FAILED" }, 503);

      // Update challenge with IP hash
      await admin.from("custom_mfa_challenges").update({ ip_hash: ipHash }).eq("id", challenge.challenge_id);

      // Send OTP via safe path (auth_otp for SMS, edge secret for Bale)
      let delivered: boolean;
      if (factorType === "sms") {
        const phone = caller.user.phone ?? "";
        if (!phone) return json({ ok: false, error: "PHONE_NOT_AVAILABLE" }, 400);
        delivered = await sendSmsOtp(caller.user.id, phone, otp);
      } else {
        delivered = await sendBaleOtp(caller.user.id, otp);
      }
      if (!delivered) return json({ ok: false, error: "TRANSPORT_UNAVAILABLE" }, 503);
      return json({ ok: true, challenge_id: challenge.challenge_id, expires_at: challenge.expires_at, factor_type: factorType });
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MODE: resend — resend OTP for existing challenge
    // ══════════════════════════════════════════════════════════════════════════
    if (mode === "resend") {
      if (!body.challenge_id) return json({ ok: false, error: "CHALLENGE_ID_REQUIRED" }, 400);
      const ipHash = await hmac(clientIp(req), "mfa_ip");

      // Rate-limit resend
      const { data: rlResult } = await admin.rpc("consume_mfa_challenge_rate_limit", {
        p_user_id: caller.user.id,
        p_session_id: caller.sessionId,
        p_ip_hash: ipHash,
      });
      if (!rlResult?.allowed) {
        return json({ ok: false, error: "RATE_LIMITED", retry_after_seconds: rlResult?.retry_after_seconds ?? 900 }, 429);
      }

      const otp = randomOtp();
      const otpHash = await hmac(otp, "mfa_otp");
      const resendAvailableAt = new Date(Date.now() + 60 * 1000).toISOString();
      const { data: resendResult, error: resendError } = await admin.rpc("update_mfa_challenge_resend", {
        p_challenge_id: body.challenge_id,
        p_otp_hash: otpHash,
        p_resend_available_at: resendAvailableAt,
      });
      if (resendError || !resendResult?.ok) return json({ ok: false, error: resendResult?.error ?? "RESEND_FAILED" }, 400);

      // Load challenge to get factor type
      const { data: challengeRow } = await admin.from("custom_mfa_challenges")
        .select("factor_type").eq("id", body.challenge_id).maybeSingle();
      if (!challengeRow) return json({ ok: false, error: "CHALLENGE_NOT_FOUND" }, 404);

      let delivered: boolean;
      if (challengeRow.factor_type === "sms") {
        const phone = caller.user.phone ?? "";
        if (!phone) return json({ ok: false, error: "PHONE_NOT_AVAILABLE" }, 400);
        delivered = await sendSmsOtp(caller.user.id, phone, otp);
      } else {
        delivered = await sendBaleOtp(caller.user.id, otp);
      }
      if (!delivered) return json({ ok: false, error: "TRANSPORT_UNAVAILABLE" }, 503);
      return json({ ok: true });
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MODE: verify — consume challenge
    // ══════════════════════════════════════════════════════════════════════════
    if (mode === "verify") {
      if (!body.challenge_id || !body.code || !/^\d{6}$/.test(body.code)) return json({ ok: false, error: "INVALID_CODE" }, 400);
      const codeHash = await hmac(body.code, "mfa_otp");
      const { data, error } = await admin.rpc("consume_custom_mfa_challenge_service", {
        p_user_id: caller.user.id, p_challenge_id: body.challenge_id, p_otp_hash: codeHash, p_session_id: caller.sessionId,
      });
      if (error || !data?.ok) return json({ ok: false, error: data?.error ?? "MFA_VERIFY_FAILED" }, 400);
      return json({ ok: true, grant_expires_at: data.expires_at });
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MODE: recovery — consume recovery code
    // ══════════════════════════════════════════════════════════════════════════
    if (mode === "recovery") {
      if (!body.code || body.code.length < 16 || body.code.length > 64) return json({ ok: false, error: "INVALID_RECOVERY_CODE" }, 400);
      const codeHash = await hmac(body.code, "mfa_recovery");
      const { data, error } = await admin.rpc("consume_custom_mfa_recovery_service", {
        p_user_id: caller.user.id, p_code_hash: codeHash, p_session_id: caller.sessionId,
      });
      if (error || !data?.ok) return json({ ok: false, error: data?.error ?? "RECOVERY_CODE_INVALID" }, 400);
      return json({ ok: true, grant_expires_at: data.expires_at });
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MODE: readiness — return MFA readiness state
    // ══════════════════════════════════════════════════════════════════════════
    if (mode === "readiness") {
      return json(readiness);
    }

    return json({ ok: false, error: "INVALID_MODE" }, 400);
  } catch (error) {
    const code = error instanceof Error && error.message === "MFA_NOT_READY" ? "MFA_NOT_READY" : "MFA_OPERATION_FAILED";
    return json({ ok: false, error: code }, code === "MFA_NOT_READY" ? 503 : 500);
  }
});
