import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-store", "Pragma": "no-cache" },
});

function adminClient() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
}

function randomOtp(): string {
  const bytes = new Uint32Array(1);
  crypto.getRandomValues(bytes);
  return String(100000 + (bytes[0] % 900000));
}

function randomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function clientIp(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "0.0.0.0";
}

function hmacWithPepper(value: string, context: string): Promise<string> {
  // Delegate to the database function via service-role RPC
  return adminClient().rpc("hmac_with_pepper", { p_input: value, p_context }).then(({ data, error }) => {
    if (error || !data) throw new Error("HMAC_FAILED");
    return data as string;
  });
}

async function hmacRecovery(value: string, context: string): Promise<string> {
  const { data, error } = await adminClient().rpc("hmac_with_pepper", { p_input: value, p_context: context });
  if (error || !data) throw new Error("HMAC_FAILED");
  return data as string;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function padTiming(minMs: number, maxMs: number): Promise<void> {
  const delay = minMs + Math.random() * (maxMs - minMs);
  await new Promise((r) => setTimeout(r, delay));
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);

  try {
    const body = await req.json() as {
      mode?: string;
      identifier_type?: string;
      identifier_value?: string;
      channel?: string;
      channel_value?: string;
      challenge_id?: string;
      code?: string;
      reset_token?: string;
      new_password?: string;
    };
    const mode = body.mode ?? "request";
    const admin = adminClient();
    const ip = clientIp(req);
    const ipHash = await hmacRecovery(ip, "recovery_ip");

    // ── MODE: request ──────────────────────────────────────────────────────
    if (mode === "request") {
      if (!body.identifier_type || !body.identifier_value) return json({ ok: false, error: "INVALID_PARAMS" }, 400);

      const { data: settings } = await admin.from("auth_security_settings").select("unified_recovery_enabled, recovery_otp_ttl_seconds, recovery_max_attempts").eq("id", 1).maybeSingle();
      if (!settings?.unified_recovery_enabled) return json({ ok: false, error: "RECOVERY_DISABLED" }, 409);

      const identifierHash = await hmacRecovery(body.identifier_value, "recovery_identifier");

      // Rate limit: 3 per identifier, 10 per IP, 900s window
      const { data: rl } = await admin.rpc("consume_unified_recovery_rate_limit", {
        p_purpose: "recovery_request", p_identifier_hash: identifierHash, p_ip_hash: ipHash,
        p_identifier_limit: 3, p_ip_limit: 10, p_window_seconds: 900,
      });
      if (!rl?.allowed) return json({ ok: false, error: "RATE_LIMITED", retry_after_seconds: rl?.retry_after_seconds ?? 900 }, 429);

      // Resolve target — anti-enumeration: always return ok
      const { data: target } = await admin.rpc("resolve_unified_recovery_target", {
        p_identifier_type: body.identifier_type, p_identifier_value: body.identifier_value,
      });

      if (!target?.ok) {
        // Not found — return fake challenge_id to prevent enumeration
        await padTiming(3000, 3200);
        return json({ ok: true, challenge_id: crypto.randomUUID() });
      }

      // For username flow: user must provide channel + channel_value
      let channelTargetHash: string | null = null;
      let channel: string = "phone";

      if (body.identifier_type === "username") {
        if (!body.channel || !body.channel_value) {
          // Anti-enumeration: do NOT return contact hints
          return json({ ok: true, challenge_id: crypto.randomUUID(), requires_channel: true });
        }
        channel = body.channel;
        const { data: ownership } = await admin.rpc("verify_recovery_channel_ownership", {
          p_user_id: target.user_id, p_channel: body.channel, p_channel_value: body.channel_value,
        });
        if (!ownership?.ok) {
          await padTiming(3000, 3200);
          return json({ ok: true, challenge_id: crypto.randomUUID() });
        }
        channelTargetHash = ownership.target_hash;
      } else if (body.identifier_type === "email") {
        channel = "email";
      } else if (body.identifier_type === "phone") {
        channel = "phone";
      }

      // Email transport not yet available
      if (channel === "email") return json({ ok: false, error: "EMAIL_TRANSPORT_UNAVAILABLE" }, 503);

      const otp = randomOtp();
      const otpHash = await hmacRecovery(`${target.user_id}:${otp}`, "recovery_otp");
      const challengeId = crypto.randomUUID();
      const ttl = settings.recovery_otp_ttl_seconds ?? 600;
      const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();

      const { data: challenge, error } = await admin.rpc("create_unified_recovery_challenge", {
        p_challenge_id: challengeId, p_user_id: target.user_id, p_identifier_hash: identifierHash,
        p_channel: channel, p_channel_target_hash: channelTargetHash, p_otp_hash: otpHash,
        p_expires_at: expiresAt, p_max_attempts: settings.recovery_max_attempts ?? 5,
      });
      if (error || !challenge?.ok) return json({ ok: false, error: "CHALLENGE_CREATE_FAILED" }, 503);

      // Send OTP via redacted auth path (no plaintext OTP in dispatch logs)
      const smsResponse = await fetch(`${Deno.env.get("SUPABASE_URL")!}/functions/v1/send-sms`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!}` },
        body: JSON.stringify({ mode: "auth_otp", mobiles: [target.phone || ""], message: `کد بازیابی رمز عبور شما: ${otp}` }),
      });
      if (!smsResponse.ok) {
        await admin.from("unified_recovery_challenges").update({ status: "DELIVERY_FAILED" }).eq("id", challengeId);
        return json({ ok: false, error: "TRANSPORT_UNAVAILABLE" }, 503);
      }

      await padTiming(3000, 3200);
      return json({ ok: true, challenge_id: challengeId });
    }

    // ── MODE: verify ────────────────────────────────────────────────────────
    if (mode === "verify") {
      if (!body.challenge_id || !body.code || !/^\d{6}$/.test(body.code)) return json({ ok: false, error: "INVALID_CODE" }, 400);

      const { data: rl } = await admin.rpc("consume_unified_recovery_rate_limit", {
        p_purpose: "recovery_verify", p_identifier_hash: null, p_ip_hash: ipHash,
        p_identifier_limit: 999, p_ip_limit: 10, p_window_seconds: 900,
      });
      if (!rl?.allowed) return json({ ok: false, error: "RATE_LIMITED", retry_after_seconds: rl?.retry_after_seconds ?? 900 }, 429);

      // Load challenge to get user_id for HMAC
      const { data: challengeRow } = await admin.from("unified_recovery_challenges").select("user_id, status").eq("id", body.challenge_id).maybeSingle();
      if (!challengeRow?.user_id) return json({ ok: false, error: "INVALID_OR_EXPIRED_CODE" }, 400);

      const otpHash = await hmacRecovery(`${challengeRow.user_id}:${body.code}`, "recovery_otp");
      const resetToken = randomToken();
      const resetTokenHash = await hmacRecovery(resetToken, "recovery_reset_token");
      const resetExpiresAt = new Date(Date.now() + 300 * 1000).toISOString();

      const { data, error } = await admin.rpc("verify_unified_recovery_challenge", {
        p_challenge_id: body.challenge_id, p_otp_hash: otpHash,
        p_reset_token_hash: resetTokenHash, p_reset_expires_at: resetExpiresAt,
      });
      if (error || !data?.ok) return json({ ok: false, error: "INVALID_OR_EXPIRED_CODE" }, 400);

      await padTiming(1500, 1700);
      return json({ ok: true, reset_token: resetToken });
    }

    // ── MODE: complete ──────────────────────────────────────────────────────
    if (mode === "complete") {
      if (!body.challenge_id || !body.reset_token || !body.new_password) return json({ ok: false, error: "INVALID_PARAMS" }, 400);
      if (body.new_password.length < 8 || body.new_password.length > 128) return json({ ok: false, error: "INVALID_PASSWORD" }, 400);
      if (!/[a-zA-Z]/.test(body.new_password) || !/\d/.test(body.new_password)) return json({ ok: false, error: "INVALID_PASSWORD" }, 400);

      const { data: rl } = await admin.rpc("consume_unified_recovery_rate_limit", {
        p_purpose: "recovery_complete", p_identifier_hash: null, p_ip_hash: ipHash,
        p_identifier_limit: 999, p_ip_limit: 10, p_window_seconds: 900,
      });
      if (!rl?.allowed) return json({ ok: false, error: "RATE_LIMITED", retry_after_seconds: rl?.retry_after_seconds ?? 900 }, 429);

      const resetTokenHash = await hmacRecovery(body.reset_token, "recovery_reset_token");
      const claimId = crypto.randomUUID();

      const { data: claim, error: claimError } = await admin.rpc("claim_unified_recovery_completion", {
        p_challenge_id: body.challenge_id, p_reset_token_hash: resetTokenHash, p_claim_id: claimId,
      });
      if (claimError || !claim?.ok) return json({ ok: false, error: "INVALID_OR_EXPIRED_CODE" }, 400);

      const targetUserId = claim.user_id;

      // Change password via Admin API
      const { error: pwError } = await admin.auth.admin.updateUserById(targetUserId, { password: body.new_password });
      if (pwError) {
        await admin.rpc("finalize_unified_recovery_completion", { p_challenge_id: body.challenge_id, p_claim_id: claimId, p_success: false });
        return json({ ok: false, error: "RESET_FAILED" }, 500);
      }

      // Finalize: increment epoch, revoke grants
      const { data: finalizeResult, error: finalizeError } = await admin.rpc("finalize_unified_recovery_completion", {
        p_challenge_id: body.challenge_id, p_claim_id: claimId, p_success: true,
      });
      if (finalizeError || !finalizeResult?.ok) {
        // Password was changed but finalization failed — log audit
        await admin.from("audit_log").insert({ user_id: targetUserId, action: "recovery_finalize_failed", severity: "error" });
      }

      await admin.from("audit_log").insert({ user_id: targetUserId, action: "unified_password_recovery", severity: "info" });

      await padTiming(1500, 1700);
      return json({ ok: true });
    }

    return json({ ok: false, error: "INVALID_MODE" }, 400);
  } catch (error) {
    return json({ ok: false, error: "RECOVERY_OPERATION_FAILED" }, 500);
  }
});
