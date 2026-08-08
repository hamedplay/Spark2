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

function jwtPayload(token: string): { sub?: string; session_id?: string } | null {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    return JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/")));
  } catch { return null; }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);

  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return json({ ok: false, error: "UNAUTHORIZED" }, 401);
  const token = authHeader.slice(7);
  const payload = jwtPayload(token);
  if (!payload?.sub || !payload?.session_id) return json({ ok: false, error: "UNAUTHORIZED" }, 401);

  const admin = adminClient();
  const { data: { user }, error } = await admin.auth.getUser(token);
  if (error || !user) return json({ ok: false, error: "UNAUTHORIZED" }, 401);

  const userId = user.id;
  const sessionId = payload.session_id;

  try {
    const body = await req.json() as { mode?: string; session_id?: string; reason?: string };

    // ── MODE: list ──────────────────────────────────────────────────────────
    // Use get_user_session_security_state with explicit user binding (not auth.uid()-dependent)
    if (body.mode === "list") {
      const { data, error } = await admin.rpc("get_user_session_security_state", { p_user_id: userId });
      if (error || !data?.ok) return json({ ok: false, error: "SESSION_STATE_UNAVAILABLE" }, 500);
      return json(data);
    }

    // ── MODE: heartbeat ─────────────────────────────────────────────────────
    if (body.mode === "heartbeat") {
      const { data: profile } = await admin.from("profiles").select("auth_epoch").eq("user_id", userId).maybeSingle();
      const epoch = profile?.auth_epoch ?? 1;
      const { data: settings } = await admin.from("auth_security_settings").select("session_idle_timeout_minutes").eq("id", 1).maybeSingle();
      const idleMinutes = settings?.session_idle_timeout_minutes ?? 480;

      const { data, error } = await admin.rpc("touch_session_security_state", {
        p_session_id: sessionId, p_user_id: userId, p_auth_epoch: epoch, p_idle_timeout_minutes: idleMinutes,
      });
      if (error || !data?.ok) return json({ ok: false, error: data?.error ?? "HEARTBEAT_FAILED" }, 401);
      return json({ ok: true, idle_expiry_at: data.idle_expiry_at, absolute_expiry_at: data.absolute_expiry_at });
    }

    // ── MODE: revoke_one ────────────────────────────────────────────────────
    if (body.mode === "revoke_one") {
      if (!body.session_id) return json({ ok: false, error: "SESSION_ID_REQUIRED" }, 400);
      const { data, error } = await admin.rpc("revoke_session_security_state", {
        p_session_id: body.session_id, p_user_id: userId, p_reason: body.reason ?? "user_revoke",
      });
      if (error || !data?.ok) return json({ ok: false, error: data?.error ?? "REVOKE_FAILED" }, 400);
      return json({ ok: true });
    }

    // ── MODE: revoke_others ────────────────────────────────────────────────
    if (body.mode === "revoke_others") {
      const { data, error } = await admin.rpc("revoke_other_sessions", {
        p_user_id: userId, p_keep_session_id: sessionId,
      });
      if (error || !data?.ok) return json({ ok: false, error: "REVOKE_FAILED" }, 400);
      return json({ ok: true, revoked_count: data.revoked_count });
    }

    // ── MODE: revoke_all ────────────────────────────────────────────────────
    if (body.mode === "revoke_all") {
      const { data, error } = await admin.rpc("revoke_all_sessions", { p_user_id: userId });
      if (error || !data?.ok) return json({ ok: false, error: "REVOKE_FAILED" }, 400);
      return json({ ok: true, revoked_count: data.revoked_count });
    }

    // ── MODE: admin_revoke (requires FULL + step-up + audit) ────────────────
    if (body.mode === "admin_revoke") {
      if (!body.session_id) return json({ ok: false, error: "SESSION_ID_REQUIRED" }, 400);
      const body2 = body as { target_user_id?: string; reason?: string };
      if (!body2.target_user_id) return json({ ok: false, error: "TARGET_USER_ID_REQUIRED" }, 400);

      // Verify admin has FULL access + step-up grant
      const { data: accessState } = await admin.rpc("get_my_auth_access_state_v3");
      if (!accessState || accessState.access_level !== 'FULL') {
        return json({ ok: false, error: 'FULL_ACCESS_REQUIRED' }, 403);
      }
      const { data: totpGrant } = await admin.rpc("has_recent_totp_stepup_grant", {
        p_user_id: userId, p_session_id: sessionId,
      });
      if (!totpGrant) return json({ ok: false, error: 'STEP_UP_REQUIRED' }, 403);

      const { data, error } = await admin.rpc("admin_revoke_user_session", {
        p_admin_user_id: userId,
        p_target_user_id: body2.target_user_id,
        p_session_id: body.session_id,
        p_reason: body.reason ?? 'admin_revoke',
      });
      if (error || !data?.ok) return json({ ok: false, error: data?.error ?? 'ADMIN_REVOKE_FAILED' }, 400);
      return json({ ok: true });
    }

    return json({ ok: false, error: "INVALID_MODE" }, 400);
  } catch {
    return json({ ok: false, error: "SESSION_OPERATION_FAILED" }, 500);
  }
});
