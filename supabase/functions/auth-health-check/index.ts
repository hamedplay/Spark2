import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const noStoreHeaders = {
  ...corsHeaders,
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
  "Pragma": "no-cache",
};

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: noStoreHeaders });

function adminClient() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
}

async function authenticate(req: Request): Promise<string | null> {
  const header = req.headers.get("Authorization");
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  const { data, error } = await adminClient().auth.getUser(token);
  if (error || !data.user) return null;
  const { data: profile } = await adminClient().from("profiles").select("is_admin, is_active").eq("user_id", data.user.id).maybeSingle();
  if (!profile?.is_active) return null;
  if (!profile.is_admin) {
    const { data: secAdmin } = await adminClient().from("security_admin_roles").select("is_active").eq("user_id", data.user.id).eq("is_active", true).maybeSingle();
    if (!secAdmin) return null;
  }
  return data.user.id;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "GET" && req.method !== "POST") return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);

  const userId = await authenticate(req);
  if (!userId) return json({ ok: false, error: "UNAUTHORIZED" }, 401);

  try {
    const admin = adminClient();

    // ── Health check ─────────────────────────────────────────────────────
    const { data: health, error: healthError } = await admin.rpc("get_auth_health_check");
    if (healthError || !health) return json({ ok: false, error: "HEALTH_CHECK_FAILED" }, 500);

    // ── Edge function readiness (not hardcoded — unknown unless introspectable) ──
    const requiredFunctions = [
      "custom-mfa", "unified-recovery", "session-management",
      "password-login", "send-sms", "send-bale-message",
      "auth-send-sms-hook", "spark-ai",
    ];
    const functionsStatus = requiredFunctions.map((fn) => ({ name: fn, status: "not_verified" as const }));

    // ── SMS readiness: active provider in DB ──────────────────────────────
    const { data: smsConfig } = await admin.from("sms_providers").select("id, is_active, is_default").eq("is_active", true).limit(1).maybeSingle();

    // ── Bale readiness: Edge Secret only ──────────────────────────────────
    const baleSecret = Deno.env.get("BALE_BOT_TOKEN") ?? "";
    const baleReady = baleSecret.length > 0;

    // ── Email readiness: Edge Secret ──────────────────────────────────────
    const emailSecret = Deno.env.get("SMTP_HOST") ?? "";
    const emailReady = emailSecret.length > 0;

    // ── Settings ──────────────────────────────────────────────────────────
    const { data: settings } = await admin.from("auth_security_settings").select("unified_recovery_enabled, progressive_lock_enabled, session_management_enabled, custom_mfa_enabled, recovery_enabled").eq("id", 1).maybeSingle();

    return json({
      ok: true,
      timestamp: new Date().toISOString(),
      database: health,
      edge_functions: functionsStatus,
      transport: {
        sms: smsConfig ? "ready" : "not_ready",
        bale: baleReady ? "ready" : "not_ready",
        email: emailReady ? "ready" : "not_ready",
      },
      settings: settings ?? {},
      deprecated_routes: health.deprecated_routes ?? [],
    });
  } catch {
    return json({ ok: false, error: "HEALTH_CHECK_FAILED" }, 500);
  }
});
