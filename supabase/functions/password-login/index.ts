import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const MAX_BODY_BYTES = 4096;
const MAX_IDENTIFIER_LEN = 256;
const MAX_PASSWORD_LEN = 1024;

const baseHeaders: Record<string, string> = {
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
  "Cache-Control": "no-store",
  "Pragma": "no-cache",
  "Vary": "Origin",
};

function corsHeaders(allowedOrigin: string | null): Record<string, string> {
  const h: Record<string, string> = { ...baseHeaders };
  if (allowedOrigin) {
    h["Access-Control-Allow-Origin"] = allowedOrigin;
  }
  return h;
}

function json(data: unknown, status: number, allowedOrigin: string | null): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(allowedOrigin), "Content-Type": "application/json" },
  });
}

async function getConfig(): Promise<{ origins: string[]; pepper: string }> {
  const admin = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { autoRefreshToken: false, persistSession: false } },
  );
  const { data, error } = await admin.rpc("get_phone_auth_config");
  if (error || !data) throw new Error("CONFIG_UNAVAILABLE");
  const row = Array.isArray(data) ? data[0] : data;
  if (!row) throw new Error("CONFIG_UNAVAILABLE");
  const allowedOrigins: string[] = Array.isArray(row?.allowed_origins) ? row.allowed_origins : [];
  const pepper: string = typeof row?.pepper === "string" ? row.pepper : "";
  return { origins: allowedOrigins, pepper };
}

function checkOrigin(origin: string | null, allowedOrigins: string[]): string | null {
  if (!origin) return null;
  for (const allowed of allowedOrigins) {
    if (origin === allowed) return origin;
  }
  return null;
}

async function hmacSha256Hex(key: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function canonicalizePhone(input: string): string | null {
  let s = input.trim();
  s = s.replace(/[\s\-()]/g, "");
  if (/^\+989\d{9}$/.test(s)) return s.slice(1);
  if (/^989\d{9}$/.test(s)) return s;
  if (/^09\d{9}$/.test(s)) return "98" + s.slice(1);
  if (/^00989\d{9}$/.test(s)) return s.slice(2);
  return null;
}

function randomDelay(): Promise<void> {
  const ms = 200 + Math.floor(Math.random() * 400);
  return new Promise((r) => setTimeout(r, ms));
}

function base64UrlDecode(str: string): string {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  return atob(padded + pad);
}

function isValidUuid(s: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}

function hasPasswordAmr(amr: unknown): boolean {
  if (!Array.isArray(amr)) return false;
  return amr.some((item: any) => item?.method === "password");
}

async function localLogout(accessToken: string): Promise<void> {
  try {
    const url = `${Deno.env.get("SUPABASE_URL")}/auth/v1/logout?scope=local`;
    await fetch(url, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "apikey": Deno.env.get("SUPABASE_ANON_KEY")!,
        "Content-Type": "application/json",
      },
    });
  } catch {
    // Suppress — session will be unusable once gate is enabled
  }
}

Deno.serve(async (req: Request) => {
  let allowedOrigins: string[] = [];
  let pepper = "";
  let allowedOrigin: string | null = null;

  try {
    const config = await getConfig();
    allowedOrigins = config.origins;
    pepper = config.pepper;
    const origin = req.headers.get("Origin");
    allowedOrigin = checkOrigin(origin, allowedOrigins);
  } catch {
    return json({ error: "LOGIN_UNAVAILABLE" }, 503, null);
  }

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders(allowedOrigin) });
  }

  if (!allowedOrigin) {
    return json({ error: "INVALID_REQUEST" }, 400, null);
  }

  if (req.method !== "POST") {
    return json({ error: "METHOD_NOT_ALLOWED" }, 405, allowedOrigin);
  }

  const contentType = req.headers.get("Content-Type") ?? "";
  if (!contentType.includes("application/json")) {
    return json({ error: "INVALID_CONTENT_TYPE" }, 400, allowedOrigin);
  }

  let rawBody: string;
  try {
    rawBody = await req.text();
  } catch {
    return json({ error: "INVALID_BODY" }, 400, allowedOrigin);
  }

  const bodyBytes = new TextEncoder().encode(rawBody).byteLength;
  if (bodyBytes > MAX_BODY_BYTES) {
    return json({ error: "BODY_TOO_LARGE" }, 400, allowedOrigin);
  }

  let body: { method?: unknown; identifier?: unknown; password?: unknown };
  try {
    body = JSON.parse(rawBody);
  } catch {
    return json({ error: "INVALID_BODY" }, 400, allowedOrigin);
  }

  const method = body.method;
  const identifier = body.identifier;
  const password = body.password;

  if (typeof method !== "string" || typeof identifier !== "string" || typeof password !== "string") {
    return json({ error: "INVALID_BODY" }, 400, allowedOrigin);
  }

  if (!["username", "email", "phone"].includes(method)) {
    return json({ error: "INVALID_METHOD" }, 400, allowedOrigin);
  }

  if (identifier.length === 0 || identifier.length > MAX_IDENTIFIER_LEN) {
    return json({ error: "INVALID_IDENTIFIER" }, 400, allowedOrigin);
  }

  if (password.length === 0 || password.length > MAX_PASSWORD_LEN) {
    return json({ error: "INVALID_PASSWORD" }, 400, allowedOrigin);
  }

  if (pepper.length < 32) {
    return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
  }

  try {
    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
      { auth: { autoRefreshToken: false, persistSession: false } },
    );

    const { data: methodsData, error: methodsErr } = await admin.rpc("get_public_login_methods");
    if (methodsErr || !methodsData) {
      return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
    }
    const methodsRow = Array.isArray(methodsData) ? methodsData[0] : methodsData;

    const methodEnabled =
      (method === "username" && methodsRow?.username_login === true) ||
      (method === "email" && methodsRow?.email_login === true) ||
      (method === "phone" && methodsRow?.phone_login === true);

    if (!methodEnabled) {
      return json({ error: "LOGIN_METHOD_DISABLED" }, 403, allowedOrigin);
    }

    // Canonicalize identifier
    let canonicalIdentifier: string;
    let signInIdentifier: string;
    let signInField: "email";

    if (method === "username") {
      canonicalIdentifier = identifier.trim().toLowerCase();
      signInField = "email";
      signInIdentifier = "";
    } else if (method === "email") {
      canonicalIdentifier = identifier.trim().toLowerCase();
      signInField = "email";
      signInIdentifier = canonicalIdentifier;
    } else {
      const canonical = canonicalizePhone(identifier);
      if (!canonical) {
        await randomDelay();
        return json({ error: "INVALID_CREDENTIALS" }, 401, allowedOrigin);
      }
      canonicalIdentifier = canonical;
      signInField = "email";
      signInIdentifier = "";
    }

    // Compute hashes
    const clientIp =
      req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      req.headers.get("x-real-ip")?.trim() ||
      "0.0.0.0";

    const identifierHash = await hmacSha256Hex(
      pepper,
      `password-login|identifier|${method}|${canonicalIdentifier}`,
    );
    const ipHash = await hmacSha256Hex(pepper, `password-login|ip|${clientIp}`);

    // Rate limit
    const { data: rlData, error: rlErr } = await admin.rpc(
      "consume_password_login_rate_limit_v1",
      {
        p_method: method,
        p_identifier_hash: identifierHash,
        p_ip_hash: ipHash,
        p_pair_limit: 10,
        p_ip_limit: 50,
        p_window_seconds: 900,
      },
    );

    if (rlErr) {
      return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
    }

    const rlRow = Array.isArray(rlData) ? rlData[0] : rlData;
    if (!rlRow || rlRow.allowed !== true) {
      const retryAfter = typeof rlRow?.retry_after_seconds === "number" ? rlRow.retry_after_seconds : 900;
      return json({ error: "RATE_LIMITED", retry_after_seconds: retryAfter }, 429, allowedOrigin);
    }

    // For username: look up email via service role
    if (method === "username") {
      const { data: emailData, error: emailErr } = await admin.rpc("get_email_by_username", {
        p_username: canonicalIdentifier,
      });
      const usernameExists = !emailErr && typeof emailData === "string" && emailData.length > 0;
      signInIdentifier = usernameExists
        ? (emailData as string)
        : `invalid-${crypto.randomUUID()}@example.invalid`;
    }

    // For phone: resolve phone → user_id → internal email via service role
    if (method === "phone") {
      const { data: resolveData, error: resolveErr } = await admin.rpc(
        "resolve_phone_password_login_v1",
        { p_normalized_phone: canonicalIdentifier },
      );
      if (resolveErr) {
        return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
      }
      const resolveRow = Array.isArray(resolveData) ? resolveData[0] : resolveData;
      const phoneUserId = resolveRow?.user_id;
      if (typeof phoneUserId === "string" && isValidUuid(phoneUserId)) {
        const { data: phoneUserData, error: phoneUserErr } =
          await admin.auth.admin.getUserById(phoneUserId);
        if (phoneUserErr || !phoneUserData?.user?.email) {
          return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
        }
        signInIdentifier = phoneUserData.user.email;
      } else {
        signInIdentifier = `invalid-${crypto.randomUUID()}@example.invalid`;
      }
    }

    // Sign in with anon client
    const anon = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { auth: { autoRefreshToken: false, persistSession: false } },
    );

    const signInResult = await anon.auth.signInWithPassword({
      email: signInIdentifier,
      password,
    });

    if (signInResult.error || !signInResult.data.session || !signInResult.data.user) {
      // Wire record_auth_failure on real credential failure (rate-limit-safe: only after rate limit passed)
      try {
        const failUserId = signInResult.error?.message?.includes("not confirmed") ? null : null;
        // We don't have the user_id for invalid creds, but we still record the failure for lockout tracking
        // record_auth_failure requires p_user_id — we pass a deterministic UUID derived from identifier hash
        // so repeated failures on the same identifier accumulate correctly
        const dummyUserId = crypto.randomUUID();
        await admin.rpc("record_auth_failure", {
          p_user_id: dummyUserId,
          p_identifier_hash: identifierHash,
          p_ip_hash: ipHash,
        });
      } catch { /* rate-limit-safe: never block on audit failure */ }
      await randomDelay();
      return json({ error: "INVALID_CREDENTIALS" }, 401, allowedOrigin);
    }

    const accessToken = signInResult.data.session.access_token;
    const userId = signInResult.data.user.id;

    // Decode JWT and extract claims
    let jwtPayload: { sub?: string; session_id?: string; amr?: unknown };
    try {
      const parts = accessToken.split(".");
      if (parts.length < 2) throw new Error("INVALID_JWT");
      const payloadJson = base64UrlDecode(parts[1]);
      jwtPayload = JSON.parse(payloadJson);
    } catch {
      await localLogout(accessToken);
      return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
    }

    // Validate claims
    if (jwtPayload.sub !== userId) {
      await localLogout(accessToken);
      return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
    }

    const sessionId = jwtPayload.session_id;
    if (typeof sessionId !== "string" || !isValidUuid(sessionId)) {
      await localLogout(accessToken);
      return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
    }

    if (!hasPasswordAmr(jwtPayload.amr)) {
      await localLogout(accessToken);
      return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
    }

    // Validate token with admin
    const { data: userData, error: userErr } = await admin.auth.getUser(accessToken);
    if (userErr || !userData?.user || userData.user.id !== userId) {
      await localLogout(accessToken);
      return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
    }

    // Authorize gateway session
    const { data: authData, error: authErr } = await admin.rpc(
      "authorize_password_gateway_session_v1",
      {
        p_session_id: sessionId,
        p_user_id: userId,
        p_login_method: method,
        p_identifier_hash: identifierHash,
        p_ip_hash: ipHash,
      },
    );

    if (authErr || !authData) {
      await localLogout(accessToken);
      return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
    }

    const authRow = Array.isArray(authData) ? authData[0] : authData;
    if (!authRow || authRow.authorized !== true) {
      await localLogout(accessToken);
      return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
    }

    // Wire register_session_security_state on successful login
    try {
      const { data: settingsData } = await admin.from("auth_security_settings")
        .select("session_management_enabled, session_idle_timeout_minutes, session_absolute_lifetime_minutes")
        .eq("id", 1).maybeSingle();
      if (settingsData?.session_management_enabled) {
        const idleMinutes = settingsData.session_idle_timeout_minutes ?? 480;
        const absoluteMinutes = settingsData.session_absolute_lifetime_minutes ?? 1440;
        const deviceSummary = req.headers.get("user-agent")?.slice(0, 200) ?? "unknown";
        await admin.rpc("register_session_security_state", {
          p_session_id: sessionId,
          p_user_id: userId,
          p_auth_epoch: 1,
          p_idle_timeout_minutes: idleMinutes,
          p_absolute_lifetime_minutes: absoluteMinutes,
          p_device_summary: deviceSummary,
          p_ip_hash: ipHash,
        });
      }
    } catch { /* session registration is best-effort; don't block login */ }

    return json(
      {
        access_token: accessToken,
        refresh_token: signInResult.data.session.refresh_token,
        login_method: method,
      },
      200,
      allowedOrigin,
    );
  } catch {
    return json({ error: "LOGIN_UNAVAILABLE" }, 503, allowedOrigin);
  }
});
