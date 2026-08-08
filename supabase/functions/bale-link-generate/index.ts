import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { requireFullAuthAccess, deniedResponse } from "../_shared/requireFullAuthAccess.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-store", "Pragma": "no-cache" },
  });
}

async function hmac(value: string, context: string): Promise<string> {
  const pepper = Deno.env.get("MFA_PEPPER");
  if (!pepper) throw new Error("MFA_NOT_READY");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(`${context}:${pepper}`), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return Array.from(new Uint8Array(signature)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });

  const authResult = await requireFullAuthAccess(req);
  if (!authResult.ok) return deniedResponse();
  const user = { id: authResult.userId! };

  const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
  const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  const admin = createClient(supabaseUrl, supabaseServiceKey);

  // Read bot username from DB (bot token stays in Edge Secret only)
  const { data: channelCfg, error: cfgErr } = await admin
    .from("social_channel_configs")
    .select("bot_username, is_active")
    .eq("channel", "bale")
    .maybeSingle();

  if (cfgErr) return json({ ok: false, error: "خطا در خواندن تنظیمات" }, 500);
  if (!channelCfg || !channelCfg.is_active) return json({ ok: false, error: "اتصال بله در حال حاضر غیرفعال است" }, 403);

  const baleBotUsername = (channelCfg.bot_username ?? "").replace(/^@/, "").trim();
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(baleBotUsername)) return json({ ok: false, error: "bot_username نامعتبر است" }, 500);

  // Generate 32-byte (64 hex char) one-time nonce
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const nonce = Array.from(nonceBytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  const nonceHash = await hmac(nonce, "bale_nonce");
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  // Store nonce via service RPC (HMAC-only, atomic)
  const { error: nonceErr } = await admin.rpc("create_bale_link_nonce", {
    p_nonce_hash: nonceHash,
    p_user_id: user.id,
    p_expires_at: expiresAt,
  });

  if (nonceErr) return json({ ok: false, error: "خطا در تولید لینک اتصال" }, 500);

  const url = `https://ble.ir/${baleBotUsername}?start=${nonce}`;
  return json({ ok: true, url, nonce, expires_at: expiresAt });
});
