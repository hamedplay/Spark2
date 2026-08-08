import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const ok = () => new Response("OK", { status: 200 });

async function hmac(value: string, context: string): Promise<string> {
  const pepper = Deno.env.get("MFA_PEPPER");
  if (!pepper) throw new Error("MFA_NOT_READY");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(`${context}:${pepper}`), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return Array.from(new Uint8Array(signature)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req: Request) => {
  try {
    if (req.method === "OPTIONS") return new Response(null, { status: 200 });
    if (req.method !== "POST") return ok();

    let update: Record<string, any>;
    try { update = await req.json(); } catch { return ok(); }

    const msg = update.message ?? update.edited_message;
    const chatId: number | undefined = msg?.chat?.id;
    const text: string = (msg?.text ?? "").trim();
    if (!chatId || !text.startsWith("/start")) return ok();

    const startMatch = text.match(/^\/start(?:@\w+)?(?:[\s=]+(\S+))?/i);
    const linkToken: string | null = startMatch?.[1] ?? null;

    const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    // Bot token from Edge Secret only
    const botToken = Deno.env.get("BALE_BOT_TOKEN");
    if (!botToken) { console.error("[bale-webhook] BALE_BOT_TOKEN not configured"); return ok(); }

    if (!linkToken) {
      await sendMessage(botToken, chatId, "سلام! برای دریافت اعلان‌های سامانه، از بخش پروفایل روی «اتصال به بله» کلیک کنید.");
      return ok();
    }

    // HMAC-only nonce lookup, atomic consume via service RPC
    const nonceHash = await hmac(linkToken, "bale_nonce");

    // Encrypt chat_id server-side — browser never sends chat_id
    const chatIdStr = String(chatId);
    const chatIdHmac = await hmac(chatIdStr, "bale_chat_id");

    const { data: consumeResult, error: consumeErr } = await supabase.rpc("consume_bale_link_nonce", {
      p_nonce_hash: nonceHash,
      p_user_id: null,
      p_bale_chat_id_enc: null,
      p_bale_chat_id_hmac: null,
    });

    // The v2 consume_bale_link_nonce requires enc/hmac — we need to encrypt first
    // Use the mfa_encrypt RPC
    const { data: encData, error: encErr } = await supabase.rpc("mfa_encrypt", { p_plaintext: chatIdStr });
    if (encErr || !encData) {
      console.error("[bale-webhook] encrypt error:", encErr?.message);
      await sendMessage(botToken, chatId, "خطای داخلی. لطفاً دوباره تلاش کنید.");
      return ok();
    }

    const { data: nonceRow, error: nonceErr } = await supabase
      .from("bale_link_nonces")
      .select("user_id, used_at, expires_at")
      .eq("nonce_hash", nonceHash)
      .maybeSingle();

    if (nonceErr || !nonceRow) {
      await sendMessage(botToken, chatId, "❌ لینک اتصال نامعتبر یا منقضی شده است. لطفاً از سامانه دوباره روی «اتصال به بله» کلیک کنید.");
      return ok();
    }

    if (nonceRow.used_at) {
      await sendMessage(botToken, chatId, "❌ این لینک قبلاً استفاده شده است.");
      return ok();
    }

    const expiresAt = new Date(nonceRow.expires_at);
    if (expiresAt <= new Date()) {
      await sendMessage(botToken, chatId, "❌ لینک اتصال منقضی شده است. لطفاً دوباره تلاش کنید.");
      return ok();
    }

    // Atomic consume: mark used
    const { data: consumed, error: markErr } = await supabase
      .from("bale_link_nonces")
      .update({ used_at: new Date().toISOString() })
      .eq("nonce_hash", nonceHash)
      .is("used_at", null)
      .select("user_id");

    if (markErr || !consumed || consumed.length === 0) {
      await sendMessage(botToken, chatId, "❌ لینک اتصال نامعتبر یا قبلاً استفاده شده است.");
      return ok();
    }

    const userId: string = consumed[0].user_id;

    // Store encrypted chat_id (never plaintext)
    const { error: upsertErr } = await supabase
      .from("user_bale_mapping")
      .upsert({
        user_id: userId,
        bale_chat_id_enc: encData,
        bale_chat_id_hmac: chatIdHmac,
        bale_mfa_codes_enabled: true,
        connected_at: new Date().toISOString(),
        last_connected_at: new Date().toISOString(),
      }, { onConflict: "user_id" });

    if (upsertErr) {
      console.error("[bale-webhook] upsert error:", upsertErr.message);
      await sendMessage(botToken, chatId, "خطا در ذخیره‌سازی. لطفاً دوباره تلاش کنید.");
      return ok();
    }

    // Also update custom_mfa_factors bale factor
    await supabase.from("custom_mfa_factors")
      .update({
        bale_chat_id_enc: encData,
        bale_chat_id_hmac: chatIdHmac,
        factor_status: "active",
        updated_at: new Date().toISOString(),
      })
      .eq("user_id", userId)
      .eq("factor_type", "bale");

    await supabase.from("security_audit_events").insert({
      user_id: userId,
      actor_user_id: userId,
      event_type: "bale_mfa_linked",
      event_category: "mfa",
      severity: "info",
      result: "success",
    });

    console.log("[bale-webhook] SUCCESS user_id=%s linked bale_chat_id (encrypted)", userId);
    await sendMessage(botToken, chatId, "✅ اتصال شما با موفقیت انجام شد. از این پس اعلان‌های جلسه را اینجا دریافت می‌کنید.");
    return ok();
  } catch (err) {
    console.error("[bale-webhook] unexpected error:", err);
    return ok();
  }
});

async function sendMessage(token: string, chatId: number | string, text: string): Promise<void> {
  try {
    const res = await fetch(`https://tapi.bale.ai/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      console.warn("[bale-webhook] sendMessage HTTP %s: %s", res.status, body.slice(0, 200));
    }
  } catch (e) {
    console.warn("[bale-webhook] sendMessage network error:", e);
  }
}
