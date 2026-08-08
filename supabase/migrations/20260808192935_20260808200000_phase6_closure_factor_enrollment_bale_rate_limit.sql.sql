-- Phase 6 Closure: factor enrollment, recovery code revoke, Bale nonce consume, rate-limit, readiness

-- ════════════════════════════════════════════════════════════════════════════
-- 1. Add revoked_at to recovery codes (revoke instead of delete)
-- ════════════════════════════════════════════════════════════════════════════
ALTER TABLE public.custom_mfa_recovery_codes
  ADD COLUMN IF NOT EXISTS revoked_at timestamptz;

-- ════════════════════════════════════════════════════════════════════════════
-- 2. Add rate-limit columns to custom_mfa_challenges
-- ════════════════════════════════════════════════════════════════════════════
ALTER TABLE public.custom_mfa_challenges
  ADD COLUMN IF NOT EXISTS ip_hash text,
  ADD COLUMN IF NOT EXISTS resend_count integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS resend_available_at timestamptz;

-- ════════════════════════════════════════════════════════════════════════════
-- 3. Factor enrollment RPCs (service_role only)
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.enroll_custom_mfa_factor(
  p_user_id uuid,
  p_factor_type text,
  p_phone_hash text DEFAULT NULL,
  p_email_hash text DEFAULT NULL,
  p_bale_chat_id_enc bytea DEFAULT NULL,
  p_bale_chat_id_hmac text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_existing public.custom_mfa_factors%ROWTYPE;
  v_factor_id uuid;
BEGIN
  IF p_user_id IS NULL OR p_factor_type NOT IN ('sms','bale','email') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;

  -- Check for existing factor of same type
  SELECT * INTO v_existing FROM public.custom_mfa_factors
  WHERE user_id = p_user_id AND factor_type = p_factor_type LIMIT 1;

  IF FOUND THEN
    -- Update existing factor to active
    UPDATE public.custom_mfa_factors SET
      factor_status = 'active',
      phone_hash = COALESCE(p_phone_hash, phone_hash),
      email_hash = COALESCE(p_email_hash, email_hash),
      bale_chat_id_enc = COALESCE(p_bale_chat_id_enc, bale_chat_id_enc),
      bale_chat_id_hmac = COALESCE(p_bale_chat_id_hmac, bale_chat_id_hmac),
      updated_at = now()
    WHERE id = v_existing.id
    RETURNING id INTO v_factor_id;
  ELSE
    INSERT INTO public.custom_mfa_factors (
      user_id, factor_type, factor_status,
      phone_hash, email_hash, bale_chat_id_enc, bale_chat_id_hmac
    ) VALUES (
      p_user_id, p_factor_type, 'active',
      p_phone_hash, p_email_hash, p_bale_chat_id_enc, p_bale_chat_id_hmac
    ) RETURNING id INTO v_factor_id;
  END IF;

  RETURN jsonb_build_object('ok', true, 'factor_id', v_factor_id);
END;
$$;
REVOKE ALL ON FUNCTION public.enroll_custom_mfa_factor(uuid, text, text, text, bytea, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.enroll_custom_mfa_factor(uuid, text, text, text, bytea, text) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 4. Disable factor (cannot activate MFA without valid factor)
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.disable_custom_mfa_factor(
  p_user_id uuid,
  p_factor_type text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE v_updated int;
BEGIN
  IF p_user_id IS NULL OR p_factor_type NOT IN ('sms','bale','email','totp') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;
  UPDATE public.custom_mfa_factors SET factor_status = 'disabled', updated_at = now()
  WHERE user_id = p_user_id AND factor_type = p_factor_type AND factor_status = 'active'
  RETURNING 1 INTO v_updated;
  IF v_updated IS NULL THEN RETURN jsonb_build_object('ok', false, 'error', 'FACTOR_NOT_ACTIVE'); END IF;
  RETURN jsonb_build_object('ok', true);
END;
$$;
REVOKE ALL ON FUNCTION public.disable_custom_mfa_factor(uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.disable_custom_mfa_factor(uuid, text) TO service_role;

-- ═════════════════════════════════════════════════════════════════════════════
-- 5. Regenerate recovery codes (revoke old, issue new — requires FULL + step-up)
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.regenerate_custom_mfa_recovery_codes_v2(
  p_user_id uuid,
  p_code_hashes text[]
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
BEGIN
  IF p_user_id IS NULL OR p_code_hashes IS NULL OR array_length(p_code_hashes, 1) IS NULL OR array_length(p_code_hashes, 1) = 0 THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;

  -- Revoke all prior unused recovery codes (not delete)
  UPDATE public.custom_mfa_recovery_codes SET revoked_at = now()
  WHERE user_id = p_user_id AND used_at IS NULL AND revoked_at IS NULL;

  -- Insert new codes
  INSERT INTO public.custom_mfa_recovery_codes (user_id, code_hash)
  SELECT p_user_id, unnest(p_code_hashes);

  RETURN jsonb_build_object('ok', true, 'code_count', array_length(p_code_hashes, 1));
END;
$$;
REVOKE ALL ON FUNCTION public.regenerate_custom_mfa_recovery_codes_v2(uuid, text[]) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.regenerate_custom_mfa_recovery_codes_v2(uuid, text[]) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 6. Atomic one-time Bale nonce consume (HMAC-only lookup)
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.consume_bale_link_nonce(
  p_nonce_hash text,
  p_user_id uuid,
  p_bale_chat_id_enc bytea,
  p_bale_chat_id_hmac text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_nonce record;
  v_updated int;
BEGIN
  IF p_nonce_hash IS NULL OR p_user_id IS NULL OR p_bale_chat_id_enc IS NULL OR p_bale_chat_id_hmac IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;

  -- HMAC-only lookup with FOR UPDATE for atomic consume
  SELECT * INTO v_nonce FROM public.bale_link_nonces
  WHERE nonce_hash = p_nonce_hash AND used_at IS NULL AND expires_at > now()
  FOR UPDATE;

  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'error', 'NONCE_INVALID_OR_EXPIRED'); END IF;

  IF v_nonce.user_id <> p_user_id THEN
    RETURN jsonb_build_object('ok', false, 'error', 'NONCE_USER_MISMATCH');
  END IF;

  -- Atomic one-time consume
  UPDATE public.bale_link_nonces SET used_at = now()
  WHERE nonce_hash = p_nonce_hash AND used_at IS NULL RETURNING 1 INTO v_updated;

  IF v_updated IS NULL THEN RETURN jsonb_build_object('ok', false, 'error', 'NONCE_CONSUMED_RACE'); END IF;

  -- Store encrypted chat_id (never plaintext)
  UPDATE public.user_bale_mapping SET
    bale_chat_id_enc = p_bale_chat_id_enc,
    bale_chat_id_hmac = p_bale_chat_id_hmac,
    last_connected_at = now()
  WHERE user_id = p_user_id;

  IF NOT FOUND THEN
    INSERT INTO public.user_bale_mapping (user_id, bale_chat_id_enc, bale_chat_id_hmac, connected_at, last_connected_at)
    VALUES (p_user_id, p_bale_chat_id_enc, p_bale_chat_id_hmac, now(), now());
  END IF;

  -- Also update custom_mfa_factors if bale factor exists
  UPDATE public.custom_mfa_factors SET
    bale_chat_id_enc = p_bale_chat_id_enc,
    bale_chat_id_hmac = p_bale_chat_id_hmac,
    factor_status = 'active',
    updated_at = now()
  WHERE user_id = p_user_id AND factor_type = 'bale';

  RETURN jsonb_build_object('ok', true);
END;
$$;
REVOKE ALL ON FUNCTION public.consume_bale_link_nonce(text, uuid, bytea, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_bale_link_nonce(text, uuid, bytea, text) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 7. Create Bale link nonce (32-byte minimum enforced in edge function)
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.create_bale_link_nonce(
  p_nonce_hash text,
  p_user_id uuid,
  p_expires_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
BEGIN
  IF p_nonce_hash IS NULL OR p_user_id IS NULL OR p_expires_at IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;
  IF length(p_nonce_hash) < 64 THEN
    RETURN jsonb_build_object('ok', false, 'error', 'NONCE_HASH_TOO_SHORT');
  END IF;
  IF p_expires_at <= now() OR p_expires_at > now() + interval '10 minutes' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_EXPIRY');
  END IF;

  INSERT INTO public.bale_link_nonces (nonce_hash, user_id, expires_at)
  VALUES (p_nonce_hash, p_user_id, p_expires_at)
  ON CONFLICT (nonce_hash) DO NOTHING;

  RETURN jsonb_build_object('ok', true);
END;
$$;
REVOKE ALL ON FUNCTION public.create_bale_link_nonce(text, uuid, timestamptz) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.create_bale_link_nonce(text, uuid, timestamptz) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 8. MFA challenge rate-limit RPC (per user/session/IP)
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.consume_mfa_challenge_rate_limit(
  p_user_id uuid,
  p_session_id uuid,
  p_ip_hash text,
  p_user_limit integer DEFAULT 5,
  p_session_limit integer DEFAULT 5,
  p_ip_limit integer DEFAULT 20,
  p_window_seconds integer DEFAULT 900
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_user_count integer;
  v_session_count integer;
  v_ip_count integer;
  v_lock_key bigint;
  v_retry integer;
BEGIN
  IF p_user_id IS NULL OR p_session_id IS NULL OR p_ip_hash IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;

  v_lock_key := hashtext(p_ip_hash);
  PERFORM pg_advisory_xact_lock(v_lock_key);

  SELECT count(*) INTO v_user_count FROM public.custom_mfa_challenges
  WHERE user_id = p_user_id AND created_at > now() - (p_window_seconds || ' seconds')::interval;

  IF v_user_count >= p_user_limit THEN
    v_retry := p_window_seconds;
    RETURN jsonb_build_object('ok', true, 'allowed', false, 'retry_after_seconds', v_retry, 'reason', 'USER_LIMIT');
  END IF;

  SELECT count(*) INTO v_session_count FROM public.custom_mfa_challenges
  WHERE user_id = p_user_id AND session_id = p_session_id AND created_at > now() - (p_window_seconds || ' seconds')::interval;

  IF v_session_count >= p_session_limit THEN
    v_retry := p_window_seconds;
    RETURN jsonb_build_object('ok', true, 'allowed', false, 'retry_after_seconds', v_retry, 'reason', 'SESSION_LIMIT');
  END IF;

  SELECT count(*) INTO v_ip_count FROM public.custom_mfa_challenges
  WHERE ip_hash = p_ip_hash AND created_at > now() - (p_window_seconds || ' seconds')::interval;

  IF v_ip_count >= p_ip_limit THEN
    v_retry := p_window_seconds;
    RETURN jsonb_build_object('ok', true, 'allowed', false, 'retry_after_seconds', v_retry, 'reason', 'IP_LIMIT');
  END IF;

  RETURN jsonb_build_object('ok', true, 'allowed', true);
END;
$$;
REVOKE ALL ON FUNCTION public.consume_mfa_challenge_rate_limit(uuid, uuid, text, integer, integer, integer, integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_mfa_challenge_rate_limit(uuid, uuid, text, integer, integer, integer, integer) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 9. Update challenge with resend info
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.update_mfa_challenge_resend(
  p_challenge_id uuid,
  p_otp_hash text,
  p_resend_available_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE v_updated int;
BEGIN
  IF p_challenge_id IS NULL OR p_otp_hash IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;
  UPDATE public.custom_mfa_challenges SET
    otp_hash = p_otp_hash,
    resend_count = resend_count + 1,
    resend_available_at = p_resend_available_at,
    attempt_count = 0,
    status = 'pending',
    updated_at = now()
  WHERE id = p_challenge_id AND status IN ('pending','expired','max_attempts') AND resend_count < (
    SELECT custom_mfa_max_resends FROM public.auth_security_settings WHERE id = 1 LIMIT 1
  ) RETURNING 1 INTO v_updated;
  IF v_updated IS NULL THEN RETURN jsonb_build_object('ok', false, 'error', 'RESEND_NOT_AVAILABLE'); END IF;
  RETURN jsonb_build_object('ok', true);
END;
$$;
REVOKE ALL ON FUNCTION public.update_mfa_challenge_resend(uuid, text, timestamptz) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.update_mfa_challenge_resend(uuid, text, timestamptz) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 10. MFA readiness check (secret-gated)
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.get_custom_mfa_readiness()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_settings record;
  v_pepper text;
  v_bale_bot_token text;
BEGIN
  SELECT custom_mfa_enabled, custom_mfa_required, custom_mfa_allowed_factors,
         custom_mfa_max_resends, custom_mfa_max_attempts, custom_mfa_challenge_ttl_seconds
  INTO v_settings FROM public.auth_security_settings WHERE id = 1 LIMIT 1;

  v_pepper := current_setting('app.mfa_pepper', true);
  v_bale_bot_token := current_setting('app.bale_bot_token', true);

  RETURN jsonb_build_object(
    'ok', true,
    'mfa_enabled', COALESCE(v_settings.custom_mfa_enabled, false),
    'mfa_required', COALESCE(v_settings.custom_mfa_required, false),
    'allowed_factors', COALESCE(v_settings.custom_mfa_allowed_factors, ARRAY[]::text[]),
    'pepper_ready', v_pepper IS NOT NULL AND length(v_pepper) > 0,
    'bale_bot_token_ready', v_bale_bot_token IS NOT NULL AND length(v_bale_bot_token) > 0,
    'sms_ready', EXISTS(SELECT 1 FROM public.sms_providers WHERE is_active = true LIMIT 1),
    'email_ready', false,
    'readiness', CASE
      WHEN NOT COALESCE(v_settings.custom_mfa_enabled, false) THEN 'disabled'
      WHEN v_pepper IS NULL OR length(v_pepper) = 0 THEN 'not_ready'
      WHEN 'sms' = ANY(COALESCE(v_settings.custom_mfa_allowed_factors, ARRAY[]::text[]))
        AND NOT EXISTS(SELECT 1 FROM public.sms_providers WHERE is_active = true LIMIT 1) THEN 'not_ready'
      WHEN 'bale' = ANY(COALESCE(v_settings.custom_mfa_allowed_factors, ARRAY[]::text[]))
        AND (v_bale_bot_token IS NULL OR length(v_bale_bot_token) = 0) THEN 'not_ready'
      ELSE 'ready'
    END
  );
END;
$$;
REVOKE ALL ON FUNCTION public.get_custom_mfa_readiness() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_custom_mfa_readiness() TO authenticated;
