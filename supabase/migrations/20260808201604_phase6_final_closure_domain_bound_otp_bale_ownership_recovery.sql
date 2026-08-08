-- Phase 6 Final Closure: domain-bound OTP, Bale ownership proof, recovery code flow, legacy ACL hardening

-- ════════════════════════════════════════════════════════════════════════════
-- 1. Add target_hash to custom_mfa_challenges for domain-bound OTP
-- ════════════════════════════════════════════════════════════════════════════
ALTER TABLE public.custom_mfa_challenges
  ADD COLUMN IF NOT EXISTS target_hash text;

-- ════════════════════════════════════════════════════════════════════════════
-- 2. Service RPC: create challenge with domain-bound OTP hash
--    OTP HMAC = HMAC(challenge_id || user_id || session_id || factor_type || target_hash || otp_code)
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.create_custom_mfa_challenge_v2(
  p_user_id uuid,
  p_factor_type text,
  p_session_id uuid,
  p_otp_hash text,
  p_target_hash text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_factor public.custom_mfa_factors%ROWTYPE;
  v_settings record;
  v_challenge_id uuid;
  v_expires_at timestamptz;
BEGIN
  IF p_user_id IS NULL OR p_session_id IS NULL OR p_otp_hash IS NULL OR p_target_hash IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;
  IF p_factor_type NOT IN ('sms','bale','email') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;

  SELECT * INTO v_factor FROM public.custom_mfa_factors
  WHERE user_id = p_user_id AND factor_type = p_factor_type AND factor_status = 'active';
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'error', 'FACTOR_NOT_ACTIVE'); END IF;
  IF p_factor_type = 'sms' AND v_factor.phone_hash IS NULL THEN RETURN jsonb_build_object('ok', false, 'error', 'SMS_FACTOR_NO_PHONE'); END IF;

  SELECT custom_mfa_challenge_ttl_seconds, custom_mfa_max_resends, custom_mfa_max_attempts
  INTO v_settings FROM public.auth_security_settings WHERE id = 1 LIMIT 1;
  v_expires_at := now() + (COALESCE(v_settings.custom_mfa_challenge_ttl_seconds, 300) || ' seconds')::interval;

  UPDATE public.custom_mfa_challenges SET status = 'expired'
  WHERE user_id = p_user_id AND factor_id = v_factor.id AND status = 'pending';

  INSERT INTO public.custom_mfa_challenges (
    user_id, factor_id, factor_type, otp_hash, target_hash, expires_at, session_id, max_attempts, max_resends
  )
  VALUES (
    p_user_id, v_factor.id, p_factor_type, p_otp_hash, p_target_hash, v_expires_at, p_session_id,
    COALESCE(v_settings.custom_mfa_max_attempts, 5), COALESCE(v_settings.custom_mfa_max_resends, 3)
  )
  RETURNING id INTO v_challenge_id;

  RETURN jsonb_build_object('ok', true, 'challenge_id', v_challenge_id, 'expires_at', v_expires_at);
END;
$$;
REVOKE ALL ON FUNCTION public.create_custom_mfa_challenge_v2(uuid, text, uuid, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.create_custom_mfa_challenge_v2(uuid, text, uuid, text, text) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 3. Service RPC: verify challenge with domain-bound OTP hash
--    Caller must reconstruct the exact same HMAC input.
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.consume_custom_mfa_challenge_v2(
  p_user_id uuid,
  p_challenge_id uuid,
  p_otp_hash text,
  p_session_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_challenge public.custom_mfa_challenges%ROWTYPE;
  v_factor public.custom_mfa_factors%ROWTYPE;
  v_updated int;
BEGIN
  IF p_user_id IS NULL OR p_challenge_id IS NULL OR p_otp_hash IS NULL OR p_session_id IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;

  SELECT * INTO v_challenge FROM public.custom_mfa_challenges
  WHERE id = p_challenge_id AND user_id = p_user_id FOR UPDATE;

  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'error', 'CHALLENGE_NOT_FOUND'); END IF;
  IF v_challenge.session_id <> p_session_id THEN RETURN jsonb_build_object('ok', false, 'error', 'SESSION_MISMATCH'); END IF;
  IF v_challenge.status <> 'pending' THEN RETURN jsonb_build_object('ok', false, 'error', 'CHALLENGE_NOT_PENDING'); END IF;
  IF v_challenge.expires_at <= now() THEN
    UPDATE public.custom_mfa_challenges SET status = 'expired' WHERE id = p_challenge_id;
    RETURN jsonb_build_object('ok', false, 'error', 'CHALLENGE_EXPIRED');
  END IF;
  IF v_challenge.attempt_count >= v_challenge.max_attempts THEN
    UPDATE public.custom_mfa_challenges SET status = 'max_attempts' WHERE id = p_challenge_id;
    RETURN jsonb_build_object('ok', false, 'error', 'MAX_ATTEMPTS_EXCEEDED');
  END IF;

  UPDATE public.custom_mfa_challenges SET attempt_count = attempt_count + 1 WHERE id = p_challenge_id;

  IF v_challenge.otp_hash <> p_otp_hash THEN
    INSERT INTO public.security_audit_events (user_id, actor_user_id, event_type, event_category, severity, result)
    VALUES (p_user_id, p_user_id, 'mfa_otp_invalid', 'mfa', 'warning', 'failure');
    RETURN jsonb_build_object('ok', false, 'error', 'OTP_INVALID');
  END IF;

  UPDATE public.custom_mfa_challenges SET status = 'consumed', consumed_at = now()
  WHERE id = p_challenge_id AND status = 'pending' RETURNING 1 INTO v_updated;
  IF v_updated IS NULL THEN RETURN jsonb_build_object('ok', false, 'error', 'CHALLENGE_CONSUMED_RACE'); END IF;

  SELECT * INTO v_factor FROM public.custom_mfa_factors WHERE id = v_challenge.factor_id;
  IF NOT FOUND OR v_factor.factor_status <> 'active' THEN RETURN jsonb_build_object('ok', false, 'error', 'FACTOR_NOT_ACTIVE'); END IF;

  INSERT INTO public.security_audit_events (user_id, actor_user_id, event_type, event_category, severity, result)
  VALUES (p_user_id, p_user_id, 'mfa_otp_verified', 'mfa', 'info', 'success');

  RETURN public.issue_custom_mfa_grant(p_user_id, p_session_id, v_challenge.factor_type, 'custom_mfa');
END;
$$;
REVOKE ALL ON FUNCTION public.consume_custom_mfa_challenge_v2(uuid, uuid, text, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_custom_mfa_challenge_v2(uuid, uuid, text, uuid) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 4. Service RPC: regenerate recovery codes (revoke old, insert new hashes)
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.regenerate_custom_mfa_recovery_codes_v3(
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

  UPDATE public.custom_mfa_recovery_codes SET revoked_at = now()
  WHERE user_id = p_user_id AND used_at IS NULL AND revoked_at IS NULL;

  INSERT INTO public.custom_mfa_recovery_codes (user_id, code_hash)
  SELECT p_user_id, unnest(p_code_hashes);

  INSERT INTO public.security_audit_events (user_id, actor_user_id, event_type, event_category, severity, result)
  VALUES (p_user_id, p_user_id, 'recovery_codes_regenerated', 'recovery', 'warning', 'success');

  RETURN jsonb_build_object('ok', true, 'code_count', array_length(p_code_hashes, 1));
END;
$$;
REVOKE ALL ON FUNCTION public.regenerate_custom_mfa_recovery_codes_v3(uuid, text[]) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.regenerate_custom_mfa_recovery_codes_v3(uuid, text[]) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 5. Service RPC: enroll SMS factor from confirmed auth phone
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.enroll_sms_factor_from_auth_phone(
  p_user_id uuid,
  p_phone_hash text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_auth_phone text;
  v_auth_phone_confirmed boolean;
  v_factor_id uuid;
BEGIN
  IF p_user_id IS NULL OR p_phone_hash IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;

  SELECT phone, COALESCE(phone_confirmed_at IS NOT NULL, false)
  INTO v_auth_phone, v_auth_phone_confirmed
  FROM auth.users WHERE id = p_user_id LIMIT 1;

  IF NOT FOUND OR v_auth_phone IS NULL OR NOT v_auth_phone_confirmed THEN
    RETURN jsonb_build_object('ok', false, 'error', 'PHONE_NOT_CONFIRMED');
  END IF;

  SELECT id INTO v_factor_id FROM public.custom_mfa_factors
  WHERE user_id = p_user_id AND factor_type = 'sms' LIMIT 1;

  IF FOUND THEN
    UPDATE public.custom_mfa_factors SET phone_hash = p_phone_hash, factor_status = 'active', updated_at = now()
    WHERE id = v_factor_id;
  ELSE
    INSERT INTO public.custom_mfa_factors (user_id, factor_type, factor_status, phone_hash)
    VALUES (p_user_id, 'sms', 'active', p_phone_hash)
    RETURNING id INTO v_factor_id;
  END IF;

  RETURN jsonb_build_object('ok', true, 'factor_id', v_factor_id);
END;
$$;
REVOKE ALL ON FUNCTION public.enroll_sms_factor_from_auth_phone(uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.enroll_sms_factor_from_auth_phone(uuid, text) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 6. Revoke legacy insecure RPCs from authenticated/anon
-- ════════════════════════════════════════════════════════════════════════════
REVOKE ALL ON FUNCTION public.regenerate_custom_mfa_recovery_codes() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.create_bale_link_nonce() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.revoke_custom_mfa_grant(uuid) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.verify_custom_mfa_challenge(uuid, text, uuid) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.verify_custom_mfa_recovery(text, uuid) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.consume_bale_link_nonce(text, text) FROM PUBLIC, anon, authenticated;
