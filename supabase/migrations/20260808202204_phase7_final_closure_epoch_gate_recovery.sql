-- Phase 7 Final Closure: epoch wiring, TOTP step-up check, fail-closed gate, recovery finalization repair

-- ════════════════════════════════════════════════════════════════════════════
-- 1. Add repair_state and finalization_succeeded to unified_recovery_challenges
-- ════════════════════════════════════════════════════════════════════════════
ALTER TABLE public.unified_recovery_challenges
  ADD COLUMN IF NOT EXISTS repair_state text DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS finalization_succeeded boolean DEFAULT NULL;

-- ════════════════════════════════════════════════════════════════════════════
-- 2. has_recent_totp_stepup_grant: check for active native TOTP step-up grant
--    Custom MFA grants do NOT count as admin step-up.
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.has_recent_totp_stepup_grant(
  p_user_id uuid,
  p_session_id uuid
)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_count int;
BEGIN
  IF p_user_id IS NULL OR p_session_id IS NULL THEN
    RETURN false;
  END IF;

  SELECT count(*) INTO v_count
  FROM public.session_security_grants
  WHERE user_id = p_user_id
    AND session_id = p_session_id
    AND grant_type = 'mfa_stepup'
    AND factor_type = 'totp'
    AND consumed_at IS NULL
    AND expires_at > now();

  RETURN v_count > 0;
END;
$$;
REVOKE ALL ON FUNCTION public.has_recent_totp_stepup_grant(uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.has_recent_totp_stepup_grant(uuid, uuid) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 3. get_my_auth_access_state_v3: fail-closed when session management enabled
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.get_my_auth_access_state_v3()
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_jwt jsonb := auth.jwt();
  v_session_id uuid;
  v_base_result jsonb;
  v_access_level text;
  v_profile record;
  v_session_state record;
  v_settings record;
BEGIN
  IF v_uid IS NULL THEN
    RETURN jsonb_build_object('has_session', false, 'access_level', 'BLOCKED', 'reason_code', 'NO_AUTH', 'next_step', 'login',
      'user_id', null, 'session_id', null, 'account_status', null, 'profile_completion_status', null,
      'mfa_required', false, 'has_verified_totp', false, 'current_aal', null);
  END IF;

  v_base_result := private.evaluate_current_auth_access();
  v_access_level := v_base_result ->> 'access_level';

  IF v_access_level = 'BLOCKED' THEN
    RETURN v_base_result;
  END IF;

  BEGIN
    v_session_id := NULLIF(v_jwt ->> 'session_id', '')::uuid;
  EXCEPTION WHEN others THEN
    v_session_id := NULL;
  END;

  SELECT auth_epoch, account_status, locked_until INTO v_profile
  FROM public.profiles WHERE user_id = v_uid LIMIT 1;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('has_session', false, 'access_level', 'BLOCKED', 'reason_code', 'PROFILE_MISSING', 'next_step', 'login',
      'user_id', v_uid::text, 'session_id', null, 'account_status', null, 'profile_completion_status', null,
      'mfa_required', false, 'has_verified_totp', false, 'current_aal', null);
  END IF;

  IF v_profile.locked_until IS NOT NULL AND v_profile.locked_until > now() THEN
    RETURN jsonb_build_object('has_session', true, 'access_level', 'BLOCKED', 'reason_code', 'ACCOUNT_LOCKED', 'next_step', 'login',
      'user_id', v_uid::text, 'session_id', v_session_id::text, 'account_status', v_profile.account_status,
      'profile_completion_status', v_base_result ->> 'profile_completion_status',
      'mfa_required', false, 'has_verified_totp', (v_base_result ->> 'has_verified_totp')::boolean, 'current_aal', v_base_result ->> 'current_aal');
  END IF;

  SELECT session_management_enabled INTO v_settings FROM public.auth_security_settings WHERE id = 1 LIMIT 1;

  IF COALESCE(v_settings.session_management_enabled, false) AND v_session_id IS NOT NULL THEN
    SELECT revoked_at, idle_expiry_at, absolute_expiry_at, auth_epoch INTO v_session_state
    FROM public.session_security_state
    WHERE session_id = v_session_id AND user_id = v_uid LIMIT 1;

    IF NOT FOUND THEN
      RETURN jsonb_build_object('has_session', true, 'access_level', 'BLOCKED', 'reason_code', 'SESSION_NOT_REGISTERED', 'next_step', 'login',
        'user_id', v_uid::text, 'session_id', v_session_id::text, 'account_status', v_profile.account_status,
        'profile_completion_status', v_base_result ->> 'profile_completion_status',
        'mfa_required', false, 'has_verified_totp', false, 'current_aal', null);
    END IF;

    IF v_session_state.revoked_at IS NOT NULL THEN
      RETURN jsonb_build_object('has_session', true, 'access_level', 'BLOCKED', 'reason_code', 'SESSION_REVOKED', 'next_step', 'login',
        'user_id', v_uid::text, 'session_id', v_session_id::text, 'account_status', v_profile.account_status,
        'profile_completion_status', v_base_result ->> 'profile_completion_status',
        'mfa_required', false, 'has_verified_totp', false, 'current_aal', null);
    END IF;

    IF v_session_state.auth_epoch IS NOT NULL AND v_profile.auth_epoch IS NOT NULL
       AND v_session_state.auth_epoch <> v_profile.auth_epoch THEN
      RETURN jsonb_build_object('has_session', true, 'access_level', 'BLOCKED', 'reason_code', 'EPOCH_MISMATCH', 'next_step', 'login',
        'user_id', v_uid::text, 'session_id', v_session_id::text, 'account_status', v_profile.account_status,
        'profile_completion_status', v_base_result ->> 'profile_completion_status',
        'mfa_required', false, 'has_verified_totp', false, 'current_aal', null);
    END IF;

    IF v_session_state.idle_expiry_at IS NOT NULL AND v_session_state.idle_expiry_at <= now() THEN
      RETURN jsonb_build_object('has_session', true, 'access_level', 'BLOCKED', 'reason_code', 'SESSION_EXPIRED', 'next_step', 'login',
        'user_id', v_uid::text, 'session_id', v_session_id::text, 'account_status', v_profile.account_status,
        'profile_completion_status', v_base_result ->> 'profile_completion_status',
        'mfa_required', false, 'has_verified_totp', false, 'current_aal', null);
    END IF;

    IF v_session_state.absolute_expiry_at IS NOT NULL AND v_session_state.absolute_expiry_at <= now() THEN
      RETURN jsonb_build_object('has_session', true, 'access_level', 'BLOCKED', 'reason_code', 'SESSION_EXPIRED', 'next_step', 'login',
        'user_id', v_uid::text, 'session_id', v_session_id::text, 'account_status', v_profile.account_status,
        'profile_completion_status', v_base_result ->> 'profile_completion_status',
        'mfa_required', false, 'has_verified_totp', false, 'current_aal', null);
    END IF;
  END IF;

  RETURN v_base_result;
END;
$$;
REVOKE ALL ON FUNCTION public.get_my_auth_access_state_v3() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_my_auth_access_state_v3() TO authenticated;

-- ════════════════════════════════════════════════════════════════════════════
-- 4. register_session_security_state_v2: reads real auth_epoch from profiles
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.register_session_security_state_v2(
  p_session_id uuid,
  p_user_id uuid,
  p_idle_timeout_minutes int,
  p_absolute_lifetime_minutes int,
  p_device_summary text,
  p_ip_hash text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_epoch int;
  v_idle_expiry timestamptz;
  v_absolute_expiry timestamptz;
  v_max_sessions int;
  v_active_count int;
BEGIN
  IF p_session_id IS NULL OR p_user_id IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;

  SELECT COALESCE(auth_epoch, 1) INTO v_epoch
  FROM public.profiles WHERE user_id = p_user_id LIMIT 1;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'PROFILE_NOT_FOUND');
  END IF;

  v_idle_expiry := now() + (COALESCE(p_idle_timeout_minutes, 480) || ' minutes')::interval;
  v_absolute_expiry := now() + (COALESCE(p_absolute_lifetime_minutes, 1440) || ' minutes')::interval;

  SELECT max_active_sessions INTO v_max_sessions FROM public.auth_security_settings WHERE id = 1 LIMIT 1;
  v_max_sessions := COALESCE(v_max_sessions, 5);
  SELECT count(*) INTO v_active_count FROM public.session_security_state
  WHERE user_id = p_user_id AND revoked_at IS NULL AND absolute_expiry_at > now();

  IF v_active_count >= v_max_sessions THEN
    UPDATE public.session_security_state SET revoked_at = now(), revoke_reason = 'max_sessions_exceeded'
    WHERE id = (
      SELECT id FROM public.session_security_state
      WHERE user_id = p_user_id AND revoked_at IS NULL
      ORDER BY created_at ASC LIMIT 1
    );
  END IF;

  INSERT INTO public.session_security_state (
    session_id, user_id, auth_epoch, idle_expiry_at, absolute_expiry_at, device_summary, ip_hash
  )
  VALUES (
    p_session_id, p_user_id, v_epoch, v_idle_expiry, v_absolute_expiry, p_device_summary, p_ip_hash
  )
  ON CONFLICT (session_id) DO UPDATE SET
    auth_epoch = EXCLUDED.auth_epoch,
    last_activity_at = now(),
    idle_expiry_at = EXCLUDED.idle_expiry_at,
    absolute_expiry_at = EXCLUDED.absolute_expiry_at,
    device_summary = EXCLUDED.device_summary,
    ip_hash = EXCLUDED.ip_hash,
    revoked_at = NULL,
    revoke_reason = NULL;

  RETURN jsonb_build_object('ok', true, 'auth_epoch', v_epoch);
END;
$$;
REVOKE ALL ON FUNCTION public.register_session_security_state_v2(uuid, uuid, int, int, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.register_session_security_state_v2(uuid, uuid, int, int, text, text) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 5. finalize_unified_recovery_completion_v2: idempotent, durable repair state
--    Returns ok:false if finalization fails; caller must NOT return ok:true
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.finalize_unified_recovery_completion_v2(
  p_challenge_id uuid,
  p_claim_id uuid,
  p_success boolean
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_challenge public.unified_recovery_challenges%ROWTYPE;
  v_user_id uuid;
  v_updated int;
  v_new_epoch int;
BEGIN
  IF p_challenge_id IS NULL OR p_claim_id IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;

  SELECT * INTO v_challenge FROM public.unified_recovery_challenges WHERE id = p_challenge_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'error', 'CHALLENGE_NOT_FOUND'); END IF;

  -- Idempotent: if already finalized, return current state
  IF v_challenge.consumed_at IS NOT NULL AND v_challenge.finalization_succeeded = true THEN
    RETURN jsonb_build_object('ok', true, 'already_finalized', true, 'finalization_succeeded', true);
  END IF;

  IF NOT p_success THEN
    UPDATE public.unified_recovery_challenges
    SET status = 'RESET_TOKEN_ISSUED', processing_claim_id = NULL, processing_expires_at = NULL,
        updated_at = now(), repair_state = 'RESET_SECURITY_FINALIZATION_FAILED', finalization_succeeded = false
    WHERE id = p_challenge_id AND status = 'PROCESSING' AND processing_claim_id = p_claim_id;

    INSERT INTO public.security_audit_events (user_id, event_type, event_category, severity, result, metadata)
    VALUES (v_challenge.user_id, 'recovery_finalization_failed', 'recovery', 'error', 'failure',
      jsonb_build_object('challenge_id', p_challenge_id, 'claim_id', p_claim_id, 'reason', 'password_changed_finalization_failed'));

    RETURN jsonb_build_object('ok', false, 'error', 'RESET_SECURITY_FINALIZATION_FAILED');
  END IF;

  -- Success: verify claim ownership
  IF v_challenge.status <> 'PROCESSING' OR v_challenge.processing_claim_id IS NULL OR v_challenge.processing_claim_id <> p_claim_id THEN
    RETURN jsonb_build_object('ok', false, 'error', 'CLAIM_MISMATCH');
  END IF;

  UPDATE public.unified_recovery_challenges
  SET status = 'CONSUMED', consumed_at = now(), processing_claim_id = NULL, processing_expires_at = NULL,
      updated_at = now(), repair_state = 'COMPLETED', finalization_succeeded = true
  WHERE id = p_challenge_id AND status = 'PROCESSING' RETURNING 1 INTO v_updated;

  IF v_updated IS NULL THEN RETURN jsonb_build_object('ok', false, 'error', 'CONSUME_RACE'); END IF;

  v_user_id := v_challenge.user_id;

  SELECT COALESCE(auth_epoch, 1) + 1 INTO v_new_epoch
  FROM public.profiles WHERE user_id = v_user_id LIMIT 1;

  UPDATE public.profiles SET auth_epoch = v_new_epoch, locked_until = NULL WHERE user_id = v_user_id;

  UPDATE public.custom_mfa_grants SET revoked_at = now()
  WHERE user_id = v_user_id AND revoked_at IS NULL;

  UPDATE public.session_security_grants SET consumed_at = now()
  WHERE user_id = v_user_id AND consumed_at IS NULL;

  UPDATE public.session_security_state SET revoked_at = now(), revoke_reason = 'password_reset'
  WHERE user_id = v_user_id AND revoked_at IS NULL;

  INSERT INTO public.security_audit_events (user_id, event_type, event_category, severity, result, metadata)
  VALUES (v_user_id, 'recovery_finalization_succeeded', 'recovery', 'info', 'success',
    jsonb_build_object('challenge_id', p_challenge_id, 'claim_id', p_claim_id, 'new_epoch', v_new_epoch));

  RETURN jsonb_build_object('ok', true, 'new_epoch', v_new_epoch);
END;
$$;
REVOKE ALL ON FUNCTION public.finalize_unified_recovery_completion_v2(uuid, uuid, boolean) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.finalize_unified_recovery_completion_v2(uuid, uuid, boolean) TO service_role;
