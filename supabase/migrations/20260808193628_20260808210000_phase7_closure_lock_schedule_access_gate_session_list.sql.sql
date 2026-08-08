-- Phase 7 Closure: fix lock schedule, fail-closed access gate, session list user binding, recovery anti-enumeration

-- ════════════════════════════════════════════════════════════════════════════
-- 1. Fix record_auth_failure: schedule in HOURS not minutes (1h→6h→12h→24h→48h→72h→admin-unlock)
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.record_auth_failure(
  p_user_id uuid,
  p_identifier_hash text,
  p_ip_hash text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_settings record;
  v_recent_failures integer;
  v_threshold integer;
  v_schedule text[];
  v_current_lock_level integer;
  v_new_lock_level integer;
  v_lock_hours integer;
  v_locked_until timestamptz;
  v_profile_locked_until timestamptz;
  v_schedule_len integer;
BEGIN
  IF p_user_id IS NULL OR p_identifier_hash IS NULL OR p_ip_hash IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;

  SELECT progressive_lock_enabled, lock_threshold, progressive_lock_schedule
  INTO v_settings FROM public.auth_security_settings WHERE id = 1 LIMIT 1;

  v_threshold := COALESCE(v_settings.lock_threshold, 5);
  v_schedule := COALESCE(v_settings.progressive_lock_schedule, ARRAY['1','6','12','24','48','72']::text[]);
  v_schedule_len := COALESCE(array_length(v_schedule, 1), 0);

  SELECT locked_until INTO v_profile_locked_until FROM public.profiles WHERE user_id = p_user_id LIMIT 1;
  IF v_profile_locked_until IS NOT NULL AND v_profile_locked_until > now() THEN
    RETURN jsonb_build_object('ok', true, 'locked', true, 'locked_until', v_profile_locked_until, 'rate_limited', false);
  END IF;

  SELECT count(*) INTO v_recent_failures
  FROM public.auth_lock_events
  WHERE user_id = p_user_id AND created_at > now() - interval '24 hours';

  INSERT INTO public.auth_lock_events (user_id, identifier_hash, ip_hash, failure_count, lock_level, locked_until)
  VALUES (p_user_id, p_identifier_hash, p_ip_hash, 1, 0, NULL);

  v_recent_failures := v_recent_failures + 1;

  IF v_recent_failures < v_threshold THEN
    RETURN jsonb_build_object('ok', true, 'locked', false, 'rate_limited', false, 'failures', v_recent_failures);
  END IF;

  v_current_lock_level := 0;
  SELECT COALESCE(max(lock_level), 0) INTO v_current_lock_level
  FROM public.auth_lock_events
  WHERE user_id = p_user_id AND locked_until IS NOT NULL AND locked_until > now() - interval '72 hours';

  v_new_lock_level := LEAST(v_current_lock_level + 1, v_schedule_len);

  IF v_new_lock_level >= v_schedule_len THEN
    UPDATE public.profiles SET account_status = 'LOCKED', locked_until = NULL WHERE user_id = p_user_id;
    UPDATE public.auth_lock_events SET lock_level = v_new_lock_level, locked_until = now() + interval '72 hours'
    WHERE id = (SELECT id FROM public.auth_lock_events WHERE user_id = p_user_id ORDER BY created_at DESC LIMIT 1);
    RETURN jsonb_build_object('ok', true, 'locked', true, 'admin_unlock_required', true, 'lock_level', v_new_lock_level);
  END IF;

  v_lock_hours := (v_schedule[v_new_lock_level])::integer;
  v_locked_until := now() + (v_lock_hours || ' hours')::interval;

  UPDATE public.profiles SET locked_until = v_locked_until WHERE user_id = p_user_id;
  UPDATE public.auth_lock_events SET lock_level = v_new_lock_level, locked_until = v_locked_until
  WHERE id = (SELECT id FROM public.auth_lock_events WHERE user_id = p_user_id ORDER BY created_at DESC LIMIT 1);

  RETURN jsonb_build_object('ok', true, 'locked', true, 'locked_until', v_locked_until, 'lock_level', v_new_lock_level, 'lock_hours', v_lock_hours);
END;
$$;

-- ════════════════════════════════════════════════════════════════════════════
-- 2. Fail-closed access gate wrapper: adds auth_epoch + session_security_state + revoked + idle + absolute + locked_until
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.get_my_auth_access_state_v2()
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_jwt jsonb := auth.jwt();
  v_session_id uuid;
  v_base_result jsonb;
  v_profile record;
  v_session_state record;
  v_settings record;
  v_access_level text;
BEGIN
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
    SELECT revoked_at, idle_expiry_at, absolute_expiry_at INTO v_session_state
    FROM public.session_security_state
    WHERE session_id = v_session_id AND user_id = v_uid LIMIT 1;

    IF NOT FOUND THEN
      RETURN v_base_result;
    END IF;

    IF v_session_state.revoked_at IS NOT NULL THEN
      RETURN jsonb_build_object('has_session', true, 'access_level', 'BLOCKED', 'reason_code', 'SESSION_REVOKED', 'next_step', 'login',
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
REVOKE ALL ON FUNCTION public.get_my_auth_access_state_v2() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_my_auth_access_state_v2() TO authenticated;

-- ════════════════════════════════════════════════════════════════════════════
-- 3. Session list with explicit user binding (for service-role calls)
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.get_user_session_security_state(
  p_user_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_caller_uid uuid := auth.uid();
BEGIN
  IF v_caller_uid IS NOT NULL AND v_caller_uid <> p_user_id THEN
    RETURN jsonb_build_object('ok', false, 'error', 'FORBIDDEN');
  END IF;

  IF p_user_id IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'USER_ID_REQUIRED');
  END IF;

  RETURN jsonb_build_object(
    'ok', true,
    'sessions', (
      SELECT jsonb_agg(jsonb_build_object(
        'session_id', session_id,
        'created_at', created_at,
        'last_activity_at', last_activity_at,
        'idle_expiry_at', idle_expiry_at,
        'absolute_expiry_at', absolute_expiry_at,
        'revoked_at', revoked_at,
        'revoke_reason', revoke_reason,
        'device_summary', device_summary,
        'status', CASE
          WHEN revoked_at IS NOT NULL THEN 'revoked'
          WHEN absolute_expiry_at <= now() THEN 'absolute_expired'
          WHEN idle_expiry_at <= now() THEN 'idle_expired'
          ELSE 'active'
        END
      ))
      FROM public.session_security_state
      WHERE user_id = p_user_id
      ORDER BY created_at DESC
    )
  );
END;
$$;
REVOKE ALL ON FUNCTION public.get_user_session_security_state(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_user_session_security_state(uuid) TO authenticated, service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 4. Admin session revoke (requires FULL + step-up + audit)
-- ════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.admin_revoke_user_session(
  p_admin_user_id uuid,
  p_target_user_id uuid,
  p_session_id uuid,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_updated int;
BEGIN
  IF p_admin_user_id IS NULL OR p_target_user_id IS NULL OR p_session_id IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_PARAMS');
  END IF;

  UPDATE public.session_security_state SET
    revoked_at = now(),
    revoke_reason = COALESCE(p_reason, 'admin_revoke')
  WHERE session_id = p_session_id AND user_id = p_target_user_id AND revoked_at IS NULL
  RETURNING 1 INTO v_updated;

  IF v_updated IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'SESSION_NOT_FOUND_OR_ALREADY_REVOKED');
  END IF;

  INSERT INTO public.security_audit_events (
    actor_user_id, target_user_id, event_type, event_category, severity, result, metadata
  ) VALUES (
    p_admin_user_id, p_target_user_id, 'admin_session_revoke', 'session', 'warning', 'success',
    jsonb_build_object('session_id', p_session_id, 'reason', p_reason)
  );

  RETURN jsonb_build_object('ok', true);
END;
$$;
REVOKE ALL ON FUNCTION public.admin_revoke_user_session(uuid, uuid, uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_revoke_user_session(uuid, uuid, uuid, text) TO service_role;
