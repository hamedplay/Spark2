-- Phase 8 Closure: detect actual search_path settings and fail health readiness closed
-- No data deletion, no table/column changes, no RLS policy changes

CREATE OR REPLACE FUNCTION public.get_auth_health_check()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $$
DECLARE
  v_settings record;
  v_missing_tables text[] := '{}';
  v_missing_rpcs text[] := '{}';
  v_rls_ok boolean := true;
  v_search_path_ok boolean := true;
  v_secdef_count integer := 0;
  v_secdef_with_search_path_count integer := 0;
  v_tbl text;
  v_rpc text;
  v_tables text[] := ARRAY[
    'auth_security_settings','profiles','audit_log','security_audit_events',
    'custom_mfa_factors','custom_mfa_challenges','custom_mfa_grants','custom_mfa_recovery_codes',
    'unified_recovery_challenges','auth_lock_events','session_security_state',
    'unified_recovery_rate_limit','phone_password_reset_challenges'
  ];
  v_rpcs text[] := ARRAY[
    'get_my_auth_access_state','get_public_auth_config','get_public_login_methods',
    'get_security_audit_page','hmac_with_pepper','resolve_unified_recovery_target',
    'create_unified_recovery_challenge','verify_unified_recovery_challenge',
    'claim_unified_recovery_completion','finalize_unified_recovery_completion',
    'record_auth_failure','check_account_lock_status',
    'register_session_security_state','touch_session_security_state',
    'revoke_session_security_state','revoke_other_sessions','revoke_all_sessions',
    'get_my_session_security_state','consume_unified_recovery_rate_limit',
    'admin_unlock_account'
  ];
BEGIN
  FOREACH v_tbl IN ARRAY v_tables LOOP
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = v_tbl) THEN
      v_missing_tables := array_append(v_missing_tables, v_tbl);
    END IF;
  END LOOP;

  FOREACH v_rpc IN ARRAY v_rpcs LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid
      WHERE n.nspname = 'public' AND p.proname = v_rpc
    ) THEN
      v_missing_rpcs := array_append(v_missing_rpcs, v_rpc);
    END IF;
  END LOOP;

  FOREACH v_tbl IN ARRAY v_tables LOOP
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = v_tbl) THEN
      IF NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = 'public' AND c.relname = v_tbl AND c.relrowsecurity = true
      ) THEN
        v_rls_ok := false;
      END IF;
    ELSE
      v_rls_ok := false;
    END IF;
  END LOOP;

  SELECT count(*) INTO v_secdef_count
  FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid
  WHERE n.nspname = 'public' AND p.prosecdef = true;

  SELECT count(*) INTO v_secdef_with_search_path_count
  FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid
  WHERE n.nspname = 'public'
    AND p.prosecdef = true
    AND EXISTS (
      SELECT 1 FROM unnest(COALESCE(p.proconfig, ARRAY[]::text[])) AS config
      WHERE config LIKE 'search_path=%'
    );

  IF v_secdef_count <> v_secdef_with_search_path_count THEN
    v_search_path_ok := false;
  END IF;

  SELECT * INTO v_settings FROM public.auth_security_settings WHERE id = 1 LIMIT 1;

  RETURN jsonb_build_object(
    'ok', array_length(v_missing_tables, 1) IS NULL
      AND array_length(v_missing_rpcs, 1) IS NULL
      AND v_rls_ok AND v_search_path_ok,
    'timestamp', now()::text,
    'tables', jsonb_build_object('required', to_jsonb(v_tables), 'missing', to_jsonb(v_missing_tables), 'all_present', array_length(v_missing_tables, 1) IS NULL),
    'rpcs', jsonb_build_object('required', to_jsonb(v_rpcs), 'missing', to_jsonb(v_missing_rpcs), 'all_present', array_length(v_missing_rpcs, 1) IS NULL),
    'rls', jsonb_build_object('all_enabled', v_rls_ok),
    'security_definer', jsonb_build_object('search_path_empty', v_search_path_ok, 'total_count', v_secdef_count, 'with_search_path_count', v_secdef_with_search_path_count),
    'settings', jsonb_build_object('unified_recovery_enabled', v_settings.unified_recovery_enabled, 'progressive_lock_enabled', v_settings.progressive_lock_enabled, 'session_management_enabled', v_settings.session_management_enabled, 'custom_mfa_enabled', v_settings.custom_mfa_enabled, 'recovery_enabled', v_settings.recovery_enabled, 'mfa_policy', v_settings.mfa_policy, 'username_login', v_settings.username_login, 'email_login', v_settings.email_login, 'phone_login', v_settings.phone_login),
    'secrets', jsonb_build_object('mfa_pepper', CASE WHEN current_setting('app.mfa_pepper', true) IS NOT NULL AND length(current_setting('app.mfa_pepper', true)) > 0 THEN 'ready' ELSE 'not_ready' END, 'auth_pepper', CASE WHEN current_setting('app.auth_pepper', true) IS NOT NULL AND length(current_setting('app.auth_pepper', true)) > 0 THEN 'ready' ELSE 'not_ready' END, 'mfa_encryption_key', CASE WHEN current_setting('app.mfa_encryption_key', true) IS NOT NULL AND length(current_setting('app.mfa_encryption_key', true)) > 0 THEN 'ready' ELSE 'not_ready' END),
    'deprecated_routes', jsonb_build_array(
      jsonb_build_object('route', 'request-phone-password-reset-otp', 'status', CASE WHEN COALESCE(v_settings.unified_recovery_enabled, false) THEN '410_ROUTE_REPLACED' ELSE 'replaced_by_unified_recovery' END, 'action', '410_after_cutover'),
      jsonb_build_object('route', 'verify-phone-password-reset-otp', 'status', CASE WHEN COALESCE(v_settings.unified_recovery_enabled, false) THEN '410_ROUTE_REPLACED' ELSE 'replaced_by_unified_recovery' END, 'action', '410_after_cutover'),
      jsonb_build_object('route', 'complete-phone-password-reset', 'status', CASE WHEN COALESCE(v_settings.unified_recovery_enabled, false) THEN '410_ROUTE_REPLACED' ELSE 'replaced_by_unified_recovery' END, 'action', '410_after_cutover')
    )
  );
END;
$$;

REVOKE ALL ON FUNCTION public.get_auth_health_check() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_auth_health_check() TO authenticated;
