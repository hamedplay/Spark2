-- Phase 8 Final Closure: ACL hardening for security RPCs

-- ════════════════════════════════════════════════════════════════════════════
-- 1. get_auth_health_check: service_role only (edge function does its own auth)
-- ════════════════════════════════════════════════════════════════════════════
REVOKE EXECUTE ON FUNCTION public.get_auth_health_check() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_auth_health_check() TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 2. get_user_session_security_state: service_role only (edge function passes
--    explicit p_user_id; authenticated must not read arbitrary user sessions)
-- ════════════════════════════════════════════════════════════════════════════
REVOKE EXECUTE ON FUNCTION public.get_user_session_security_state(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_user_session_security_state(uuid) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 3. set_phone_password_recovery_config: service_role only (admin config RPC)
-- ════════════════════════════════════════════════════════════════════════════
REVOKE EXECUTE ON FUNCTION public.set_phone_password_recovery_config(boolean) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.set_phone_password_recovery_config(boolean) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 4. set_phone_password_recovery_test_mode: service_role only + fix search_path
-- ════════════════════════════════════════════════════════════════════════════
REVOKE EXECUTE ON FUNCTION public.set_phone_password_recovery_test_mode(boolean, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.set_phone_password_recovery_test_mode(boolean, text) TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 5. get_custom_mfa_state: service_role only (edge function does its own auth)
-- ════════════════════════════════════════════════════════════════════════════
REVOKE EXECUTE ON FUNCTION public.get_custom_mfa_state() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_custom_mfa_state() TO service_role;

-- ════════════════════════════════════════════════════════════════════════════
-- 6. get_custom_mfa_readiness: service_role only (edge function does its own auth)
-- ════════════════════════════════════════════════════════════════════════════
REVOKE EXECUTE ON FUNCTION public.get_custom_mfa_readiness() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_custom_mfa_readiness() TO service_role;
