-- Phase 8: Fix set_phone_password_recovery_test_mode search_path from 'public' to ''
-- SECURITY DEFINER functions must have empty search_path to prevent injection
CREATE OR REPLACE FUNCTION public.set_phone_password_recovery_test_mode(
  p_enabled boolean,
  p_test_phone text
)
RETURNS TABLE(success boolean, masked_phone text, error text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO ''
AS $function$
DECLARE
  v_caller_uid uuid;
  v_is_admin boolean := false;
  v_provider_id text := NULL;
  v_provider_active boolean := false;
  v_provider_ready boolean := false;
  v_template_ready boolean := false;
  v_secret_confirmed boolean := false;
  v_ttl_text text := '';
  v_ttl_seconds int := 0;
  v_public_enabled boolean := false;
  v_normalized_phone text;
  v_resolve_status text;
  v_resolve_user_id uuid;
  v_masked text;
BEGIN
  v_caller_uid := auth.uid();
  IF v_caller_uid IS NULL THEN
    RETURN QUERY SELECT false, NULL::text, 'NOT_AUTHENTICATED'::text;
    RETURN;
  END IF;

  SELECT COALESCE(is_admin, false) INTO v_is_admin
  FROM public.profiles WHERE user_id = v_caller_uid LIMIT 1;

  IF NOT v_is_admin THEN
    RETURN QUERY SELECT false, NULL::text, 'NOT_ADMIN'::text;
    RETURN;
  END IF;

  IF NOT p_enabled THEN
    UPDATE public.system_config SET value = 'false'
    WHERE section = 'security' AND key = 'phone_password_recovery_test_mode';
    UPDATE public.system_config SET value = ''
    WHERE section = 'security' AND key = 'phone_password_recovery_test_phone';
    RETURN QUERY SELECT true, NULL::text, NULL::text;
    RETURN;
  END IF;

  SELECT (value = 'true') INTO v_public_enabled
  FROM public.system_config WHERE section = 'security' AND key = 'phone_password_recovery_enabled' LIMIT 1;

  IF COALESCE(v_public_enabled, false) THEN
    RETURN QUERY SELECT false, NULL::text, 'PUBLIC_RECOVERY_ENABLED'::text;
    RETURN;
  END IF;

  SELECT value INTO v_provider_id
  FROM public.system_config WHERE section = 'sms' AND key = 'phone_login_sms_provider_id' LIMIT 1;

  IF v_provider_id IS NOT NULL THEN
    BEGIN
      SELECT is_active INTO v_provider_active
      FROM public.sms_providers WHERE id = v_provider_id::uuid AND is_active = true LIMIT 1;
    EXCEPTION WHEN OTHERS THEN v_provider_active := false; END;
  END IF;
  v_provider_ready := v_provider_id IS NOT NULL AND COALESCE(v_provider_active, false);

  IF NOT v_provider_ready THEN
    RETURN QUERY SELECT false, NULL::text, 'PROVIDER_NOT_READY'::text;
    RETURN;
  END IF;

  BEGIN
    SELECT EXISTS(
      SELECT 1 FROM public.notification_templates
      WHERE category = 'auth' AND event_type = 'password_reset_otp' AND audience = 'all' AND is_active = true
    ) INTO v_template_ready;
  EXCEPTION WHEN OTHERS THEN v_template_ready := false; END;

  IF NOT v_template_ready THEN
    RETURN QUERY SELECT false, NULL::text, 'TEMPLATE_NOT_READY'::text;
    RETURN;
  END IF;

  SELECT (value = 'true') INTO v_secret_confirmed
  FROM public.system_config WHERE section = 'security' AND key = 'phone_password_recovery_secret_operator_confirmed' LIMIT 1;

  IF NOT COALESCE(v_secret_confirmed, false) THEN
    RETURN QUERY SELECT false, NULL::text, 'SECRET_NOT_CONFIRMED'::text;
    RETURN;
  END IF;

  SELECT value INTO v_ttl_text
  FROM public.system_config WHERE section = 'security' AND key = 'phone_password_recovery_otp_ttl_seconds' LIMIT 1;

  BEGIN
    v_ttl_seconds := v_ttl_text::integer;
  EXCEPTION WHEN OTHERS THEN v_ttl_seconds := 0; END;

  IF v_ttl_seconds < 60 OR v_ttl_seconds > 86400 THEN
    RETURN QUERY SELECT false, NULL::text, 'INVALID_TTL'::text;
    RETURN;
  END IF;

  v_normalized_phone := public.normalize_iran_phone_sql(p_test_phone);
  IF v_normalized_phone !~ '^989\d{9}$' THEN
    RETURN QUERY SELECT false, NULL::text, 'INVALID_PHONE'::text;
    RETURN;
  END IF;

  SELECT status, user_id INTO v_resolve_status, v_resolve_user_id
  FROM public.resolve_phone_password_reset_target_detailed(v_normalized_phone);

  IF v_resolve_status IS NULL OR v_resolve_status <> 'MATCHED' THEN
    RETURN QUERY SELECT false, NULL::text, COALESCE(v_resolve_status, 'PHONE_NOT_UNIQUE')::text;
    RETURN;
  END IF;

  UPDATE public.system_config SET value = 'true'
  WHERE section = 'security' AND key = 'phone_password_recovery_test_mode';
  UPDATE public.system_config SET value = p_test_phone
  WHERE section = 'security' AND key = 'phone_password_recovery_test_phone';

  v_masked := substr(v_normalized_phone, 1, 5) || '****' || substr(v_normalized_phone, length(v_normalized_phone) - 1);

  RETURN QUERY SELECT true, v_masked, NULL::text;
END;
$function$;
REVOKE ALL ON FUNCTION public.set_phone_password_recovery_test_mode(boolean, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.set_phone_password_recovery_test_mode(boolean, text) TO service_role;
ALTER FUNCTION public.set_phone_password_recovery_test_mode(boolean, text) OWNER TO postgres;
