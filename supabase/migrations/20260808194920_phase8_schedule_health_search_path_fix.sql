-- Phase 8 Closure: harden the existing scheduler SECURITY DEFINER function
ALTER FUNCTION public.schedule_daily_report_check() SET search_path = '';
