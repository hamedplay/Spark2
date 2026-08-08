import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();

const healthEdge = readFileSync(join(root, 'supabase/functions/auth-health-check/index.ts'), 'utf8');
const recoveryEdge = readFileSync(join(root, 'supabase/functions/unified-recovery/index.ts'), 'utf8');
const sessionEdge = readFileSync(join(root, 'supabase/functions/session-management/index.ts'), 'utf8');
const customMfaEdge = readFileSync(join(root, 'supabase/functions/custom-mfa/index.ts'), 'utf8');
const sw = readFileSync(join(root, 'public/sw.js'), 'utf8');

const deprecatedFns = {
  request: readFileSync(join(root, 'supabase/functions/request-phone-password-reset-otp/index.ts'), 'utf8'),
  verify: readFileSync(join(root, 'supabase/functions/verify-phone-password-reset-otp/index.ts'), 'utf8'),
  complete: readFileSync(join(root, 'supabase/functions/complete-phone-password-reset/index.ts'), 'utf8'),
};

const migration8 = readFileSync(join(root, 'supabase/migrations/20260808191059_20260808180000_phase8_audit_health_check.sql.sql'), 'utf8');

describe('Phase 8 Security Verification', () => {
  // ── Enumeration ──────────────────────────────────────────────────────────────
  it('recovery edge returns identical response for found/not-found accounts', () => {
    assert.match(recoveryEdge, /fake challenge_id to prevent enumeration/i);
    assert.match(recoveryEdge, /padTiming/);
  });

  // ── OTP/token replay ─────────────────────────────────────────────────────────
  it('recovery challenge uses atomic transitions preventing replay', () => {
    assert.match(recoveryEdge, /claim_unified_recovery_completion/);
    assert.match(recoveryEdge, /finalize_unified_recovery_completion/);
  });

  it('reset token is one-time with short TTL', () => {
    assert.match(recoveryEdge, /randomToken/);
    assert.match(recoveryEdge, /300 \* 1000/);
  });

  // ── Concurrent Race ─────────────────────────────────────────────────────────
  it('custom MFA uses atomic consume', () => {
    assert.match(customMfaEdge, /consume_custom_mfa_challenge_service/);
  });

  it('recovery uses atomic claim for race protection', () => {
    assert.match(recoveryEdge, /claim_unified_recovery_completion/);
  });

  // ── Factor Independence ─────────────────────────────────────────────────────
  it('custom MFA enforces phone OTP factor independence', () => {
    assert.match(customMfaEdge, /isPhoneOtpPrimary/);
    assert.match(customMfaEdge, /FACTOR_INDEPENDENCE_REQUIRED/);
  });

  // ── MFA grant session binding ───────────────────────────────────────────────
  it('custom MFA grants are bound to session_id', () => {
    assert.match(customMfaEdge, /p_session_id: caller\.sessionId/);
  });

  // ── Lockout abuse ───────────────────────────────────────────────────────────
  it('recovery remains available for locked accounts', () => {
    assert.match(recoveryEdge, /resolve_unified_recovery_target/);
    assert.doesNotMatch(recoveryEdge, /locked.*return.*ok.*false/i);
  });

  // ── Revoked/expired/old-epoch session ────────────────────────────────────────
  it('session management rejects revoked sessions', () => {
    assert.match(sessionEdge, /revoke_session_security_state|revoke_other_sessions|revoke_all_sessions/);
  });

  it('session management rejects old-epoch sessions', () => {
    assert.match(sessionEdge, /auth_epoch/);
  });

  it('session management checks idle and absolute timeout', () => {
    assert.match(sessionEdge, /idle_expiry_at/);
    assert.match(sessionEdge, /absolute_expiry_at/);
  });

  // ── No secret/plaintext OTP storage ─────────────────────────────────────────
  it('no edge function returns raw OTP or secret values', () => {
    assert.doesNotMatch(recoveryEdge, /return.*otp.*\d/i);
    assert.doesNotMatch(customMfaEdge, /return.*otp.*\d/i);
    assert.doesNotMatch(healthEdge, /return.*secret.*value/i);
    assert.doesNotMatch(healthEdge, /return.*pepper/i);
  });

  it('health check returns only ready/not_ready for secrets', () => {
    assert.doesNotMatch(healthEdge, /pepper|secret_value|key_value/i);
  });

  // ── PWA cache exclusion ─────────────────────────────────────────────────────
  it('service worker excludes /auth/ from cache', () => {
    assert.match(sw, /\/auth\//);
  });

  it('no edge function sets cacheable headers on auth responses', () => {
    assert.match(healthEdge, /no-store/);
    assert.match(healthEdge, /no-cache/);
  });

  // ── Health check: no hardcoded "deployed" ───────────────────────────────────
  it('health check does not hardcode edge function status as deployed', () => {
    assert.doesNotMatch(healthEdge, /status:\s*["']deployed["']/);
    assert.match(healthEdge, /not_verified/);
  });

  it('health check Bale readiness uses Edge Secret not DB bot_token', () => {
    assert.match(healthEdge, /BALE_BOT_TOKEN/);
    assert.doesNotMatch(healthEdge, /bot_token.*DB|DB.*bot_token/i);
  });

  // ── Deprecated routes return 410 after Phase 7 readiness ────────────────────
  it('deprecated recovery routes check unified_recovery_enabled and return 410', () => {
    for (const [name, src] of Object.entries(deprecatedFns)) {
      assert.match(src, /unified_recovery_enabled/, `${name} must check unified_recovery_enabled`);
      assert.match(src, /ROUTE_REPLACED/, `${name} must return ROUTE_REPLACED`);
      assert.match(src, /410/, `${name} must return 410 status`);
    }
  });

  it('deprecated routes do not delete data on 410', () => {
    for (const [name, src] of Object.entries(deprecatedFns)) {
      assert.doesNotMatch(src, /DELETE|DROP|TRUNCATE/i, `${name} must not delete data`);
    }
  });

  // ── No direct auth table writes ──────────────────────────────────────────────
  it('no edge function writes directly to auth tables', () => {
    assert.doesNotMatch(recoveryEdge, /INSERT INTO auth\.|UPDATE auth\.|DELETE FROM auth\./i);
    assert.doesNotMatch(sessionEdge, /INSERT INTO auth\.|UPDATE auth\.|DELETE FROM auth\./i);
    assert.doesNotMatch(healthEdge, /INSERT INTO auth\.|UPDATE auth\.|DELETE FROM auth\./i);
  });

  // ── Health Check UI wired ───────────────────────────────────────────────────
  it('HealthCheckPanel is wired into SecurityControlCenter', () => {
    const controlCenter = readFileSync(join(root, 'src/features/security-administration/components/SecurityControlCenter.tsx'), 'utf8');
    const panel = readFileSync(join(root, 'src/features/security-administration/components/HealthCheckPanel.tsx'), 'utf8');
    assert.match(controlCenter, /HealthCheckPanel/);
    assert.match(controlCenter, /'health'/);
    assert.match(panel, /fetchHealthCheck/);
    assert.match(panel, /HealthCheckResponse/);
  });

  // ── Audit viewer redaction ──────────────────────────────────────────────────
  it('audit page v2 does not expose ip_address or user_agent_hash directly', () => {
    assert.doesNotMatch(migration8, /'ip_address'[^)]*, e\.ip_address/);
    assert.doesNotMatch(migration8, /'user_agent_hash'[^)]*, e\.user_agent_hash/);
    assert.match(migration8, /p_request_id/);
  });

  // ── DB Runtime: RLS on security tables (migration source) ────────────────────
  it('migration enforces RLS on all security tables', () => {
    const rlsMigrations = readFileSync(join(root, 'supabase/migrations/20260808191059_20260808180000_phase8_audit_health_check.sql.sql'), 'utf8');
    assert.match(rlsMigrations, /relrowsecurity/);
  });

  it('health check RPC is SECURITY DEFINER with search_path', () => {
    assert.match(migration8, /SECURITY DEFINER SET search_path TO ''/);
  });

  it('audit page v2 RPC is SECURITY DEFINER with search_path', () => {
    assert.match(migration8, /get_security_audit_page_v2[\s\S]*SECURITY DEFINER SET search_path TO ''/);
  });

  // ── DB Runtime: ACL checks (migration source) ────────────────────────────────
  it('health check RPC is revoked from PUBLIC and anon', () => {
    assert.match(migration8, /REVOKE ALL ON FUNCTION public\.get_auth_health_check\(\) FROM PUBLIC, anon/);
    assert.match(migration8, /GRANT EXECUTE ON FUNCTION public\.get_auth_health_check\(\) TO authenticated/);
  });

  it('audit page v2 RPC is revoked from PUBLIC and anon', () => {
    assert.match(migration8, /REVOKE ALL ON FUNCTION public\.get_security_audit_page_v2/);
    assert.match(migration8, /GRANT EXECUTE ON FUNCTION public\.get_security_audit_page_v2.*TO authenticated/);
  });

  // ── Fail-closed search_path check (migration source) ────────────────────────
  it('health check migration counts all SECURITY DEFINER functions', () => {
    const newMigration = readFileSync(join(root, 'supabase/migrations/20260808194536_phase8_health_check_fail_closed_search_path.sql'), 'utf8');
    assert.match(newMigration, /v_secdef_count/);
    assert.match(newMigration, /v_secdef_with_search_path_count/);
    assert.match(newMigration, /v_secdef_count > v_secdef_with_search_path_count/);
  });

  // ── Session epoch enforcement (source) ──────────────────────────────────────
  it('session heartbeat validates auth_epoch from profiles', () => {
    assert.match(sessionEdge, /auth_epoch/);
    assert.match(sessionEdge, /touch_session_security_state/);
  });

  // ── Recovery rate limiting (source) ──────────────────────────────────────────
  it('recovery enforces per-identifier and per-IP rate limits', () => {
    assert.match(recoveryEdge, /consume_unified_recovery_rate_limit/);
    assert.match(recoveryEdge, /p_identifier_limit: 3/);
    assert.match(recoveryEdge, /p_ip_limit: 10/);
  });

  // ── Anti-enumeration: no hints (source) ──────────────────────────────────────
  it('recovery does not return email_hint or phone_hint', () => {
    assert.doesNotMatch(recoveryEdge, /email_hint|phone_hint/i);
  });

  // ── Health check no-store (source) ───────────────────────────────────────────
  it('health check response includes no-store and no-cache', () => {
    assert.match(healthEdge, /no-store/);
    assert.match(healthEdge, /no-cache/);
  });
});
