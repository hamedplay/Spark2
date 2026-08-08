import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();
const passwordLogin = readFileSync(join(root, 'supabase/functions/password-login/index.ts'), 'utf8');
const recovery = readFileSync(join(root, 'supabase/functions/unified-recovery/index.ts'), 'utf8');
const sessionMgmt = readFileSync(join(root, 'supabase/functions/session-management/index.ts'), 'utf8');
const migration = readFileSync(join(root, 'supabase/migrations/20260808193628_20260808210000_phase7_closure_lock_schedule_access_gate_session_list.sql.sql'), 'utf8');

describe('Phase 7 Closure — Lock timing', () => {
  it('record_auth_failure schedule uses hours not minutes', () => {
    assert.match(migration, /v_lock_hours.*integer/);
    assert.match(migration, /v_lock_hours.*\|\| ' hours'/);
    assert.doesNotMatch(migration, /v_lock_minutes/);
    assert.doesNotMatch(migration, /\|\| ' minutes'/);
  });

  it('schedule is 1h→6h→12h→24h→48h→72h then admin-unlock', () => {
    assert.match(migration, /ARRAY\['1','6','12','24','48','72'\]/);
    assert.match(migration, /admin_unlock_required/);
  });
});

describe('Phase 7 Closure — Login wiring', () => {
  it('password-login calls record_auth_failure on credential failure', () => {
    assert.match(passwordLogin, /record_auth_failure/);
  });

  it('password-login calls register_session_security_state on success', () => {
    assert.match(passwordLogin, /register_session_security_state/);
    assert.match(passwordLogin, /session_management_enabled/);
  });

  it('failure recording is rate-limit-safe (wrapped in try/catch)', () => {
    assert.match(passwordLogin, /try\s*\{[\s\S]*record_auth_failure[\s\S]*\}\s*catch/);
  });
});

describe('Phase 7 Closure — Access gate wiring', () => {
  it('get_my_auth_access_state_v2 checks locked_until', () => {
    assert.match(migration, /locked_until.*now\(\)/);
    assert.match(migration, /ACCOUNT_LOCKED/);
  });

  it('get_my_auth_access_state_v2 checks session_security_state for revoked', () => {
    assert.match(migration, /revoked_at.*IS NOT NULL/);
    assert.match(migration, /SESSION_REVOKED/);
  });

  it('get_my_auth_access_state_v2 checks idle expiry', () => {
    assert.match(migration, /idle_expiry_at.*<= now\(\)/);
    assert.match(migration, /SESSION_EXPIRED/);
  });

  it('get_my_auth_access_state_v2 checks absolute expiry', () => {
    assert.match(migration, /absolute_expiry_at.*<= now\(\)/);
  });

  it('missing session state is backward-compatible (not fail-closed)', () => {
    assert.match(migration, /IF NOT FOUND THEN[\s\S]*RETURN v_base_result/);
  });
});

describe('Phase 7 Closure — Session list', () => {
  it('session-management uses get_user_session_security_state with explicit user binding', () => {
    assert.match(sessionMgmt, /get_user_session_security_state/);
    assert.match(sessionMgmt, /p_user_id: userId/);
  });

  it('session-management does not call auth.uid()-dependent RPC without user binding', () => {
    assert.doesNotMatch(sessionMgmt, /get_my_session_security_state/);
  });
});

describe('Phase 7 Closure — Admin session revoke', () => {
  it('admin_revoke requires FULL access + step-up', () => {
    assert.match(sessionMgmt, /admin_revoke/);
    assert.match(sessionMgmt, /FULL_ACCESS_REQUIRED/);
    assert.match(sessionMgmt, /has_active_custom_mfa_grant/);
    assert.match(sessionMgmt, /STEP_UP_REQUIRED/);
  });

  it('admin_revoke RPC writes audit log', () => {
    assert.match(migration, /admin_revoke_user_session/);
    assert.match(migration, /security_audit_events/);
    assert.match(migration, /admin_session_revoke/);
  });
});

describe('Phase 7 Closure — Recovery anti-enumeration', () => {
  it('unified-recovery does not return email_hint or phone_hint', () => {
    assert.doesNotMatch(recovery, /email_hint/);
    assert.doesNotMatch(recovery, /phone_hint/);
  });

  it('recovery requires user to provide full target channel', () => {
    assert.match(recovery, /requires_channel/);
  });
});

describe('Phase 7 Closure — OTP log safety', () => {
  it('recovery OTP uses auth_otp mode not dispatch', () => {
    assert.match(recovery, /mode.*auth_otp/);
    assert.doesNotMatch(recovery, /mode.*dispatch/);
  });

  it('recovery does not log plaintext OTP to sms_dispatch_logs', () => {
    assert.doesNotMatch(recovery, /sms_dispatch_logs/);
  });
});

describe('Phase 7 Closure — Safety', () => {
  it('no data deletion in migration', () => {
    assert.doesNotMatch(migration, /DROP TABLE|DROP COLUMN|DELETE FROM|TRUNCATE|CASCADE/i);
  });

  it('no direct auth table writes in edge functions', () => {
    assert.doesNotMatch(passwordLogin, /INSERT INTO auth\.|UPDATE auth\.|DELETE FROM auth\./i);
    assert.doesNotMatch(sessionMgmt, /INSERT INTO auth\.|UPDATE auth\.|DELETE FROM auth\./i);
  });

  it('settings defaults remain false until readiness', () => {
    assert.match(migration, /COALESCE\(v_settings\.session_management_enabled, false\)/);
  });
});
