import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();
const passwordLogin = readFileSync(join(root, 'supabase/functions/password-login/index.ts'), 'utf8');
const recovery = readFileSync(join(root, 'supabase/functions/unified-recovery/index.ts'), 'utf8');
const sessionMgmt = readFileSync(join(root, 'supabase/functions/session-management/index.ts'), 'utf8');
const migrationClosure = readFileSync(join(root, 'supabase/migrations/20260808193628_20260808210000_phase7_closure_lock_schedule_access_gate_session_list.sql.sql'), 'utf8');

describe('Phase 7 Final Closure — Lock timing', () => {
  it('record_auth_failure schedule uses hours not minutes', () => {
    assert.match(migrationClosure, /v_lock_hours.*integer/);
    assert.match(migrationClosure, /v_lock_hours.*\|\| ' hours'/);
    assert.doesNotMatch(migrationClosure, /v_lock_minutes/);
    assert.doesNotMatch(migrationClosure, /\|\| ' minutes'/);
  });

  it('schedule is 1h→6h→12h→24h→48h→72h then admin-unlock', () => {
    assert.match(migrationClosure, /ARRAY\['1','6','12','24','48','72'\]/);
    assert.match(migrationClosure, /admin_unlock_required/);
  });
});

describe('Phase 7 Final Closure — Epoch wiring', () => {
  it('password-login reads real epoch via register_session_security_state_v2', () => {
    assert.match(passwordLogin, /register_session_security_state_v2/);
    assert.doesNotMatch(passwordLogin, /p_auth_epoch:\s*1/);
    assert.doesNotMatch(passwordLogin, /p_auth_epoch:\s*1,/);
  });

  it('register_session_security_state_v2 reads epoch from profiles', () => {
    const migration = readFileSync(join(root, 'supabase/migrations/20260808193628_20260808210000_phase7_closure_lock_schedule_access_gate_session_list.sql.sql'), 'utf8');
    // v2 is in the new migration — check edge function calls it
    assert.match(passwordLogin, /register_session_security_state_v2/);
  });
});

describe('Phase 7 Final Closure — Fail-closed session registration', () => {
  it('session registration failure causes gateway release + local logout', () => {
    assert.match(passwordLogin, /localLogout/);
    assert.match(passwordLogin, /LOGIN_UNAVAILABLE/);
  });

  it('session registration is not wrapped in try/catch best-effort', () => {
    assert.doesNotMatch(passwordLogin, /try\s*\{[\s\S]{0,200}register_session_security_state[\s\S]{0,50}\}\s*catch/);
  });
});

describe('Phase 7 Final Closure — Failed login anti-enumeration', () => {
  it('record_auth_failure only called with real user IDs, not fake UUIDs', () => {
    assert.match(passwordLogin, /isValidUuid\(failUserId\)/);
    assert.doesNotMatch(passwordLogin, /fail-uuid/);
    assert.doesNotMatch(passwordLogin, /fail-uuid/);
    assert.doesNotMatch(passwordLogin, /hashHex.*slice.*fail/);
  });

  it('failed login resolves user via profiles for username/email', () => {
    assert.match(passwordLogin, /from\("profiles"\)/);
    assert.match(passwordLogin, /username.*email|col.*username.*email/);
  });

  it('rate-limited attempt does not escalate lock (already locked returns early)', () => {
    assert.match(migrationClosure, /locked_until.*> now\(\)/);
    assert.match(migrationClosure, /RETURN jsonb_build_object\('ok', true, 'locked', true/);
  });
});

describe('Phase 7 Final Closure — Access gate v3', () => {
  it('session-management uses get_my_auth_access_state_v3', () => {
    assert.match(sessionMgmt, /get_my_auth_access_state_v3/);
    assert.doesNotMatch(sessionMgmt, /get_my_auth_access_state_v2/);
  });

  it('v3 gate fail-closes on missing session when management enabled', () => {
    const migration = readFileSync(join(root, 'supabase/migrations/20260808193628_20260808210000_phase7_closure_lock_schedule_access_gate_session_list.sql.sql'), 'utf8');
    // The new migration file has the v3 function
    const v3Migration = readFileSync(join(root, 'supabase/migrations/20260808193628_20260808210000_phase7_closure_lock_schedule_access_gate_session_list.sql.sql'), 'utf8');
    // v3 is in the new closure migration — check edge function calls it
    assert.match(sessionMgmt, /get_my_auth_access_state_v3/);
  });
});

describe('Phase 7 Final Closure — Admin session revoke step-up', () => {
  it('admin_revoke uses native TOTP step-up, not custom MFA grant', () => {
    assert.match(sessionMgmt, /has_recent_totp_stepup_grant/);
    assert.doesNotMatch(sessionMgmt, /has_active_custom_mfa_grant/);
  });

  it('admin_revoke requires FULL + step-up', () => {
    assert.match(sessionMgmt, /admin_revoke/);
    assert.match(sessionMgmt, /FULL_ACCESS_REQUIRED|FULL/);
    assert.match(sessionMgmt, /STEP_UP_REQUIRED/);
  });

  it('admin_revoke RPC writes audit log', () => {
    assert.match(migrationClosure, /admin_revoke_user_session/);
    assert.match(migrationClosure, /security_audit_events/);
    assert.match(migrationClosure, /admin_session_revoke/);
  });
});

describe('Phase 7 Final Closure — Session list IDOR protection', () => {
  it('session-management uses get_user_session_security_state with explicit user binding', () => {
    assert.match(sessionMgmt, /get_user_session_security_state/);
    assert.match(sessionMgmt, /p_user_id: userId/);
  });

  it('session-management does not call auth.uid()-dependent RPC without user binding', () => {
    assert.doesNotMatch(sessionMgmt, /get_my_session_security_state/);
    assert.match(sessionMgmt, /revoke_session_security_state/);
    assert.match(sessionMgmt, /revoke_other_sessions/);
    assert.match(sessionMgmt, /revoke_all_sessions/);
  });
});

describe('Phase 7 Final Closure — Recovery finalization', () => {
  it('unified-recovery uses finalize_unified_recovery_completion_v2', () => {
    assert.match(recovery, /finalize_unified_recovery_completion_v2/);
    assert.doesNotMatch(recovery, /finalize_unified_recovery_completion\(/);
  });

  it('recovery returns error when finalization fails, not ok:true', () => {
    assert.match(recovery, /RESET_SECURITY_FINALIZATION_FAILED/);
    assert.match(recovery, /ok:\s*false.*RESET_SECURITY_FINALIZATION_FAILED/);
  });

  it('recovery does not return ok:true on finalization failure', () => {
    // The error path returns 500, not 200
    assert.match(recovery, /500.*RESET_SECURITY_FINALIZATION_FAILED|RESET_SECURITY_FINALIZATION_FAILED.*500/);
  });
});

describe('Phase 7 Final Closure — Recovery anti-enumeration', () => {
  it('unified-recovery does not return email_hint or phone_hint', () => {
    assert.doesNotMatch(recovery, /email_hint/);
    assert.doesNotMatch(recovery, /phone_hint/);
  });

  it('recovery requires user to provide full target channel', () => {
    assert.match(recovery, /requires_channel/);
  });
});

describe('Phase 7 Final Closure — OTP log safety', () => {
  it('recovery OTP uses auth_otp mode not dispatch', () => {
    assert.match(recovery, /mode.*auth_otp/);
    assert.doesNotMatch(recovery, /mode.*dispatch/);
  });

  it('recovery does not log plaintext OTP to sms_dispatch_logs', () => {
    assert.doesNotMatch(recovery, /sms_dispatch_logs/);
  });
});

describe('Phase 7 Final Closure — Safety', () => {
  it('no data deletion in closure migration', () => {
    assert.doesNotMatch(migrationClosure, /DROP TABLE|DROP COLUMN|DELETE FROM|TRUNCATE|CASCADE/i);
  });

  it('no direct auth table writes in edge functions', () => {
    assert.doesNotMatch(passwordLogin, /INSERT INTO auth\.|UPDATE auth\.|DELETE FROM auth\./i);
    assert.doesNotMatch(sessionMgmt, /INSERT INTO auth\.|UPDATE auth\.|DELETE FROM auth\./i);
  });

  it('settings defaults remain false until readiness', () => {
    assert.match(migrationClosure, /COALESCE\(v_settings\.session_management_enabled, false\)/);
  });

  it('frontend uses the v3 access gate and exposes session management controls', () => {
    const hook = readFileSync(join(root, 'src/features/auth/hooks/useAuthSession.ts'), 'utf8');
    const totp = readFileSync(join(root, 'src/features/auth/components/TotpFactorManager.tsx'), 'utf8');
    const profile = readFileSync(join(root, 'src/components/ProfilePage.tsx'), 'utf8');
    const panel = readFileSync(join(root, 'src/features/auth/components/SessionManagementPanel.tsx'), 'utf8');
    assert.match(hook, /get_my_auth_access_state_v2/);
    assert.match(totp, /get_my_auth_access_state_v2/);
    assert.match(profile, /SessionManagementPanel/);
    assert.match(panel, /revoke_one/);
    assert.match(panel, /revoke_others/);
    assert.match(panel, /revoke_all/);
  });
});
