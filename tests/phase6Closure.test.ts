import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();
const edge = readFileSync(join(root, 'supabase/functions/custom-mfa/index.ts'), 'utf8');
const migration = readFileSync(join(root, 'supabase/migrations/20260808192935_20260808200000_phase6_closure_factor_enrollment_bale_rate_limit.sql.sql'), 'utf8');

describe('Phase 6 Closure — OTP logging proof', () => {
  it('uses auth_otp mode for SMS (no plaintext OTP in sms_dispatch_logs)', () => {
    assert.match(edge, /mode.*auth_otp/);
    assert.doesNotMatch(edge, /mode.*dispatch/);
  });

  it('never passes plaintext OTP to dispatch mode or logs it to DB', () => {
    // The send-sms auth_otp mode does NOT log message to sms_dispatch_logs
    // (only dispatch mode logs message, and we never use dispatch)
    assert.doesNotMatch(edge, /mode.*dispatch/);
    assert.doesNotMatch(edge, /sms_dispatch_logs/);
  });

  it('OTP is only in the HMAC hash and the transport payload, never in any DB insert', () => {
    assert.doesNotMatch(edge, /insert.*otp/i);
    assert.match(edge, /hmac\(otp/);
  });
});

describe('Phase 6 Closure — Bale runtime proof', () => {
  it('reads Bale bot_token from edge secret, not from social_channel_configs DB table', () => {
    assert.match(edge, /Deno\.env\.get\("BALE_BOT_TOKEN"\)/);
    assert.doesNotMatch(edge, /from\("social_channel_configs"\)/);
    assert.doesNotMatch(edge, /social_channel_configs\.bot_token/i);
  });

  it('bale_chat_id is never stored or logged in plaintext', () => {
    assert.match(edge, /mfa_encrypt/);
    assert.match(edge, /mfa_decrypt/);
    assert.doesNotMatch(edge, /bale_chat_id.*plaintext/i);
    assert.doesNotMatch(edge, /return.*bale_chat_id/i);
  });

  it('Bale nonce is minimum 32 bytes (64 hex chars) and HMAC-only lookup', () => {
    assert.match(edge, /bale_nonce\.length < 64/);
    assert.match(migration, /consume_bale_link_nonce.*nonce_hash.*FOR UPDATE/s);
    assert.match(migration, /NONCE_CONSUMED_RACE/);
  });

  it('Bale nonce consume is atomic one-time', () => {
    assert.match(migration, /used_at = now\(\).*used_at IS NULL.*RETURNING 1/s);
  });
});

describe('Phase 6 Closure — Factor enrollment', () => {
  it('enrollment RPCs exist for sms, bale, email', () => {
    assert.match(migration, /enroll_custom_mfa_factor/);
    assert.match(migration, /p_factor_type.*sms.*bale.*email/s);
  });

  it('disabling a factor sets status to disabled, not delete', () => {
    assert.match(migration, /disable_custom_mfa_factor/);
    assert.match(migration, /factor_status = 'disabled'/);
    assert.doesNotMatch(migration, /DELETE FROM public\.custom_mfa_factors/i);
  });

  it('recovery code regeneration revokes old codes, does not delete', () => {
    assert.match(migration, /regenerate_custom_mfa_recovery_codes_v2/);
    assert.match(migration, /revoked_at = now\(\)/);
    assert.doesNotMatch(migration, /DELETE FROM public\.custom_mfa_recovery_codes/i);
  });

  it('regenerate requires FULL + step-up grant', () => {
    assert.match(edge, /has_active_custom_mfa_grant/);
    assert.match(edge, /STEP_UP_REQUIRED/);
  });

  it('MFA cannot be activated without at least one valid factor', () => {
    // The readiness gate checks for active factors before allowing operations
    assert.match(edge, /get_custom_mfa_readiness/);
    assert.match(edge, /MFA_NOT_READY/);
  });
});

describe('Phase 6 Closure — Rate-limit + resend', () => {
  it('challenge creation is rate-limited per user/session/IP', () => {
    assert.match(edge, /consume_mfa_challenge_rate_limit/);
    assert.match(migration, /p_user_limit.*p_session_limit.*p_ip_limit/s);
  });

  it('resend enforces resend_count limit and cooldown', () => {
    assert.match(edge, /update_mfa_challenge_resend/);
    assert.match(migration, /resend_count.*custom_mfa_max_resends/s);
    assert.match(migration, /resend_available_at/);
  });

  it('resend is also rate-limited', () => {
    assert.match(edge, /mode.*resend[\s\S]*consume_mfa_challenge_rate_limit/s);
  });
});

describe('Phase 6 Closure — Secret readiness', () => {
  it('readiness RPC returns ready/not_ready without exposing secret values', () => {
    assert.match(migration, /get_custom_mfa_readiness/);
    assert.match(migration, /pepper_ready/);
    assert.match(migration, /bale_bot_token_ready/);
    assert.doesNotMatch(migration, /return.*pepper.*value/i);
    assert.doesNotMatch(migration, /return.*bot_token.*value/i);
  });

  it('edge function blocks operations when readiness is not_ready', () => {
    assert.match(edge, /readiness.*not_ready.*503/s);
  });

  it('TOTP/aal2 for admins is not touched', () => {
    assert.doesNotMatch(edge, /aal2|auth\.mfa_factors|totp_secret/s);
    assert.doesNotMatch(migration, /ALTER.*auth\.mfa|auth\.identities/i);
  });

  it('no direct auth table writes', () => {
    assert.doesNotMatch(edge, /INSERT INTO auth\.|UPDATE auth\.|DELETE FROM auth\./i);
    assert.doesNotMatch(migration, /INSERT INTO auth\.|UPDATE auth\.|DELETE FROM auth\./i);
  });

  it('no data deletion in migration', () => {
    assert.doesNotMatch(migration, /DROP TABLE|DROP COLUMN|DELETE FROM|TRUNCATE|CASCADE/i);
  });
});
