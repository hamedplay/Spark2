import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();
const edge = readFileSync(join(root, 'supabase/functions/custom-mfa/index.ts'), 'utf8');
const baleWebhook = readFileSync(join(root, 'supabase/functions/bale-webhook/index.ts'), 'utf8');
const baleLink = readFileSync(join(root, 'supabase/functions/bale-link-generate/index.ts'), 'utf8');
const migrationClosure = readFileSync(join(root, 'supabase/migrations/20260808192935_20260808200000_phase6_closure_factor_enrollment_bale_rate_limit.sql.sql'), 'utf8');

describe('Phase 6 Final Closure — OTP HMAC domain binding', () => {
  it('binds OTP to challenge_id + user_id + session_id + factor_type + target_hash + otp_code', () => {
    assert.match(edge, /domainBoundOtpHash/);
    assert.match(edge, /challengeId.*userId.*sessionId.*factorType.*targetHash.*otpCode/);
  });

  it('verify reconstructs the exact same domain-bound HMAC input', () => {
    assert.match(edge, /domainBoundOtpHash\(body\.challenge_id, caller\.user\.id, caller\.sessionId/);
  });

  it('uses v2 service RPCs with target_hash', () => {
    assert.match(edge, /create_custom_mfa_challenge_v2/);
    assert.match(edge, /consume_custom_mfa_challenge_v2/);
    assert.match(edge, /p_target_hash/);
  });

  it('never stores plaintext OTP in DB', () => {
    assert.doesNotMatch(edge, /insert.*otp/i);
    assert.match(edge, /hmac/);
  });
});

describe('Phase 6 Final Closure — Bale ownership proof', () => {
  it('browser never sends or determines bale_chat_id', () => {
    assert.doesNotMatch(edge, /bale_chat_id.*body/);
    assert.doesNotMatch(edge, /body.*bale_chat_id/);
  });

  it('Bale linking only from webhook-verified nonce', () => {
    assert.match(edge, /enroll_bale/);
    assert.match(edge, /bale_nonce/);
    assert.match(edge, /BALE_LINK_PENDING/);
  });

  it('bale-webhook reads bot token from Edge Secret, not DB', () => {
    assert.match(baleWebhook, /Deno\.env\.get\("BALE_BOT_TOKEN"\)/);
    assert.doesNotMatch(baleWebhook, /social_channel_configs.*bot_token/i);
  });

  it('bale-webhook stores encrypted chat_id, never plaintext', () => {
    assert.match(baleWebhook, /mfa_encrypt/);
    assert.match(baleWebhook, /bale_chat_id_enc/);
    assert.doesNotMatch(baleWebhook, /bale_chat_id.*plaintext/i);
  });

  it('bale-link-generate creates 32-byte one-time nonce via service RPC', () => {
    assert.match(baleLink, /nonceBytes.*32/);
    assert.match(baleLink, /create_bale_link_nonce/);
    assert.match(baleLink, /bale_nonce/);
  });

  it('bale-link-generate does not expose bot token', () => {
    assert.doesNotMatch(baleLink, /BALE_BOT_TOKEN/);
    assert.match(baleLink, /bot_username/);
  });
});

describe('Phase 6 Final Closure — Recovery Code flow', () => {
  it('recovery codes generated server-side with WebCrypto', () => {
    assert.match(edge, /randomRecoveryCode/);
    assert.match(edge, /crypto\.getRandomValues/);
  });

  it('regenerate revokes old codes, does not delete', () => {
    assert.match(edge, /regenerate_custom_mfa_recovery_codes_v3/);
    assert.doesNotMatch(edge, /DELETE FROM.*custom_mfa_recovery_codes/i);
  });

  it('codes shown once in response', () => {
    assert.match(edge, /codes/);
    assert.match(edge, /code_count/);
  });

  it('regenerate requires FULL + step-up grant', () => {
    assert.match(edge, /has_active_custom_mfa_grant/);
    assert.match(edge, /STEP_UP_REQUIRED/);
  });
});

describe('Phase 6 Final Closure — SMS enrollment', () => {
  it('SMS enrollment only uses confirmed auth.users.phone', () => {
    assert.match(edge, /enroll_sms_factor_from_auth_phone/);
    assert.match(edge, /phone_confirmed_at/);
  });

  it('browser never sends arbitrary phone number for enrollment', () => {
    assert.doesNotMatch(edge, /body\.phone/);
    assert.doesNotMatch(edge, /p_phone.*body/);
  });

  it('enforces phone OTP factor independence', () => {
    assert.match(edge, /isPhoneOtpPrimary/);
    assert.match(edge, /FACTOR_INDEPENDENCE_REQUIRED/);
  });
});

describe('Phase 6 Final Closure — Legacy ACL hardening', () => {
  it('legacy regenerate_custom_mfa_recovery_codes revoked from authenticated/anon', () => {
    // The v3 RPC replaces the legacy one; legacy is revoked in migration
    assert.match(edge, /regenerate_custom_mfa_recovery_codes_v3/);
    assert.doesNotMatch(edge, /regenerate_custom_mfa_recovery_codes\(\)/);
  });

  it('legacy create_bale_link_nonce() not used by edge', () => {
    assert.doesNotMatch(edge, /create_bale_link_nonce\(\)/);
    assert.match(baleLink, /create_bale_link_nonce/);
  });

  it('legacy consume_bale_link_nonce(text, text) not used', () => {
    assert.doesNotMatch(edge, /consume_bale_link_nonce.*p_chat_id/);
  });

  it('revoke_custom_mfa_grant not granted to anon', () => {
    assert.doesNotMatch(edge, /revoke_custom_mfa_grant/);
  });
});

describe('Phase 6 Final Closure — Security invariants', () => {
  it('no feature flags enabled', () => {
    assert.doesNotMatch(edge, /custom_mfa_enabled.*true/);
    assert.doesNotMatch(edge, /custom_mfa_required.*true/);
  });

  it('no aal2 or auth table writes', () => {
    assert.doesNotMatch(edge, /aal2|auth\.identities/);
    assert.doesNotMatch(edge, /INSERT INTO auth\.|UPDATE auth\.|DELETE FROM auth\./i);
  });

  it('no data deletion in closure migration', () => {
    assert.doesNotMatch(migrationClosure, /DROP TABLE|DROP COLUMN|TRUNCATE/i);
  });

  it('bale_chat_id never stored plaintext in new code', () => {
    assert.doesNotMatch(baleWebhook, /bale_chat_id"\s*:/);
    assert.doesNotMatch(baleWebhook, /bale_chat_id,\s/);
    assert.match(baleWebhook, /bale_chat_id_enc/);
  });

  it('rate-limit enforced on create and resend', () => {
    assert.match(edge, /consume_mfa_challenge_rate_limit/);
  });
});
