import { supabase } from '../../../lib/supabase';
import type { CustomMfaChallengeResponse, CustomMfaFactor, CustomMfaGrantResponse, CustomMfaState } from '../types/customMfa';

async function invoke<T>(body: Record<string, unknown>): Promise<T> {
  const { data, error } = await supabase.functions.invoke('custom-mfa', { body });
  if (error || !data) throw new Error('MFA_OPERATION_FAILED');
  return data as T;
}

export function createCustomMfaChallenge(factorType: Exclude<CustomMfaFactor, 'totp' | 'recovery'>): Promise<CustomMfaChallengeResponse> {
  return invoke<CustomMfaChallengeResponse>({ mode: 'create', factor_type: factorType });
}

export function verifyCustomMfaChallenge(challengeId: string, code: string): Promise<CustomMfaGrantResponse> {
  return invoke<CustomMfaGrantResponse>({ mode: 'verify', challenge_id: challengeId, code });
}

export function verifyCustomMfaRecovery(code: string): Promise<CustomMfaGrantResponse> {
  return invoke<CustomMfaGrantResponse>({ mode: 'recovery', code });
}

export function resendCustomMfaChallenge(challengeId: string): Promise<{ ok: boolean }> {
  return invoke<{ ok: boolean }>({ mode: 'resend', challenge_id: challengeId });
}

export function enrollSmsFactor(): Promise<{ ok: boolean; factor_id?: string }> {
  return invoke<{ ok: boolean; factor_id?: string }>({ mode: 'enroll_sms' });
}

export function checkBaleLinkStatus(baleNonce: string): Promise<{ ok: boolean; factor_id?: string }> {
  return invoke<{ ok: boolean; factor_id?: string }>({ mode: 'enroll_bale', bale_nonce: baleNonce });
}

export function disableCustomMfaFactor(factorType: CustomMfaFactor): Promise<{ ok: boolean }> {
  return invoke<{ ok: boolean }>({ mode: 'disable', factor_type: factorType });
}

export function regenerateRecoveryCodes(): Promise<{ ok: boolean; codes: string[]; code_count: number }> {
  return invoke<{ ok: boolean; codes: string[]; code_count: number }>({ mode: 'regenerate_recovery' });
}

export async function loadCustomMfaState(): Promise<CustomMfaState> {
  const { data, error } = await supabase.rpc('get_custom_mfa_state');
  if (error || !data) throw new Error('MFA_STATE_UNAVAILABLE');
  return data as unknown as CustomMfaState;
}
