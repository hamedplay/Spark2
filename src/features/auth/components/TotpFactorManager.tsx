import { useState, useEffect, useCallback, useRef } from 'react';
import { Shield, ShieldCheck, Plus, Trash2, X, Loader as Loader2, QrCode, Copy, Check, CircleAlert as AlertCircle, Smartphone } from 'lucide-react';
import toast from 'react-hot-toast';
import { supabase } from '../../../lib/supabase';
import {
  listCurrentUserTotpFactors,
  startTotpEnrollment,
  verifyTotpFactor,
  cancelCurrentTotpEnrollment,
  validateTotpCode,
  type TotpFactor,
  type TotpEnrollmentResult,
} from '../services/mfaOperations';

type Phase = 'idle' | 'enrolling' | 'verifying';

export function TotpFactorManager() {
  const [factors, setFactors] = useState<TotpFactor[]>([]);
  const [loading, setLoading] = useState(true);
  const [phase, setPhase] = useState<Phase>('idle');
  const [enrollment, setEnrollment] = useState<TotpEnrollmentResult | null>(null);
  const [friendlyName, setFriendlyName] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [currentAal, setCurrentAal] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [removeTarget, setRemoveTarget] = useState<TotpFactor | null>(null);
  const [removeCode, setRemoveCode] = useState('');
  const [removing, setRemoving] = useState(false);
  const enrolledFactorIdRef = useRef<string | null>(null);

  const loadFactors = useCallback(async () => {
    setLoading(true);
    try {
      const allFactors = await listCurrentUserTotpFactors();
      const verified = allFactors.filter((f) => f.status === 'verified');
      setFactors(verified);

      const { data: aalData } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
      setCurrentAal(aalData?.currentLevel ?? '');

      const { data: accessState } = await supabase.rpc('get_my_auth_access_state_v2' as never) as { data: unknown };
      setMfaRequired((accessState as { mfa_required?: boolean })?.mfa_required ?? false);
    } catch {
      // best-effort
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadFactors(); }, [loadFactors]);

  const handleStartEnrollment = useCallback(async () => {
    const trimmedName = friendlyName.trim();
    if (trimmedName.length < 3 || trimmedName.length > 64) {
      toast.error('نام برنامه باید بین ۳ تا ۶۴ کاراکتر باشد.');
      return;
    }

    setBusy(true);
    try {
      const result = await startTotpEnrollment(trimmedName);
      enrolledFactorIdRef.current = result.factorId;
      setEnrollment(result);
      setPhase('enrolling');
    } catch {
      toast.error('فعال‌سازی انجام نشد؛ دوباره تلاش کنید.');
    } finally {
      setBusy(false);
    }
  }, [friendlyName]);

  const handleVerify = useCallback(async () => {
    const validCode = validateTotpCode(code);
    if (!validCode) {
      toast.error('کد واردشده معتبر نیست.');
      return;
    }

    if (!enrolledFactorIdRef.current) {
      toast.error('فعال‌سازی انجام نشد؛ دوباره تلاش کنید.');
      return;
    }

    setBusy(true);
    setPhase('verifying');
    try {
      await verifyTotpFactor(enrolledFactorIdRef.current, validCode);
      setCode('');
      setEnrollment(null);
      setFriendlyName('');
      setPhase('idle');
      enrolledFactorIdRef.current = null;
      await loadFactors();
      toast.success('برنامه احراز هویت با موفقیت فعال شد.');
    } catch {
      toast.error('کد واردشده معتبر نیست.');
      setPhase('enrolling');
    } finally {
      setBusy(false);
    }
  }, [code, loadFactors]);

  const handleCancel = useCallback(async () => {
    if (enrolledFactorIdRef.current) {
      try {
        await cancelCurrentTotpEnrollment(enrolledFactorIdRef.current);
      } catch {
        // best-effort
      }
    }
    enrolledFactorIdRef.current = null;
    setEnrollment(null);
    setCode('');
    setFriendlyName('');
    setPhase('idle');
  }, []);

  const handleCopySecret = useCallback(() => {
    if (enrollment?.secret) {
      navigator.clipboard.writeText(enrollment.secret).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      });
    }
  }, [enrollment]);

  const handleRemoveInitiate = useCallback((factor: TotpFactor) => {
    setRemoveTarget(factor);
    setRemoveCode('');
  }, []);

  const closeRemoveDialog = useCallback(() => {
    if (removing) return;

    setRemoveTarget(null);
    setRemoveCode('');
  }, [removing]);

  const handleRemoveConfirm = useCallback(async () => {
    if (!removeTarget) return;
    const validCode = validateTotpCode(removeCode);
    if (!validCode) {
      toast.error('کد واردشده معتبر نیست.');
      return;
    }

    setRemoving(true);
    try {
      // Step 1: challengeAndVerify with the target factor
      await verifyTotpFactor(removeTarget.id, validCode);

      // Step 2: only after AAL2 confirmed, unenroll
      const { error } = await supabase.auth.mfa.unenroll({ factorId: removeTarget.id });
      if (error) {
        toast.error('خطا در حذف برنامه احراز هویت.');
        return;
      }

      setRemoveCode('');
      setRemoveTarget(null);
      await loadFactors();
      toast.success('برنامه احراز هویت حذف شد.');
    } catch {
      toast.error('کد واردشده معتبر نیست.');
    } finally {
      setRemoving(false);
    }
  }, [removeTarget, removeCode, loadFactors]);

  const verifiedCount = factors.filter((f) => f.status === 'verified').length;

  if (loading) {
    return (
      <div className="flex justify-center py-8">
        <Loader2 className="w-8 h-8 text-teal-500 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-4" dir="rtl">
      {/* Status banner */}
      <div className={`flex items-center gap-3 p-4 rounded-xl border ${
        verifiedCount > 0
          ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-700/40'
          : 'bg-gray-50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600'
      }`}>
        {verifiedCount > 0 ? (
          <ShieldCheck className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0" />
        ) : (
          <Shield className="w-5 h-5 text-gray-400 flex-shrink-0" />
        )}
        <div>
          <p className="text-sm font-semibold text-gray-800 dark:text-white">
            {verifiedCount > 0
              ? `${verifiedCount} برنامه احراز هویت فعال`
              : 'احراز هویت دومرحله‌ای فعال نیست'}
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
            سطح تایید فعلی: {currentAal || 'aal1'}
            {mfaRequired && ' — MFA برای حساب شما الزامی است'}
          </p>
        </div>
      </div>

      {/* Factor list */}
      {factors.length > 0 && (
        <div className="space-y-2">
          {factors.map((f) => (
            <div key={f.id} className="flex items-center justify-between p-3 bg-white dark:bg-gray-800 rounded-xl border border-gray-100 dark:border-gray-700">
              <div className="flex items-center gap-3">
                <Smartphone className="w-4 h-4 text-gray-400" />
                <div>
                  <p className="text-sm font-medium text-gray-800 dark:text-white">{f.friendlyName ?? 'بدون نام'}</p>
                  <p className="text-xs text-gray-400">
                    {new Date(f.createdAt).toLocaleDateString('fa-IR')} — تأییدشده
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => handleRemoveInitiate(f)}
                disabled={removing}
                className="p-2 rounded-lg text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                title="حذف"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Enrollment flow */}
      {phase === 'idle' && (
        <div className="space-y-3">
          <button
            type="button"
            onClick={() => setPhase('enrolling')}
            disabled={busy}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-teal-500 hover:bg-teal-600 disabled:opacity-50 text-white rounded-xl text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" />
            افزودن برنامه احراز هویت
          </button>
        </div>
      )}

      {phase === 'enrolling' && !enrollment && (
        <div className="space-y-4 p-4 bg-gray-50 dark:bg-gray-700/50 rounded-xl">
          <div>
            <label className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2 block">
              نام برنامه احراز هویت
            </label>
            <input
              type="text"
              value={friendlyName}
              onChange={(e) => setFriendlyName(e.target.value)}
              maxLength={64}
              placeholder="مثلاً: گوشی شخصی"
              className="w-full px-4 py-2.5 border border-gray-200 dark:border-gray-600 rounded-xl bg-white dark:bg-gray-800 text-gray-800 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-teal-500"
            />
            <p className="text-xs text-gray-400 mt-1">۳ تا ۶۴ کاراکتر</p>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={handleStartEnrollment}
              disabled={busy || friendlyName.trim().length < 3}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-teal-500 hover:bg-teal-600 disabled:opacity-50 text-white rounded-xl text-sm font-medium transition-colors"
            >
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <QrCode className="w-4 h-4" />}
              ایجاد کد QR
            </button>
            <button
              type="button"
              onClick={handleCancel}
              disabled={busy}
              className="px-4 py-2.5 bg-gray-200 hover:bg-gray-300 dark:bg-gray-600 dark:hover:bg-gray-500 text-gray-700 dark:text-gray-300 rounded-xl text-sm transition-colors"
            >
              انصراف
            </button>
          </div>
        </div>
      )}

      {(phase === 'enrolling' || phase === 'verifying') && enrollment && (
        <div className="space-y-4 p-4 bg-gray-50 dark:bg-gray-700/50 rounded-xl">
          <div className="flex flex-col items-center gap-3">
            <p className="text-sm text-gray-600 dark:text-gray-400 text-center">
              کد QR را با برنامه احراز هویت (مثل Google Authenticator) اسکن کنید:
            </p>
            <img src={enrollment.qrCode} alt="QR Code" className="w-40 h-40 rounded-xl border border-gray-200 dark:border-gray-600 bg-white p-2" />
            <div className="w-full flex items-center gap-2 bg-white dark:bg-gray-800 rounded-lg p-3">
              <code className="flex-1 text-xs text-gray-600 dark:text-gray-300 break-all font-mono">
                {enrollment.secret}
              </code>
              <button type="button" onClick={handleCopySecret} className="flex-shrink-0 p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors" title="کپی کلید">
                {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4 text-gray-400" />}
              </button>
            </div>
            <details className="w-full">
              <summary className="text-xs text-gray-400 cursor-pointer hover:text-gray-500">استفاده از URI به‌جای QR</summary>
              <code className="block mt-2 text-xs text-gray-500 dark:text-gray-400 break-all font-mono bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
                {enrollment.uri}
              </code>
            </details>
          </div>

          <div>
            <label className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2 block">کد ۶ رقمی از برنامه:</label>
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="000000"
              className="w-full text-center text-2xl tracking-[0.5em] font-mono px-4 py-3 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-800 dark:text-white focus:outline-none focus:ring-2 focus:ring-teal-500"
              dir="ltr"
            />
          </div>

          <div className="flex gap-2">
            <button
              type="button"
              onClick={handleVerify}
              disabled={busy || code.length !== 6}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-teal-500 hover:bg-teal-600 disabled:opacity-50 text-white rounded-xl text-sm font-medium transition-colors"
            >
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
              تأیید و فعال‌سازی
            </button>
            <button
              type="button"
              onClick={handleCancel}
              disabled={busy}
              className="px-4 py-2.5 bg-gray-200 hover:bg-gray-300 dark:bg-gray-600 dark:hover:bg-gray-500 text-gray-700 dark:text-gray-300 rounded-xl text-sm transition-colors"
            >
              انصراف
            </button>
          </div>
        </div>
      )}

      {/* Remove modal */}
      {removeTarget && (
        <div className="fixed inset-0 z-[300] flex items-center justify-center bg-black/50" dir="rtl">
          <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-md w-full mx-4 p-6 space-y-5">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-bold text-gray-800 dark:text-white flex items-center gap-2">
                <AlertCircle className="w-5 h-5 text-red-500" />
                حذف برنامه احراز هویت
              </h3>
              <button type="button" onClick={closeRemoveDialog} disabled={removing} aria-disabled={removing} className="p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-400 disabled:opacity-50 disabled:pointer-events-none">
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-sm text-gray-500 dark:text-gray-400">
              برای حذف برنامه «{removeTarget.friendlyName ?? 'بدون نام'}» کد ۶ رقمی آن را وارد کنید.
            </p>

            {verifiedCount === 1 && mfaRequired && (
              <div className="p-3 bg-red-50 dark:bg-red-900/20 rounded-xl text-xs text-red-700 dark:text-red-300">
                این حساب به احراز هویت دومرحله‌ای نیاز دارد. ابتدا یک برنامه احراز هویت دیگر اضافه کنید، سپس این مورد را حذف کنید.
              </div>
            )}

            {verifiedCount === 1 && !mfaRequired && (
              <div className="p-3 bg-amber-50 dark:bg-amber-900/20 rounded-xl text-xs text-amber-700 dark:text-amber-300">
                این آخرین برنامه احراز هویت شماست. پس از حذف، حساب شما بدون MFA خواهد بود.
              </div>
            )}

            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={removeCode}
              onChange={(e) => setRemoveCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="کد ۶ رقمی"
              className="w-full text-center text-2xl tracking-[0.5em] font-mono px-4 py-3 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-800 dark:text-white focus:outline-none focus:ring-2 focus:ring-red-500"
              dir="ltr"
            />

            <div className="flex gap-3">
              <button
                type="button"
                onClick={handleRemoveConfirm}
                disabled={removing || removeCode.length !== 6 || (verifiedCount === 1 && mfaRequired)}
                className="flex-1 flex items-center justify-center gap-2 px-5 py-2.5 bg-red-500 hover:bg-red-600 disabled:opacity-50 text-white rounded-xl text-sm font-medium transition-colors"
              >
                {removing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                حذف
              </button>
              <button
                type="button"
                onClick={closeRemoveDialog}
                disabled={removing}
                aria-disabled={removing}
                className="px-5 py-2.5 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-xl text-sm font-medium transition-colors disabled:opacity-50"
              >
                انصراف
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
