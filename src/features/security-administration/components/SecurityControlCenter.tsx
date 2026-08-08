import { useState, useCallback } from 'react';
import { Settings as SettingsIcon, Shield, FileText, Users, Activity } from 'lucide-react';
import { SecuritySettingsConsole } from '../../security-settings/components/SecuritySettingsConsole';
import { SecurityAdminManagement } from './SecurityAdminManagement';
import { SecurityAuditConsole } from './SecurityAuditConsole';
import { AccountLifecycleManagement } from './AccountLifecycleManagement';
import { HealthCheckPanel } from './HealthCheckPanel';
import { SecurityStepUpDialog } from '../../security-settings/components/SecurityStepUpDialog';
import { changeSecurityAdminRole } from '../services/securityAdministrationService';
import { getSecurityAdminErrorMessage } from '../utils/securityAdministrationValidation';
import toast from 'react-hot-toast';
import type { VersionConflictSnapshot } from '../types/securityAdministration';

type Tab = 'settings' | 'admins' | 'audit' | 'lifecycle' | 'health';

interface PendingChange {
  targetUserId: string;
  targetDisplayName: string;
  newValue: boolean;
  expectedVersion: number;
  changeReason: string;
}

export function SecurityControlCenter() {
  const [tab, setTab] = useState<Tab>('settings');
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [pendingChange, setPendingChange] = useState<PendingChange | null>(null);
  const [conflict, setConflict] = useState<VersionConflictSnapshot | null>(null);
  const [changeBusy, setChangeBusy] = useState(false);
  const [adminRefreshVersion, setAdminRefreshVersion] = useState(0);
  const [auditRefreshVersion, setAuditRefreshVersion] = useState(0);

  const handleOpenStepUp = useCallback((params: {
    targetUserId: string;
    targetDisplayName: string;
    newValue: boolean;
    expectedVersion: number;
    changeReason: string;
  }) => {
    setPendingChange(params);
    setConflict(null);
    setStepUpOpen(true);
  }, []);

  const handleStepUpSuccess = useCallback(async () => {
    if (!pendingChange) return;

    setChangeBusy(true);
    try {
      const result = await changeSecurityAdminRole({
        targetUserId: pendingChange.targetUserId,
        newValue: pendingChange.newValue,
        expectedVersion: pendingChange.expectedVersion,
        changeReason: pendingChange.changeReason,
      });

      if (!result.ok) {
        if (result.error === 'VERSION_CONFLICT') {
          setConflict({
            targetUserId: pendingChange.targetUserId,
            targetDisplayName: pendingChange.targetDisplayName,
            requestedValue: pendingChange.newValue,
            expectedVersion: pendingChange.expectedVersion,
            currentVersion: result.currentVersion,
            changeReason: pendingChange.changeReason,
          });
          toast.error(getSecurityAdminErrorMessage('VERSION_CONFLICT'));
          setAdminRefreshVersion((v) => v + 1);
        } else {
          toast.error(getSecurityAdminErrorMessage(result.error ?? 'UNKNOWN_SECURITY_ADMIN_ERROR'));
        }
        return;
      }

      toast.success(pendingChange.newValue ? 'نقش مدیر امنیت اعطا شد.' : 'نقش مدیر امنیت حذف شد.');
      setConflict(null);
      setAdminRefreshVersion((v) => v + 1);
      setAuditRefreshVersion((v) => v + 1);
    } catch {
      toast.error('خطای ناشناخته رخ داد.');
    } finally {
      setChangeBusy(false);
      setPendingChange(null);
      setStepUpOpen(false);
    }
  }, [pendingChange]);

  const handleStepUpClose = useCallback(() => {
    if (changeBusy) return;
    setStepUpOpen(false);
    setPendingChange(null);
  }, [changeBusy]);

  const tabs: { id: Tab; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { id: 'settings', label: 'تنظیمات امنیتی', icon: SettingsIcon },
    { id: 'admins', label: 'مدیران امنیت', icon: Shield },
    { id: 'audit', label: 'رویدادهای امنیتی', icon: FileText },
    { id: 'lifecycle', label: 'چرخه عمر حساب‌ها', icon: Users },
    { id: 'health', label: 'سلامت سیستم', icon: Activity },
  ];

  return (
    <div className="space-y-4" dir="rtl">
      <div className="flex gap-2 border-b border-gray-100 dark:border-gray-700">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            disabled={changeBusy}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition disabled:opacity-50 ${
              tab === t.id
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
            }`}
          >
            <t.icon className="w-4 h-4" />
            {t.label}
          </button>
        ))}
      </div>

      {conflict && (
        <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700/40 rounded-2xl p-5 space-y-3">
          <h4 className="text-sm font-bold text-amber-800 dark:text-amber-200">تعارض نسخه</h4>
          <div className="text-xs text-amber-700 dark:text-amber-300 space-y-1">
            <p>کاربر: {conflict.targetDisplayName}</p>
            <p>نقش درخواستی: {conflict.requestedValue ? 'اعطا' : 'حذف'}</p>
            <p>نسخه مورد انتظار: {conflict.expectedVersion}</p>
            {conflict.currentVersion !== undefined && <p>نسخه فعلی: {conflict.currentVersion}</p>}
            <p>دلیل تغییر: {conflict.changeReason}</p>
          </div>
          <p className="text-xs text-amber-600 dark:text-amber-400">
            داده‌های جدید بارگذاری شده است. لطفاً تغییرات خود را بازبینی و دوباره اعمال کنید.
          </p>
        </div>
      )}

      <div>
        {tab === 'settings' && <SecuritySettingsConsole />}
        {tab === 'admins' && (
          <SecurityAdminManagement
            onOpenStepUp={handleOpenStepUp}
            refreshVersion={adminRefreshVersion}
            changeBusy={changeBusy}
          />
        )}
        {tab === 'audit' && <SecurityAuditConsole refreshVersion={auditRefreshVersion} />}
        {tab === 'lifecycle' && <AccountLifecycleManagement />}
        {tab === 'health' && <HealthCheckPanel />}
      </div>

      {stepUpOpen && pendingChange && (
        <SecurityStepUpDialog
          open={stepUpOpen}
          purpose="account_security_change"
          title="تأیید تغییر نقش امنیتی"
          description={`برای ${pendingChange.newValue ? 'اعطای' : 'حذف'} نقش مدیر امنیت از ${pendingChange.targetDisplayName}، کد ۶ رقمی را وارد کنید.`}
          confirmLabel="تأیید و اعمال"
          onClose={handleStepUpClose}
          onSuccess={handleStepUpSuccess}
        />
      )}
    </div>
  );
}
