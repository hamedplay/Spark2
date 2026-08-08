import { useState, useCallback } from 'react';
import { Activity, RefreshCw, CircleCheck as CheckCircle2, Circle as XCircle, CircleAlert as AlertCircle } from 'lucide-react';
import { fetchHealthCheck } from '../../auth/services/healthCheckService';
import type { HealthCheckResponse } from '../../auth/types/healthCheck';

export function HealthCheckPanel() {
  const [data, setData] = useState<HealthCheckResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchHealthCheck();
      setData(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'UNKNOWN_ERROR');
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <div className="space-y-4" dir="rtl">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-blue-500" />
          <h3 className="text-sm font-bold text-gray-800 dark:text-white">بررسی سلامت سیستم</h3>
        </div>
        <button
          type="button"
          onClick={run}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 text-sm text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-700 rounded-lg hover:bg-blue-50 dark:hover:bg-blue-900/20 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          {loading ? 'در حال بررسی...' : 'بررسی'}
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700/40 rounded-xl text-sm text-red-700 dark:text-red-300">
          <XCircle className="w-4 h-4 shrink-0" />
          <span>خطا: {error}</span>
        </div>
      )}

      {data && (
        <div className="space-y-4">
          {/* Database */}
          <Section title="پایگاه داده" ok={data.database?.ok ?? false}>
            <StatusRow label="جدول‌ها" ok={data.database?.tables?.all_present ?? false} detail={data.database?.tables?.missing?.length ? `نقص: ${data.database.tables.missing.join(', ')}` : 'همه موجود'} />
            <StatusRow label="RPCها" ok={data.database?.rpcs?.all_present ?? false} detail={data.database?.rpcs?.missing?.length ? `نقص: ${data.database.rpcs.missing.join(', ')}` : 'همه موجود'} />
            <StatusRow label="RLS" ok={data.database?.rls?.all_enabled ?? false} detail={data.database?.rls?.all_enabled ? 'فعال روی همه' : 'غیرفعال روی برخی'} />
            <StatusRow label="SECURITY DEFINER" ok={data.database?.security_definer?.search_path_empty ?? false} detail={data.database?.security_definer?.search_path_empty ? 'search_path تنظیم‌شده' : 'برخی بدون search_path'} />
          </Section>

          {/* Secrets */}
          <Section title="رموز" ok={Object.values(data.database?.secrets ?? {}).every((s) => s === 'ready')}>
            {Object.entries(data.database?.secrets ?? {}).map(([key, val]) => (
              <StatusRow key={key} label={key} ok={val === 'ready'} detail={val === 'ready' ? 'آماده' : 'نیم‌آماده'} />
            ))}
          </Section>

          {/* Transport */}
          <Section title="انتقال" ok={data.transport?.sms === 'ready' || data.transport?.bale === 'ready'}>
            <StatusRow label="SMS" ok={data.transport?.sms === 'ready'} detail={data.transport?.sms === 'ready' ? 'آماده' : 'نیم‌آماده'} />
            <StatusRow label="Bale" ok={data.transport?.bale === 'ready'} detail={data.transport?.bale === 'ready' ? 'آماده' : 'نیم‌آماده'} />
            <StatusRow label="Email" ok={data.transport?.email === 'ready'} detail={data.transport?.email === 'ready' ? 'آماده' : 'نیم‌آماده'} />
          </Section>

          {/* Edge Functions */}
          <Section title="Edge Functions" ok={false}>
            {data.edge_functions?.map((fn) => (
              <StatusRow key={fn.name} label={fn.name} ok={false} detail={fn.status === 'deployed' ? 'deployed' : 'not_verified'} warn={fn.status === 'not_verified'} />
            ))}
          </Section>

          {/* Deprecated Routes */}
          {data.deprecated_routes?.length > 0 && (
            <Section title="مسیرهای منسوخ‌شده" ok={false}>
              {data.deprecated_routes.map((r) => (
                <StatusRow key={r.route} label={r.route} ok={false} detail={`${r.status} — ${r.action}`} warn />
              ))}
            </Section>
          )}
        </div>
      )}
    </div>
  );
}

function Section({ title, ok, children }: { title: string; ok: boolean; children: React.ReactNode }) {
  return (
    <div className="rounded-2xl border border-gray-100 dark:border-gray-700 overflow-hidden">
      <div className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium ${ok ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300' : 'bg-gray-50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-300'}`}>
        {ok ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
        {title}
      </div>
      <div className="divide-y divide-gray-50 dark:divide-gray-700/50">{children}</div>
    </div>
  );
}

function StatusRow({ label, ok, detail, warn }: { label: string; ok: boolean; detail: string; warn?: boolean }) {
  return (
    <div className="flex items-center justify-between px-4 py-2.5 text-sm">
      <span className="text-gray-600 dark:text-gray-400 font-mono text-xs" dir="ltr">{label}</span>
      <div className="flex items-center gap-2">
        <span className="text-xs text-gray-400">{detail}</span>
        {ok ? (
          <CheckCircle2 className="w-4 h-4 text-green-500" />
        ) : warn ? (
          <AlertCircle className="w-4 h-4 text-amber-500" />
        ) : (
          <XCircle className="w-4 h-4 text-red-500" />
        )}
      </div>
    </div>
  );
}
