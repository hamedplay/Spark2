import { useState, useEffect, useCallback } from 'react';
import { supabase } from '../../../lib/supabase';

interface SessionInfo {
  session_id: string;
  created_at: string;
  last_activity_at: string;
  idle_expiry_at: string;
  absolute_expiry_at: string;
  revoked_at: string | null;
  revoke_reason: string | null;
  device_summary: string;
  status: string;
}

export function SessionManagementPanel() {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);

  const loadSessions = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { data, error: fnError } = await supabase.functions.invoke('session-management', {
        method: 'POST',
        body: { mode: 'list' },
      });
      if (fnError || !data?.ok) throw new Error(data?.error ?? 'LOAD_FAILED');
      setSessions(data.sessions ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'LOAD_FAILED');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadSessions(); }, [loadSessions]);

  const revokeOne = async (sessionId: string) => {
    setRevoking(sessionId);
    try {
      const { data, error: fnError } = await supabase.functions.invoke('session-management', {
        method: 'POST',
        body: { mode: 'revoke', session_id: sessionId },
      });
      if (fnError || !data?.ok) throw new Error(data?.error ?? 'REVOKE_FAILED');
      await loadSessions();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'REVOKE_FAILED');
    } finally {
      setRevoking(null);
    }
  };

  const revokeAll = async () => {
    setRevoking('all');
    try {
      const { data, error: fnError } = await supabase.functions.invoke('session-management', {
        method: 'POST',
        body: { mode: 'revoke_all' },
      });
      if (fnError || !data?.ok) throw new Error(data?.error ?? 'REVOKE_FAILED');
      await loadSessions();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'REVOKE_FAILED');
    } finally {
      setRevoking(null);
    }
  };

  if (loading) return <div className="p-4 text-sm text-gray-500">در حال بارگذاری...</div>;
  if (error) return <div className="p-4 text-sm text-red-600">{error}</div>;

  return (
    <div className="space-y-4" dir="rtl">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">مدیریت نشست‌ها</h3>
        <button
          onClick={revokeAll}
          disabled={revoking === 'all'}
          className="px-3 py-1.5 text-sm text-red-600 border border-red-300 rounded-lg hover:bg-red-50 disabled:opacity-50"
        >
          {revoking === 'all' ? '...' : 'لغو همه نشست‌ها'}
        </button>
      </div>

      {sessions.length === 0 ? (
        <p className="text-sm text-gray-500">نشستی یافت نشد.</p>
      ) : (
        <div className="space-y-2">
          {sessions.map((s) => (
            <div
              key={s.session_id}
              className="flex items-center justify-between p-3 border rounded-lg"
            >
              <div className="space-y-1">
                <div className="text-sm font-medium">{s.device_summary || 'ناشناخته'}</div>
                <div className="text-xs text-gray-500">
                  ایجاد: {new Date(s.created_at).toLocaleString('fa-IR')}
                </div>
                <div className="text-xs text-gray-500">
                  آخرین فعالیت: {new Date(s.last_activity_at).toLocaleString('fa-IR')}
                </div>
                <span
                  className={`inline-block px-2 py-0.5 text-xs rounded-full ${
                    s.status === 'active'
                      ? 'bg-green-100 text-green-700'
                      : s.status === 'revoked'
                      ? 'bg-red-100 text-red-700'
                      : 'bg-gray-100 text-gray-600'
                  }`}
                >
                  {s.status === 'active' ? 'فعال' : s.status === 'revoked' ? 'لغو شده' : 'منقضی شده'}
                </span>
              </div>
              {s.status === 'active' && (
                <button
                  onClick={() => revokeOne(s.session_id)}
                  disabled={revoking === s.session_id}
                  className="px-3 py-1 text-sm text-red-600 border border-red-300 rounded-lg hover:bg-red-50 disabled:opacity-50"
                >
                  {revoking === s.session_id ? '...' : 'لغو'}
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
