import { useState, useEffect, useRef } from 'react';
import { User, Mail, Phone, Building, MapPin, Camera, Loader as Loader2, Save, Briefcase, Hash, Users, CreditCard, ChevronDown, ChevronUp, CircleCheck as CheckCircle2, Crown, Building2, Link2, AtSign } from 'lucide-react';
import { supabase } from '../lib/supabase';
import toast from 'react-hot-toast';

import { JalaaliDateInput } from './Profile/JalaaliDateInput';
import { Field } from './Profile/Field';
import { BaleConnectSection } from './Profile/BaleConnectSection';
import { TelegramConnectSection } from './Profile/TelegramConnectSection';
import type { OrgPositionInfo, Profile } from './Profile/types';
import { empty, LEVEL_LABELS, inp, inpDisabled } from './Profile/types';
import { TotpFactorManager } from '../features/auth/components/TotpFactorManager';
import { SessionManagementPanel } from '../features/auth/components/SessionManagementPanel';

export function ProfilePage() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [avatarProcessing, setAvatarProcessing] = useState(false);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [openSection, setOpenSection] = useState<'personal' | 'work' | 'social' | 'calendar' | 'security'>('personal');
  const [saved, setSaved] = useState(false);
  const [orgPositionInfo, setOrgPositionInfo] = useState<OrgPositionInfo | null>(null);
  const avatarPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => { fetchProfile(); }, []);

  useEffect(() => {
    return () => { stopAvatarPoll(); };
  }, []);

  const fetchOrgInfo = async (positionId: string | null) => {
    const [{ data: posData }, { data: allPos }, { data: allUnits }, { data: orgData }] = await Promise.all([
      positionId
        ? supabase.from('org_positions').select('id,title,level,color,icon,unit_id,parent_position_id').eq('id', positionId).maybeSingle()
        : Promise.resolve({ data: null }),
      supabase.from('org_positions').select('id,title,level,color,icon,unit_id').order('level'),
      supabase.from('org_units').select('id,name').order('name'),
      supabase.from('org_organizations').select('name').maybeSingle(),
    ]);
    if (posData) {
      const unit = (allUnits || []).find((u: any) => u.id === posData.unit_id);
      const parent = posData.parent_position_id
        ? (allPos || []).find((p: any) => p.id === posData.parent_position_id)
        : null;
      setOrgPositionInfo({
        id: posData.id, title: posData.title, level: posData.level,
        color: posData.color, icon: posData.icon,
        unit_name: unit?.name, parent_title: parent?.title,
      });
      // Auto-fill organization from org_organizations (the company name), not the unit name
      if (orgData?.name) {
        setProfile(p => p ? { ...p, organization: orgData.name } : p);
      }
    } else {
      setOrgPositionInfo(null);
    }
  };

  const fetchProfile = async () => {
    try {
      setLoading(true);
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('کاربر احراز هویت نشده است');

      const { data, error } = await supabase
        .from('profiles').select('*').eq('user_id', user.id).maybeSingle();
      if (error && error.code !== 'PGRST116') throw error;

      if (data) {
        setProfile({ ...empty, ...data } as unknown as Profile);
        fetchOrgInfo(data.primary_position_id || null);
      } else {
        const newProfile = { ...empty, user_id: user.id, email: user.email ?? '' };
        const { data: created, error: ce } = await supabase
          .from('profiles').insert([newProfile]).select().single();
        if (ce) throw ce;
        setProfile(created as unknown as Profile);
      }
    } catch (error: any) {
      toast.error(error.message || 'خطا در دریافت پروفایل');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!profile) return;
    setSaving(true);
    try {
      // date fields: send null instead of empty string to avoid Postgres date parse error
      const payload: Pick<Profile, 'full_name' | 'national_id' | 'birth_date' | 'gender' | 'city' | 'bio' | 'employee_id' | 'hire_date' | 'location'> & { updated_at: string } = {
        full_name: profile.full_name,
        national_id: profile.national_id,
        birth_date: profile.birth_date ?? null,
        gender: profile.gender,
        city: profile.city,
        bio: profile.bio,
        employee_id: profile.employee_id,
        hire_date: profile.hire_date ?? null,
        location: profile.location,
        updated_at: new Date().toISOString(),
      };
      const { error } = await supabase.from('profiles').update(payload).eq('id', profile.id);
      if (error) throw error;
      toast.success('پروفایل با موفقیت ذخیره شد');
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (error: any) {
      toast.error(error.message || 'خطا در ذخیره پروفایل');
    } finally {
      setSaving(false);
    }
  };

  const stopAvatarPoll = () => {
    if (avatarPollRef.current) { clearInterval(avatarPollRef.current); avatarPollRef.current = null; }
  };

  const startAvatarPoll = (jobId: string) => {
    stopAvatarPoll();
    const startTime = Date.now();
    const maxMs = 60_000;
    const intervalMs = 2_000;

    avatarPollRef.current = setInterval(async () => {
      if (Date.now() - startTime > maxMs) {
        stopAvatarPoll();
        setAvatarProcessing(false);
        toast.error('پردازش تصویر طولانی شد. لطفاً بعداً دوباره بررسی کنید.');
        return;
      }
      try {
        const { data, error } = await supabase
          .from('avatar_jobs')
          .select('status')
          .eq('id', jobId)
          .maybeSingle();
        if (error) throw error;
        if (!data) return;

        if (data.status === 'completed') {
          stopAvatarPoll();
          setAvatarProcessing(false);
          await fetchProfile();
          toast.success('تصویر پروفایل به‌روزرسانی شد');
        } else if (data.status === 'failed') {
          stopAvatarPoll();
          setAvatarProcessing(false);
          toast.error('پردازش تصویر ناموفق بود. لطفاً فایل دیگری امتحان کنید.');
        }
      } catch {
        // transient poll error — keep polling
      }
    }, intervalMs);
  };

  const handleAvatarUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !profile) return;

    // Stop any existing poll (new file selected)
    stopAvatarPoll();

    // UX validation (not the security boundary)
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowedTypes.includes(file.type)) {
      toast.error('فقط فرمت‌های JPEG، PNG و WebP مجاز هستند');
      e.target.value = '';
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      toast.error('حجم فایل نباید بیشتر از ۲ مگابایت باشد');
      e.target.value = '';
      return;
    }

    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);

      const { data, error } = await supabase.functions.invoke('avatar-upload', {
        body: formData,
      });

      if (error) throw error;
      if (!data?.job_id) throw new Error('پاسخ نامعتبر از سرور');

      setUploading(false);
      setAvatarProcessing(true);
      toast.success('تصویر ارسال شد. در حال پردازش...');
      startAvatarPoll(data.job_id);
    } catch (error: any) {
      setUploading(false);
      toast.error('خطا در آپلود تصویر. لطفاً دوباره تلاش کنید.');
    } finally {
      e.target.value = '';
    }
  };

  const set = (field: keyof typeof empty, value: string) =>
    setProfile(p => p ? { ...p, [field]: value } : p);

  const SectionHeader = ({ id, title, subtitle }: { id: 'personal' | 'work' | 'social' | 'calendar' | 'security'; title: string; subtitle: string }) => (
    <button
      type="button"
      onClick={() => setOpenSection(id)}
      className="w-full flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700/50 rounded-xl hover:bg-gray-100 dark:hover:bg-gray-700 transition"
    >
      <div className="text-right">
        <p className="font-semibold text-gray-800 dark:text-white text-sm">{title}</p>
        <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{subtitle}</p>
      </div>
      {openSection === id
        ? <ChevronUp className="w-4 h-4 text-gray-400" />
        : <ChevronDown className="w-4 h-4 text-gray-400" />}
    </button>
  );

  if (loading) {
    return (
      <div className="flex justify-center items-center h-96">
        <Loader2 className="w-10 h-10 animate-spin text-teal-500" />
      </div>
    );
  }

  if (!profile) return null;

  const initials = profile.full_name
    ? profile.full_name.split(' ').map(w => w[0]).slice(0, 2).join('')
    : profile.email[0]?.toUpperCase() || '?';

  return (
    <div className="max-w-3xl mx-auto">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">پروفایل کاربری</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">اطلاعات حساب و سازمانی خود را مدیریت کنید</p>
      </div>

      {/* Avatar card */}
      <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-gray-100 dark:border-gray-700 p-6 mb-4">
        <div className="flex items-center gap-6">
          <div className="relative flex-shrink-0">
            <div className="w-24 h-24 rounded-2xl overflow-hidden bg-teal-100 dark:bg-teal-900/30">
              {profile.avatar_url ? (
                <img src={profile.avatar_url} alt="avatar" className="w-full h-full object-cover" />
              ) : (
                <div className="w-full h-full flex items-center justify-center">
                  <span className="text-2xl font-bold text-teal-600 dark:text-teal-400">{initials}</span>
                </div>
              )}
            </div>
            <label className={`absolute -bottom-2 -left-2 w-8 h-8 bg-teal-500 hover:bg-teal-600 rounded-xl flex items-center justify-center cursor-pointer shadow-md transition ${(uploading || avatarProcessing) ? 'opacity-60 pointer-events-none' : ''}`}>
              {(uploading || avatarProcessing) ? <Loader2 className="w-4 h-4 text-white animate-spin" /> : <Camera className="w-4 h-4 text-white" />}
              <input type="file" accept="image/jpeg,image/png,image/webp" onChange={handleAvatarUpload} className="hidden" disabled={uploading || avatarProcessing} />
            </label>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              {profile.full_name || 'نام تعریف نشده'}
            </h3>
            <p className="text-sm text-gray-500 dark:text-gray-400">{profile.email}</p>
            {avatarProcessing && (
              <p className="text-xs text-teal-600 dark:text-teal-400 mt-1 flex items-center gap-1">
                <Loader2 className="w-3 h-3 animate-spin" />
                در حال پردازش تصویر...
              </p>
            )}
            {profile.position && profile.organization && (
              <p className="text-sm text-teal-600 dark:text-teal-400 mt-1">
                {profile.position} — {profile.organization}
              </p>
            )}
            {profile.updated_at && (
              <p className="text-xs text-gray-400 mt-1">
                آخرین به‌روزرسانی: {new Date(profile.updated_at).toLocaleString('fa-IR')}
              </p>
            )}
          </div>
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-4">

        {/* Personal info */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-gray-100 dark:border-gray-700 overflow-hidden">
          <SectionHeader id="personal" title="اطلاعات شخصی" subtitle="نام، مشخصات فردی، ارتباطی" />
          {openSection === 'personal' && (
            <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-5">
              <Field label="نام و نام خانوادگی" icon={User}>
                <input type="text" value={profile.full_name} onChange={e => set('full_name', e.target.value)}
                  className={inp} placeholder="نام کامل" />
              </Field>

              <Field label="نام کاربری" icon={AtSign}>
                <input type="text" value={profile.username || ''} disabled
                  className={inpDisabled} placeholder="username_123" dir="ltr" />
                <p className="text-xs text-gray-400 mt-1">نام کاربری توسط مدیر تعیین می‌شود و قابل تغییر نیست</p>
              </Field>

              <Field label="ایمیل" icon={Mail}>
                <input type="email" value={profile.email} disabled className={inpDisabled} />
              </Field>

              <Field label="شماره موبایل" icon={Phone}>
                <input type="tel" value={profile.phone} disabled
                  className={inpDisabled} placeholder="09xxxxxxxxx" dir="ltr" />
                <p className="text-xs text-gray-400 mt-1">برای تغییر شماره موبایل از فرآیند تأیید شماره استفاده کنید یا با مدیر سامانه تماس بگیرید.</p>
              </Field>

              <Field label="کد ملی" icon={CreditCard}>
                <input type="text" value={profile.national_id} onChange={e => set('national_id', e.target.value)}
                  className={inp} placeholder="کد ملی ۱۰ رقمی" dir="ltr" maxLength={10} />
              </Field>

              <div>
                <label className="block text-sm font-medium text-gray-600 dark:text-gray-400 mb-1.5">
                  تاریخ تولد (شمسی)
                </label>
                <JalaaliDateInput value={profile.birth_date || ''} onChange={v => set('birth_date', v)} className="w-full" />
              </div>

              <Field label="جنسیت" icon={Users}>
                <select value={profile.gender} onChange={e => set('gender', e.target.value)} className={inp}>
                  <option value="">انتخاب کنید</option>
                  <option value="male">مرد</option>
                  <option value="female">زن</option>
                  <option value="other">سایر</option>
                </select>
              </Field>

              <Field label="شهر" icon={MapPin}>
                <input type="text" value={profile.city} onChange={e => set('city', e.target.value)}
                  className={inp} placeholder="شهر محل سکونت" />
              </Field>

              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-gray-600 dark:text-gray-400 mb-1.5">درباره من</label>
                <textarea value={profile.bio} onChange={e => set('bio', e.target.value)} rows={3}
                  className="w-full px-4 py-2.5 border border-gray-200 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-transparent transition text-sm resize-none"
                  placeholder="چند جمله درباره خودتان بنویسید..." />
              </div>
            </div>
          )}
        </div>

        {/* Work/org section */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-gray-100 dark:border-gray-700 overflow-hidden">
          <SectionHeader id="work" title="اطلاعات سازمانی" subtitle="سازمان، سمت، واحد و مشخصات شغلی" />
          {openSection === 'work' && (
            <div className="p-6 space-y-5">

              {/* Org chart card */}
              {orgPositionInfo ? (
                <div className="flex items-center gap-4 p-4 rounded-2xl border-2"
                  style={{ borderColor: orgPositionInfo.color + '60', backgroundColor: orgPositionInfo.color + '0d' }}>
                  <div className="w-12 h-12 rounded-2xl flex items-center justify-center text-2xl flex-shrink-0"
                    style={{ backgroundColor: orgPositionInfo.color + '20' }}>
                    {orgPositionInfo.icon || '💼'}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-gray-800 dark:text-white">{orgPositionInfo.title}</span>
                      <span className="text-xs px-2 py-0.5 rounded-full text-white font-medium"
                        style={{ backgroundColor: orgPositionInfo.color }}>
                        {LEVEL_LABELS[orgPositionInfo.level] || `سطح ${orgPositionInfo.level}`}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-xs text-gray-500 dark:text-gray-400 flex-wrap">
                      {orgPositionInfo.unit_name && (
                        <span className="flex items-center gap-1">
                          <Building2 className="w-3 h-3" />{orgPositionInfo.unit_name}
                        </span>
                      )}
                      {orgPositionInfo.parent_title && (
                        <span className="flex items-center gap-1">
                          <Crown className="w-3 h-3" />گزارش به: {orgPositionInfo.parent_title}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="text-xs text-gray-400 flex items-center gap-1 flex-shrink-0">
                    <Link2 className="w-3 h-3" /> از چارت سازمانی
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-3 p-4 rounded-2xl border border-dashed border-gray-200 dark:border-gray-600 text-sm text-gray-400 dark:text-gray-500">
                  <Building2 className="w-5 h-5 flex-shrink-0" />
                  <span>سمت سازمانی از طریق ساختار سازمانی تخصیص نیافته است. ادمین می‌تواند از پنل پیکربندی → ساختار سازمانی سمت تخصیص دهد.</span>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <Field label="نام سازمان / شرکت" icon={Building}>
                  <input type="text" value={profile.organization}
                    onChange={e => set('organization', e.target.value)}
                    className={(orgPositionInfo || profile.primary_position_id) ? inpDisabled : inp}
                    readOnly={!!(orgPositionInfo || profile.primary_position_id)}
                    title={(orgPositionInfo || profile.primary_position_id) ? 'این فیلد از ساختار سازمانی تکمیل می‌شود' : ''}
                    placeholder="نام سازمان یا شرکت" />
                </Field>

                <Field label="سمت / عنوان شغلی" icon={Briefcase}>
                  <input type="text" value={profile.position} disabled className={inpDisabled}
                    title="این فیلد توسط ساختار سازمانی مدیریت می‌شود" />
                </Field>

                <Field label="واحد / دپارتمان" icon={Users}>
                  <input type="text" value={profile.department} disabled className={inpDisabled}
                    title="این فیلد توسط ساختار سازمانی مدیریت می‌شود" />
                </Field>

                <Field label="کد پرسنلی" icon={Hash}>
                  <input type="text" value={profile.employee_id} onChange={e => set('employee_id', e.target.value)}
                    className={inp} placeholder="شماره پرسنلی" dir="ltr" />
                </Field>

                <div>
                  <label className="block text-sm font-medium text-gray-600 dark:text-gray-400 mb-1.5">
                    تاریخ استخدام (شمسی)
                  </label>
                  <JalaaliDateInput value={profile.hire_date || ''} onChange={v => set('hire_date', v)} className="w-full" />
                </div>

                <Field label="موقعیت مکانی (دفتر)" icon={MapPin}>
                  <input type="text" value={profile.location} onChange={e => set('location', e.target.value)}
                    className={inp} placeholder="آدرس دفتر یا محل کار" />
                </Field>
              </div>

              {(profile.position || profile.department) && (
                <div className="flex items-start gap-2 p-3 rounded-xl bg-blue-50 dark:bg-blue-900/20 border border-blue-100 dark:border-blue-800 text-xs text-blue-700 dark:text-blue-300">
                  <Building2 className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
                  فیلدهای سمت و واحد توسط ادمین از طریق ساختار سازمانی تنظیم می‌شوند و قابل ویرایش نیستند.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Social / links */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-gray-100 dark:border-gray-700 overflow-hidden">
          <SectionHeader id="social" title="شبکه‌های اجتماعی و پیام‌رسان" subtitle="اتصال به پیام‌رسان‌های بله و تلگرام" />
          {openSection === 'social' && (
            <div className="p-6 space-y-5">
              <BaleConnectSection />
              <TelegramConnectSection />
            </div>
          )}
        </div>

        {/* Save */}
        <div className="flex justify-end pb-4">
          <button type="submit" disabled={saving}
            className="flex items-center gap-2 bg-teal-500 hover:bg-teal-600 text-white px-8 py-2.5 rounded-xl font-medium transition disabled:opacity-60 shadow-sm">
            {saving ? <Loader2 className="w-4 h-4 animate-spin" />
              : saved ? <CheckCircle2 className="w-4 h-4" />
              : <Save className="w-4 h-4" />}
            {saving ? 'در حال ذخیره...' : saved ? 'ذخیره شد' : 'ذخیره تغییرات'}
          </button>
        </div>
      </form>

      {/* Security / TOTP — outside profile form to prevent submit on Enter */}
      <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-gray-100 dark:border-gray-700 overflow-hidden mt-4">
        <SectionHeader id="security" title="امنیت حساب" subtitle="مدیریت احراز هویت دومرحله‌ای (TOTP)" />
        {openSection === 'security' && (
          <div className="p-6 space-y-6">
            <TotpFactorManager />
            <div className="border-t border-gray-100 dark:border-gray-700 pt-6">
              <SessionManagementPanel />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
