/**
 * Skills Management Page
 * 展示文件系统承载的可插拔审计知识包（只读 + reload）
 * Cyberpunk Terminal Aesthetic — 与 PromptManager / AuditRules 一致
 */

import { useState, useEffect, useMemo } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { toast } from 'sonner';
import {
  Sparkles,
  Package,
  RefreshCw,
  Search,
  Terminal,
  FileText,
  BookOpen,
  ExternalLink,
  ShieldAlert,
  Layers,
  Folder,
  Activity,
  GitBranch,
  Upload,
  Store,
  Trash2,
  Download,
  BellRing,
} from 'lucide-react';
import {
  listSkills,
  getSkill,
  getSkillReference,
  reloadSkills,
  importSkillFromGit,
  importSkillFromZip,
  fetchRegistrySkills,
  installSkillFromRegistry,
  deleteSkill,
  updateSkill,
  checkSkillUpdates,
  type SkillSummary,
  type SkillDetail,
  type RegistrySkillItem,
  type SkillUpdateCheckItem,
} from '@/shared/api/skills';

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'cyber-badge-critical',
  high: 'cyber-badge-danger',
  medium: 'cyber-badge-warning',
  low: 'cyber-badge-info',
  info: 'cyber-badge-muted',
};

function formatTargets(targets: Record<string, unknown> | undefined): string[] {
  if (!targets) return [];
  const out: string[] = [];
  for (const [k, v] of Object.entries(targets)) {
    if (Array.isArray(v)) {
      for (const item of v) out.push(`${k}:${item}`);
    } else if (v !== null && v !== undefined && typeof v !== 'object') {
      out.push(`${k}:${String(v)}`);
    }
  }
  return out;
}

export default function Skills() {
  const [skills, setSkills] = useState<SkillSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [reloading, setReloading] = useState(false);
  const [keyword, setKeyword] = useState('');
  const [category, setCategory] = useState<string>('all');

  const [detailOpen, setDetailOpen] = useState(false);
  const [detail, setDetail] = useState<SkillDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [refOpen, setRefOpen] = useState(false);
  const [refContent, setRefContent] = useState<{ path: string; content: string } | null>(null);
  const [refLoading, setRefLoading] = useState(false);

  // Import from Git
  const [gitOpen, setGitOpen] = useState(false);
  const [gitUrl, setGitUrl] = useState('');
  const [gitName, setGitName] = useState('');
  const [gitBranch, setGitBranch] = useState('');
  const [gitSubdir, setGitSubdir] = useState('');
  const [gitSubmitting, setGitSubmitting] = useState(false);

  // Import from Zip
  const [zipSubmitting, setZipSubmitting] = useState(false);

  // Registry browser
  const [registryOpen, setRegistryOpen] = useState(false);
  const [registryUrl, setRegistryUrl] = useState('');
  const [registryItems, setRegistryItems] = useState<RegistrySkillItem[]>([]);
  const [registryLoading, setRegistryLoading] = useState(false);
  const [installingName, setInstallingName] = useState<string | null>(null);

  // Delete confirmation
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Update
  const [updatingName, setUpdatingName] = useState<string | null>(null);
  const [checkingUpdates, setCheckingUpdates] = useState(false);
  const [updateInfo, setUpdateInfo] = useState<Record<string, SkillUpdateCheckItem>>({});

  const load = async () => {
    try {
      setLoading(true);
      const params: { category?: string; keyword?: string } = {};
      if (category !== 'all') params.category = category;
      if (keyword.trim()) params.keyword = keyword.trim();
      const items = await listSkills(params);
      setSkills(items);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || '加载 Skills 失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSearch = () => {
    load();
  };

  const handleReload = async () => {
    try {
      setReloading(true);
      const res = await reloadSkills();
      toast.success(`已重载 ${res.count} 个 Skill 包`);
      await load();
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || '重载失败');
    } finally {
      setReloading(false);
    }
  };

  const openDetail = async (name: string) => {
    setDetailOpen(true);
    setDetail(null);
    setDetailLoading(true);
    try {
      const d = await getSkill(name);
      setDetail(d);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || '加载 Skill 详情失败');
      setDetailOpen(false);
    } finally {
      setDetailLoading(false);
    }
  };

  const openReference = async (skillName: string, refPath: string) => {
    setRefOpen(true);
    setRefContent(null);
    setRefLoading(true);
    try {
      const r = await getSkillReference(skillName, refPath);
      setRefContent({ path: r.reference, content: r.content });
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || '加载引用文档失败');
      setRefOpen(false);
    } finally {
      setRefLoading(false);
    }
  };

  const resetGitForm = () => {
    setGitUrl('');
    setGitName('');
    setGitBranch('');
    setGitSubdir('');
  };

  const handleImportFromGit = async () => {
    if (!gitUrl.trim()) {
      toast.error('请填写 Git URL');
      return;
    }
    setGitSubmitting(true);
    try {
      const res = await importSkillFromGit({
        git_url: gitUrl.trim(),
        name: gitName.trim() || undefined,
        branch: gitBranch.trim() || undefined,
        subdir: gitSubdir.trim() || undefined,
      });
      toast.success(`已导入 Skill: ${res.name} v${res.version}`);
      setGitOpen(false);
      resetGitForm();
      await load();
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Git 导入失败');
    } finally {
      setGitSubmitting(false);
    }
  };

  const handleImportFromZip = async (file: File) => {
    setZipSubmitting(true);
    try {
      const res = await importSkillFromZip(file);
      toast.success(`已导入 Skill: ${res.name} v${res.version}`);
      await load();
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Zip 导入失败');
    } finally {
      setZipSubmitting(false);
    }
  };

  const handleOpenRegistry = async () => {
    setRegistryOpen(true);
    setRegistryItems([]);
    setRegistryLoading(true);
    try {
      const res = await fetchRegistrySkills(registryUrl.trim() || undefined);
      setRegistryItems(res.skills || []);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || '拉取 Registry 失败');
    } finally {
      setRegistryLoading(false);
    }
  };

  const handleRefreshRegistry = async () => {
    setRegistryLoading(true);
    setRegistryItems([]);
    try {
      const res = await fetchRegistrySkills(registryUrl.trim() || undefined);
      setRegistryItems(res.skills || []);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || '拉取 Registry 失败');
    } finally {
      setRegistryLoading(false);
    }
  };

  const handleInstallFromRegistry = async (name: string) => {
    setInstallingName(name);
    try {
      const res = await installSkillFromRegistry(name, registryUrl.trim() || undefined);
      toast.success(`已安装 Skill: ${res.name} v${res.version}`);
      await load();
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || '安装失败');
    } finally {
      setInstallingName(null);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await deleteSkill(deleteTarget);
      toast.success(`已删除 Skill: ${deleteTarget}`);
      setDeleteTarget(null);
      await load();
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || '删除失败');
    } finally {
      setDeleting(false);
    }
  };

  const handleUpdate = async (name: string) => {
    setUpdatingName(name);
    try {
      const res = await updateSkill(name);
      toast.success(`已更新 Skill: ${res.name} v${res.version}`);
      // clear this skill's update flag
      setUpdateInfo((prev) => {
        const next = { ...prev };
        delete next[name];
        return next;
      });
      await load();
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || '更新失败（需要该 Skill 记录了 git 源）');
    } finally {
      setUpdatingName(null);
    }
  };

  const handleCheckUpdates = async () => {
    setCheckingUpdates(true);
    try {
      const res = await checkSkillUpdates();
      const map: Record<string, SkillUpdateCheckItem> = {};
      res.items.forEach((it) => (map[it.name] = it));
      setUpdateInfo(map);
      if (res.updates_available > 0) {
        toast.success(`发现 ${res.updates_available} 个 Skill 有可用更新`);
      } else if (res.count === 0) {
        toast('没有 git 来源的 Skill，无需检查更新');
      } else {
        toast.success('所有 git 来源的 Skill 都是最新的');
      }
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || '检查更新失败');
    } finally {
      setCheckingUpdates(false);
    }
  };

  const categories = useMemo(() => {
    const s = new Set<string>();
    skills.forEach((sk) => sk.category && s.add(sk.category));
    return Array.from(s).sort();
  }, [skills]);

  const stats = useMemo(() => {
    const totalRefs = skills.reduce((sum, s) => sum + (s.reference_count || 0), 0);
    const totalScripts = skills.reduce((sum, s) => sum + (s.script_count || 0), 0);
    return { total: skills.length, totalRefs, totalScripts, categories: categories.length };
  }, [skills, categories]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen cyber-bg-elevated">
        <div className="text-center space-y-4">
          <div className="loading-spinner mx-auto" />
          <p className="text-muted-foreground font-mono text-sm uppercase tracking-wider">加载中...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6 cyber-bg-elevated min-h-screen font-mono relative">
      <div className="absolute inset-0 cyber-grid-subtle pointer-events-none" />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 relative z-10">
        <div className="cyber-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="stat-label">Skill 总数</p>
              <p className="stat-value text-primary">{stats.total}</p>
            </div>
            <div className="stat-icon text-primary">
              <Package className="w-6 h-6" />
            </div>
          </div>
        </div>
        <div className="cyber-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="stat-label">Category 数</p>
              <p className="stat-value text-sky-400">{stats.categories}</p>
            </div>
            <div className="stat-icon text-sky-400">
              <Layers className="w-6 h-6" />
            </div>
          </div>
        </div>
        <div className="cyber-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="stat-label">Reference 文档</p>
              <p className="stat-value text-emerald-400">{stats.totalRefs}</p>
            </div>
            <div className="stat-icon text-emerald-400">
              <BookOpen className="w-6 h-6" />
            </div>
          </div>
        </div>
        <div className="cyber-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="stat-label">Script 数</p>
              <p className="stat-value text-amber-400">{stats.totalScripts}</p>
            </div>
            <div className="stat-icon text-amber-400">
              <Activity className="w-6 h-6" />
            </div>
          </div>
        </div>
      </div>

      {/* Action Bar */}
      <div className="cyber-card p-0 relative z-10">
        <div className="cyber-card-header">
          <Terminal className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-bold uppercase tracking-wider text-foreground">Skills 知识包</h3>
          <span className="text-xs text-muted-foreground ml-3 normal-case">
            文件系统承载 · 只读 + Reload · SKILL.md 格式
          </span>
          <div className="ml-auto flex gap-2 flex-wrap">
            <Button
              onClick={() => setGitOpen(true)}
              className="cyber-btn-primary h-9"
            >
              <GitBranch className="w-4 h-4 mr-2" />
              从 Git 导入
            </Button>
            <label className="cursor-pointer">
              <input
                type="file"
                accept=".zip"
                className="hidden"
                disabled={zipSubmitting}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleImportFromZip(f);
                  e.target.value = '';
                }}
              />
              <span className="cyber-btn-primary h-9 inline-flex items-center px-4 rounded text-sm font-medium">
                <Upload className={`w-4 h-4 mr-2 ${zipSubmitting ? 'animate-spin' : ''}`} />
                上传 Zip
              </span>
            </label>
            <Button
              onClick={handleOpenRegistry}
              className="cyber-btn-primary h-9"
            >
              <Store className="w-4 h-4 mr-2" />
              Registry 浏览
            </Button>
            <Button
              onClick={handleCheckUpdates}
              disabled={checkingUpdates}
              className="cyber-btn-primary h-9"
            >
              <BellRing className={`w-4 h-4 mr-2 ${checkingUpdates ? 'animate-spin' : ''}`} />
              检查更新
            </Button>
            <Button
              onClick={handleReload}
              disabled={reloading}
              className="cyber-btn-primary h-9"
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${reloading ? 'animate-spin' : ''}`} />
              重载 Skills
            </Button>
          </div>
        </div>

        <div className="p-4 flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[200px] space-y-2">
            <Label className="text-xs font-bold text-muted-foreground uppercase">关键词搜索</Label>
            <div className="flex gap-2">
              <Input
                value={keyword}
                onChange={(e) => setKeyword(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                placeholder="匹配 name / description / tags / body"
                className="cyber-input"
              />
              <Button onClick={handleSearch} className="cyber-btn-primary h-10">
                <Search className="w-4 h-4" />
              </Button>
            </div>
          </div>
          <div className="w-48 space-y-2">
            <Label className="text-xs font-bold text-muted-foreground uppercase">Category</Label>
            <Select
              value={category}
              onValueChange={(v) => {
                setCategory(v);
                // trigger reload after state change
                setTimeout(() => load(), 0);
              }}
            >
              <SelectTrigger className="cyber-input">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="cyber-dialog border-border">
                <SelectItem value="all">全部</SelectItem>
                {categories.map((c) => (
                  <SelectItem key={c} value={c}>
                    {c}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      {/* Skill Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 relative z-10">
        {skills.length === 0 ? (
          <div className="col-span-full cyber-card p-16">
            <div className="empty-state">
              <Package className="empty-state-icon" />
              <p className="empty-state-title">暂无 Skill 包</p>
              <p className="empty-state-description">
                将 SKILL.md 包放入 skills/ 目录后点击"重载 Skills"
              </p>
              <Button className="cyber-btn-primary h-12 px-8 mt-6" onClick={handleReload}>
                <RefreshCw className="w-5 h-5 mr-2" />
                重载 Skills
              </Button>
            </div>
          </div>
        ) : (
          skills.map((s) => {
            const targets = formatTargets(s.targets);
            const upd = updateInfo[s.name];
            const hasUpdate = !!upd?.has_update;
            const src = s.source;
            const hasGitSource = !!src?.git_url;
            const updatedAt = src?.updated_at || src?.installed_at;
            return (
              <div
                key={s.name}
                className="cyber-card p-0 cursor-pointer hover:border-primary/40 transition-colors"
                onClick={() => openDetail(s.name)}
              >
                <div className="p-5 border-b border-border">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="w-10 h-10 bg-muted border border-border flex items-center justify-center rounded flex-shrink-0">
                        <Sparkles className="w-5 h-5 text-primary" />
                      </div>
                      <div className="min-w-0">
                        <h3 className="font-bold text-base text-foreground uppercase truncate">
                          {s.name}
                        </h3>
                        <p className="text-xs text-muted-foreground line-clamp-1">
                          {s.description || '(无描述)'}
                        </p>
                      </div>
                    </div>
                    <Badge className="cyber-badge-muted flex-shrink-0 ml-2">v{s.version}</Badge>
                  </div>
                  <div className="flex flex-wrap gap-2 items-center">
                    {s.category && <Badge className="cyber-badge-info">{s.category}</Badge>}
                    {s.severity_focus.map((sev) => (
                      <Badge
                        key={sev}
                        className={SEVERITY_COLOR[sev.toLowerCase()] || 'cyber-badge-muted'}
                      >
                        {sev}
                      </Badge>
                    ))}
                    {hasGitSource && (
                      <Badge className="cyber-badge-muted" title={src?.git_url}>
                        <GitBranch className="w-3 h-3 mr-1" />
                        {src?.branch || 'git'}
                      </Badge>
                    )}
                    {hasUpdate && (
                      <Badge className="cyber-badge-warning animate-pulse" title={`local ${upd?.local_commit?.slice(0, 7) || '—'} → remote ${upd?.remote_commit?.slice(0, 7) || '—'}`}>
                        <BellRing className="w-3 h-3 mr-1" />
                        有新版本
                      </Badge>
                    )}
                  </div>
                </div>

                <div className="p-4 space-y-3">
                  {targets.length > 0 && (
                    <div className="text-xs text-muted-foreground">
                      <span className="font-bold uppercase mr-2">Targets:</span>
                      <span className="text-emerald-400">{targets.slice(0, 4).join(' · ')}</span>
                      {targets.length > 4 && (
                        <span className="text-muted-foreground"> +{targets.length - 4}</span>
                      )}
                    </div>
                  )}
                  {s.cwe_tags.length > 0 && (
                    <div className="text-xs text-muted-foreground">
                      <span className="font-bold uppercase mr-2">CWE:</span>
                      <span className="text-sky-400">{s.cwe_tags.slice(0, 5).join(', ')}</span>
                      {s.cwe_tags.length > 5 && (
                        <span className="text-muted-foreground"> +{s.cwe_tags.length - 5}</span>
                      )}
                    </div>
                  )}
                  <div className="flex items-center gap-4 text-xs text-muted-foreground pt-2 border-t border-border">
                    <span className="flex items-center gap-1">
                      <BookOpen className="w-3 h-3" />
                      {s.reference_count} refs
                    </span>
                    <span className="flex items-center gap-1">
                      <Activity className="w-3 h-3" />
                      {s.script_count} scripts
                    </span>
                    {s.tags.length > 0 && (
                      <span className="ml-auto text-emerald-400 line-clamp-1">
                        #{s.tags.slice(0, 2).join(' #')}
                      </span>
                    )}
                  </div>
                  {updatedAt && (
                    <div className="text-[10px] text-muted-foreground font-mono">
                      {src?.updated_at ? '更新于' : '安装于'}: {new Date(updatedAt).toLocaleString()}
                    </div>
                  )}
                  <div
                    className="flex items-center gap-2 pt-2 border-t border-border"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={updatingName === s.name || !hasGitSource}
                      onClick={() => handleUpdate(s.name)}
                      className={`h-7 px-2 text-xs ${hasUpdate ? 'text-amber-400 hover:bg-amber-500/10' : 'text-sky-400 hover:bg-sky-500/10'}`}
                      title={hasGitSource ? (hasUpdate ? '有新版本可用，点击更新' : '从 Git 源拉取最新') : '此 Skill 无 Git 源，无法自动更新'}
                    >
                      <RefreshCw className={`w-3.5 h-3.5 mr-1 ${updatingName === s.name ? 'animate-spin' : ''}`} />
                      {hasUpdate ? '有更新' : '更新'}
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => setDeleteTarget(s.name)}
                      className="h-7 px-2 text-xs text-red-400 hover:bg-red-500/10 ml-auto"
                    >
                      <Trash2 className="w-3.5 h-3.5 mr-1" />
                      删除
                    </Button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Skill Detail Dialog */}
      <Dialog open={detailOpen} onOpenChange={setDetailOpen}>
        <DialogContent className="!w-[min(95vw,1100px)] !max-w-none max-h-[90vh] flex flex-col p-0 gap-0 cyber-dialog border border-border rounded-lg">
          <DialogHeader className="px-6 py-4 border-b border-border flex-shrink-0 bg-muted">
            <DialogTitle className="flex items-center gap-3 font-mono text-foreground">
              <div className="p-2 bg-primary/20 rounded border border-primary/30">
                <Sparkles className="w-5 h-5 text-primary" />
              </div>
              <div className="min-w-0">
                <span className="text-base font-bold uppercase tracking-wider truncate block">
                  {detail?.name || '加载中...'}
                </span>
                <p className="text-xs text-muted-foreground font-normal mt-0.5">
                  {detail ? `v${detail.version} · ${detail.category}` : ''}
                </p>
              </div>
            </DialogTitle>
          </DialogHeader>

          {detailLoading ? (
            <div className="flex-1 flex items-center justify-center py-16">
              <div className="loading-spinner" />
            </div>
          ) : detail ? (
            <ScrollArea className="flex-1">
              <div className="p-6 space-y-5">
                <div className="cyber-card p-4">
                  <p className="text-sm text-foreground">{detail.description || '(无描述)'}</p>
                  <div className="flex flex-wrap gap-2 mt-3">
                    {detail.severity_focus.map((sev) => (
                      <Badge
                        key={sev}
                        className={SEVERITY_COLOR[sev.toLowerCase()] || 'cyber-badge-muted'}
                      >
                        {sev}
                      </Badge>
                    ))}
                    {detail.tags.map((t) => (
                      <Badge key={t} className="cyber-badge-muted">
                        #{t}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* Meta */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {formatTargets(detail.targets).length > 0 && (
                    <div className="cyber-card p-4">
                      <p className="text-xs font-bold text-muted-foreground uppercase mb-2 flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4" /> Targets
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {formatTargets(detail.targets).map((t) => (
                          <Badge key={t} className="cyber-badge-info text-xs">
                            {t}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {detail.cwe_tags.length > 0 && (
                    <div className="cyber-card p-4">
                      <p className="text-xs font-bold text-muted-foreground uppercase mb-2">
                        CWE Tags
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {detail.cwe_tags.map((c) => (
                          <Badge key={c} className="cyber-badge-info text-xs">
                            {c}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* References */}
                {detail.references.length > 0 && (
                  <div className="cyber-card p-4">
                    <p className="text-xs font-bold text-muted-foreground uppercase mb-3 flex items-center gap-2">
                      <BookOpen className="w-4 h-4" /> References ({detail.references.length})
                    </p>
                    <div className="space-y-1">
                      {detail.references.map((r) => (
                        <button
                          key={r}
                          onClick={() => openReference(detail.name, r)}
                          className="w-full text-left px-3 py-2 flex items-center gap-2 text-xs text-sky-400 hover:bg-primary/10 border border-border hover:border-primary/40 rounded transition-colors font-mono"
                        >
                          <FileText className="w-3.5 h-3.5 flex-shrink-0" />
                          <span className="truncate">{r}</span>
                          <ExternalLink className="w-3 h-3 ml-auto opacity-60" />
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Scripts */}
                {detail.scripts.length > 0 && (
                  <div className="cyber-card p-4">
                    <p className="text-xs font-bold text-muted-foreground uppercase mb-3">
                      Scripts ({detail.scripts.length})
                    </p>
                    <div className="space-y-1">
                      {detail.scripts.map((s) => (
                        <div
                          key={s}
                          className="px-3 py-2 flex items-center gap-2 text-xs text-amber-400 border border-border rounded font-mono"
                        >
                          <Activity className="w-3.5 h-3.5 flex-shrink-0" />
                          <span className="truncate">{s}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Root dir */}
                <div className="text-xs text-muted-foreground flex items-center gap-2 font-mono">
                  <Folder className="w-3.5 h-3.5" />
                  <span className="truncate" title={detail.root_dir}>
                    {detail.root_dir}
                  </span>
                </div>

                {/* Body */}
                <div className="cyber-card p-0 overflow-hidden">
                  <div className="cyber-card-header">
                    <FileText className="w-4 h-4 text-primary" />
                    <h4 className="text-sm font-bold uppercase tracking-wider">SKILL.md Body</h4>
                  </div>
                  <pre className="p-4 text-xs text-emerald-400 whitespace-pre-wrap font-mono overflow-x-auto max-h-[500px] overflow-y-auto">
{detail.body || '(空)'}
                  </pre>
                </div>
              </div>
            </ScrollArea>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* Reference Dialog */}
      <Dialog open={refOpen} onOpenChange={setRefOpen}>
        <DialogContent className="!w-[min(95vw,900px)] !max-w-none max-h-[85vh] flex flex-col p-0 gap-0 cyber-dialog border border-border rounded-lg">
          <DialogHeader className="px-6 py-4 border-b border-border flex-shrink-0 bg-muted">
            <DialogTitle className="flex items-center gap-3 font-mono text-foreground">
              <div className="p-2 bg-sky-500/20 rounded border border-sky-500/30">
                <BookOpen className="w-5 h-5 text-sky-400" />
              </div>
              <div className="min-w-0">
                <span className="text-base font-bold uppercase tracking-wider truncate block">
                  {refContent?.path || '加载中...'}
                </span>
                <p className="text-xs text-muted-foreground font-normal mt-0.5">Reference Document</p>
              </div>
            </DialogTitle>
          </DialogHeader>
          {refLoading ? (
            <div className="flex-1 flex items-center justify-center py-16">
              <div className="loading-spinner" />
            </div>
          ) : refContent ? (
            <ScrollArea className="flex-1">
              <pre className="p-6 text-xs text-emerald-400 whitespace-pre-wrap font-mono">
{refContent.content}
              </pre>
            </ScrollArea>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* Import from Git Dialog */}
      <Dialog open={gitOpen} onOpenChange={(o) => { setGitOpen(o); if (!o) resetGitForm(); }}>
        <DialogContent className="!w-[min(95vw,600px)] !max-w-none cyber-dialog border border-border rounded-lg">
          <DialogHeader className="px-6 py-4 border-b border-border bg-muted">
            <DialogTitle className="flex items-center gap-3 font-mono text-foreground">
              <div className="p-2 bg-primary/20 rounded border border-primary/30">
                <GitBranch className="w-5 h-5 text-primary" />
              </div>
              <span className="text-base font-bold uppercase tracking-wider">从 Git 导入 Skill</span>
            </DialogTitle>
          </DialogHeader>
          <div className="p-6 space-y-4">
            <div className="space-y-2">
              <Label className="text-xs font-bold uppercase text-muted-foreground">
                Git URL <span className="text-red-400">*</span>
              </Label>
              <Input
                value={gitUrl}
                onChange={(e) => setGitUrl(e.target.value)}
                placeholder="https://github.com/xxx/skill-repo.git"
                className="cyber-input"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label className="text-xs font-bold uppercase text-muted-foreground">名称（可选）</Label>
                <Input
                  value={gitName}
                  onChange={(e) => setGitName(e.target.value)}
                  placeholder="覆盖 SKILL.md name"
                  className="cyber-input"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-bold uppercase text-muted-foreground">分支（可选）</Label>
                <Input
                  value={gitBranch}
                  onChange={(e) => setGitBranch(e.target.value)}
                  placeholder="main / master"
                  className="cyber-input"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label className="text-xs font-bold uppercase text-muted-foreground">子目录（可选）</Label>
              <Input
                value={gitSubdir}
                onChange={(e) => setGitSubdir(e.target.value)}
                placeholder="仓库中 SKILL.md 所在子目录"
                className="cyber-input"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="ghost" onClick={() => setGitOpen(false)} className="h-9">
                取消
              </Button>
              <Button
                onClick={handleImportFromGit}
                disabled={gitSubmitting || !gitUrl.trim()}
                className="cyber-btn-primary h-9"
              >
                {gitSubmitting ? (
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Download className="w-4 h-4 mr-2" />
                )}
                导入
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Registry Browser Dialog */}
      <Dialog open={registryOpen} onOpenChange={setRegistryOpen}>
        <DialogContent className="!w-[min(95vw,900px)] !max-w-none max-h-[85vh] flex flex-col p-0 gap-0 cyber-dialog border border-border rounded-lg">
          <DialogHeader className="px-6 py-4 border-b border-border flex-shrink-0 bg-muted">
            <DialogTitle className="flex items-center gap-3 font-mono text-foreground">
              <div className="p-2 bg-primary/20 rounded border border-primary/30">
                <Store className="w-5 h-5 text-primary" />
              </div>
              <div className="min-w-0">
                <span className="text-base font-bold uppercase tracking-wider truncate block">
                  Skill Registry
                </span>
                <p className="text-xs text-muted-foreground font-normal mt-0.5">
                  可用 Skill 目录 · 一键安装
                </p>
              </div>
            </DialogTitle>
          </DialogHeader>
          <div className="p-4 border-b border-border flex-shrink-0 flex gap-2">
            <Input
              value={registryUrl}
              onChange={(e) => setRegistryUrl(e.target.value)}
              placeholder="Registry URL（留空使用默认）"
              className="cyber-input flex-1"
            />
            <Button
              onClick={handleRefreshRegistry}
              disabled={registryLoading}
              className="cyber-btn-primary h-10"
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${registryLoading ? 'animate-spin' : ''}`} />
              刷新
            </Button>
          </div>
          <ScrollArea className="flex-1">
            {registryLoading ? (
              <div className="flex-1 flex items-center justify-center py-16">
                <div className="loading-spinner" />
              </div>
            ) : registryItems.length === 0 ? (
              <div className="text-center text-muted-foreground text-sm py-16">
                （空）点击"刷新"从 Registry 拉取
              </div>
            ) : (
              <div className="p-4 space-y-3">
                {registryItems.map((item) => (
                  <div key={item.name} className="cyber-card p-4">
                    <div className="flex items-start justify-between mb-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <h4 className="font-bold text-foreground uppercase truncate">{item.name}</h4>
                          <Badge className="cyber-badge-muted text-xs">v{item.version}</Badge>
                          {item.category && (
                            <Badge className="cyber-badge-info text-xs">{item.category}</Badge>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground line-clamp-2">
                          {item.description || '(无描述)'}
                        </p>
                      </div>
                      <Button
                        size="sm"
                        onClick={() => handleInstallFromRegistry(item.name)}
                        disabled={installingName === item.name}
                        className="cyber-btn-primary h-8 flex-shrink-0"
                      >
                        {installingName === item.name ? (
                          <RefreshCw className="w-3.5 h-3.5 mr-1 animate-spin" />
                        ) : (
                          <Download className="w-3.5 h-3.5 mr-1" />
                        )}
                        安装
                      </Button>
                    </div>
                    <div className="flex flex-wrap gap-1 text-xs text-muted-foreground">
                      {item.author && <span>作者: {item.author}</span>}
                      {item.tags?.map((t) => (
                        <Badge key={t} className="cyber-badge-muted text-xs">#{t}</Badge>
                      ))}
                    </div>
                    <div className="text-xs text-muted-foreground mt-2 truncate font-mono" title={item.source}>
                      源: {item.source}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteTarget} onOpenChange={(o) => !o && setDeleteTarget(null)}>
        <DialogContent className="!w-[min(95vw,480px)] !max-w-none cyber-dialog border border-border rounded-lg">
          <DialogHeader className="px-6 py-4 border-b border-border bg-muted">
            <DialogTitle className="flex items-center gap-3 font-mono text-foreground">
              <div className="p-2 bg-red-500/20 rounded border border-red-500/30">
                <Trash2 className="w-5 h-5 text-red-400" />
              </div>
              <span className="text-base font-bold uppercase tracking-wider">删除 Skill</span>
            </DialogTitle>
          </DialogHeader>
          <div className="p-6 space-y-4">
            <p className="text-sm text-foreground">
              确定要删除 Skill <span className="text-red-400 font-bold">{deleteTarget}</span> 吗？
            </p>
            <p className="text-xs text-muted-foreground">
              此操作会从可写 skills 目录移除该包，无法从 UI 恢复（可重新 Git/Zip/Registry 导入）。
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="ghost" onClick={() => setDeleteTarget(null)} className="h-9">
                取消
              </Button>
              <Button
                onClick={handleDelete}
                disabled={deleting}
                className="cyber-btn-danger h-9 bg-red-500/20 border border-red-500/40 text-red-300 hover:bg-red-500/30"
              >
                {deleting ? (
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Trash2 className="w-4 h-4 mr-2" />
                )}
                确认删除
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
