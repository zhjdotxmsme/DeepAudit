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
} from 'lucide-react';
import {
  listSkills,
  getSkill,
  getSkillReference,
  reloadSkills,
  type SkillSummary,
  type SkillDetail,
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
          <div className="ml-auto flex gap-2">
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
                  <div className="flex flex-wrap gap-2">
                    {s.category && <Badge className="cyber-badge-info">{s.category}</Badge>}
                    {s.severity_focus.map((sev) => (
                      <Badge
                        key={sev}
                        className={SEVERITY_COLOR[sev.toLowerCase()] || 'cyber-badge-muted'}
                      >
                        {sev}
                      </Badge>
                    ))}
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
    </div>
  );
}
