/**
 * CVE Knowledge Base Page
 * NVD / OSV CVE 知识库 — 列表 / 详情 / 同步触发 / 同步日志
 * Cyberpunk Terminal Aesthetic — 与 Skills / PromptManager 一致
 */

import { useState, useEffect, useMemo, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';
import { toast } from 'sonner';
import {
  Shield,
  ShieldAlert,
  RefreshCw,
  Search,
  Terminal,
  Database,
  Cloud,
  Package,
  Activity,
  ChevronLeft,
  ChevronRight,
  Cpu,
  Zap,
  FileWarning,
  CheckCircle2,
  XCircle,
  Clock,
  GitBranch,
} from 'lucide-react';
import {
  listCVEs,
  getCVE,
  getCVEStats,
  listSyncLogs,
  triggerNVDSync,
  triggerOSVSync,
  triggerCvelistV5Sync,
  getOSVPresets,
  triggerOSVPresetSync,
  type CVEItem,
  type CVEDetail,
  type CVEStats,
  type SyncLogItem,
  type OSVPackage,
  type OSVPresetsResponse,
  type PresetEcosystem,
  type PresetFramework,
} from '@/shared/api/cve';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'cyber-badge-critical',
  HIGH: 'cyber-badge-danger',
  MEDIUM: 'cyber-badge-warning',
  LOW: 'cyber-badge-info',
  NONE: 'cyber-badge-muted',
};

const STATUS_ICON: Record<string, JSX.Element> = {
  running: <Clock className="w-3.5 h-3.5 text-sky-400 animate-pulse" />,
  success: <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />,
  partial: <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />,
  failed: <XCircle className="w-3.5 h-3.5 text-red-400" />,
};

const PAGE_SIZE = 20;

function formatDate(s?: string | null): string {
  if (!s) return '-';
  try {
    return new Date(s).toLocaleString('zh-CN', { hour12: false });
  } catch {
    return s;
  }
}

function severityBadge(sev?: string | null) {
  if (!sev) return null;
  const key = sev.toUpperCase();
  return <Badge className={SEVERITY_COLOR[key] || 'cyber-badge-muted'}>{key}</Badge>;
}

export default function CVEKnowledge() {
  // list state
  const [items, setItems] = useState<CVEItem[]>([]);
  const [total, setTotal] = useState(0);
  const [skip, setSkip] = useState(0);
  const [loading, setLoading] = useState(true);

  // filters
  const [keyword, setKeyword] = useState('');
  const [severity, setSeverity] = useState<string>('all');
  const [source, setSource] = useState<string>('all');

  // stats
  const [stats, setStats] = useState<CVEStats | null>(null);

  // sync logs
  const [logs, setLogs] = useState<SyncLogItem[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);

  // detail
  const [detailOpen, setDetailOpen] = useState(false);
  const [detail, setDetail] = useState<CVEDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // NVD sync dialog
  const [nvdOpen, setNvdOpen] = useState(false);
  const [nvdDaysBack, setNvdDaysBack] = useState(30);
  const [nvdMaxResults, setNvdMaxResults] = useState(500);
  const [nvdSeverity, setNvdSeverity] = useState<string>('all');
  const [nvdSubmitting, setNvdSubmitting] = useState(false);

  // OSV sync dialog
  const [osvOpen, setOsvOpen] = useState(false);
  const [osvPackages, setOsvPackages] = useState(
    'npm:lodash\nPyPI:requests\nMaven:org.springframework:spring-core',
  );
  const [osvSubmitting, setOsvSubmitting] = useState(false);

  // cvelistV5 Git 兜底同步 dialog
  const [gitOpen, setGitOpen] = useState(false);
  const [gitForceFull, setGitForceFull] = useState(false);
  const [gitSubmitting, setGitSubmitting] = useState(false);

  // OSV 预设同步 dialog (多选替代手写文本)
  const [presetOpen, setPresetOpen] = useState(false);
  const [presetsData, setPresetsData] = useState<OSVPresetsResponse | null>(null);
  const [presetsLoading, setPresetsLoading] = useState(false);
  const [presetSelected, setPresetSelected] = useState<Set<string>>(
    () => new Set(),
  ); // key: `${ecosystem}::${framework}`
  const [presetSubmitting, setPresetSubmitting] = useState(false);

  const loadList = useCallback(
    async (nextSkip: number = skip) => {
      try {
        setLoading(true);
        const params: {
          skip: number;
          limit: number;
          severity?: string;
          source?: string;
          keyword?: string;
        } = { skip: nextSkip, limit: PAGE_SIZE };
        if (severity !== 'all') params.severity = severity;
        if (source !== 'all') params.source = source;
        if (keyword.trim()) params.keyword = keyword.trim();
        const res = await listCVEs(params);
        setItems(res.items);
        setTotal(res.total);
        setSkip(res.skip);
      } catch (e: any) {
        toast.error(e?.response?.data?.detail || '加载 CVE 列表失败');
      } finally {
        setLoading(false);
      }
    },
    [skip, severity, source, keyword],
  );

  const loadStats = useCallback(async () => {
    try {
      const s = await getCVEStats();
      setStats(s);
    } catch (e: any) {
      // 静默失败，Stats 面板显示占位
      console.warn('getCVEStats', e);
    }
  }, []);

  const loadLogs = useCallback(async () => {
    try {
      setLogsLoading(true);
      const l = await listSyncLogs({ limit: 10 });
      setLogs(l);
    } catch (e: any) {
      console.warn('listSyncLogs', e);
    } finally {
      setLogsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadList(0);
    loadStats();
    loadLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSearch = () => {
    setSkip(0);
    loadList(0);
  };

  const handleReset = () => {
    setKeyword('');
    setSeverity('all');
    setSource('all');
    setSkip(0);
    // 状态变更后下一渲染 loadList 用旧值，因此直接手动传参
    setTimeout(() => loadList(0), 0);
  };

  const openDetail = async (cveId: string) => {
    setDetailOpen(true);
    setDetail(null);
    setDetailLoading(true);
    try {
      const d = await getCVE(cveId);
      setDetail(d);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || '加载 CVE 详情失败');
      setDetailOpen(false);
    } finally {
      setDetailLoading(false);
    }
  };

  const submitNVDSync = async () => {
    try {
      setNvdSubmitting(true);
      const payload: {
        days_back: number;
        max_results: number;
        severity_filter?: string;
      } = { days_back: nvdDaysBack, max_results: nvdMaxResults };
      if (nvdSeverity !== 'all') payload.severity_filter = nvdSeverity;
      const res = await triggerNVDSync(payload);
      toast.success(res.message || 'NVD 同步任务已提交');
      setNvdOpen(false);
      // 稍等再刷日志，让后端任务落库
      setTimeout(loadLogs, 1000);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'NVD 同步触发失败');
    } finally {
      setNvdSubmitting(false);
    }
  };

  const submitOSVSync = async () => {
    // 解析 packages
    const lines = osvPackages
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    if (lines.length === 0) {
      toast.error('请至少填写一个包');
      return;
    }
    const packages: OSVPackage[] = [];
    for (const line of lines) {
      const parts = line.split(':');
      if (parts.length < 2) {
        toast.error(`格式错误: "${line}"，应为 "ecosystem:name" 或 "ecosystem:name:version"`);
        return;
      }
      const ecosystem = parts[0].trim();
      // Maven 类支持 group:artifact 形式，把第二段之后拼回来
      const rest = parts.slice(1).join(':').trim();
      // rest 里最后一个 : 之后如果像版本号，则作为 version
      const versionMatch = rest.match(/^(.+):([0-9][^\s:]*)$/);
      if (versionMatch) {
        packages.push({
          ecosystem,
          name: versionMatch[1].trim(),
          version: versionMatch[2].trim(),
        });
      } else {
        packages.push({ ecosystem, name: rest });
      }
    }
    try {
      setOsvSubmitting(true);
      const res = await triggerOSVSync({ packages });
      toast.success(res.message || `OSV 同步已提交（${packages.length} 个包）`);
      setOsvOpen(false);
      setTimeout(loadLogs, 1000);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'OSV 同步触发失败');
    } finally {
      setOsvSubmitting(false);
    }
  };

  const submitGitSync = async () => {
    try {
      setGitSubmitting(true);
      const res = await triggerCvelistV5Sync(gitForceFull);
      toast.success(res.message || 'cvelistV5 Git 同步任务已提交');
      setGitOpen(false);
      setTimeout(loadLogs, 1500);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'cvelistV5 Git 同步触发失败');
    } finally {
      setGitSubmitting(false);
    }
  };

  // OSV 预设同步 - 打开对话框时拉取预设
  const openPresetDialog = async () => {
    setPresetOpen(true);
    setPresetSelected(new Set());
    if (presetsData) return;
    try {
      setPresetsLoading(true);
      const data = await getOSVPresets();
      setPresetsData(data);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || '加载预设失败');
      setPresetOpen(false);
    } finally {
      setPresetsLoading(false);
    }
  };

  const togglePreset = (ecosystem: string, framework: string) => {
    const key = `${ecosystem}::${framework}`;
    setPresetSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  const toggleEcoAll = (eco: PresetEcosystem, selectAll: boolean) => {
    setPresetSelected((prev) => {
      const next = new Set(prev);
      eco.frameworks.forEach((fw) => {
        const key = `${eco.ecosystem}::${fw.id}`;
        if (selectAll) {
          next.add(key);
        } else {
          next.delete(key);
        }
      });
      return next;
    });
  };

  const submitPresetSync = async (mode: 'selected' | 'all' = 'selected') => {
    try {
      setPresetSubmitting(true);
      const payload =
        mode === 'all'
          ? { sync_all: true }
          : {
              selections: Array.from(presetSelected).map((key) => {
                const [ecosystem, framework] = key.split('::');
                return { ecosystem, framework };
              }),
            };
      const res = await triggerOSVPresetSync(payload);
      toast.success(res.message || 'OSV 预设同步已提交');
      setPresetOpen(false);
      setTimeout(loadLogs, 1500);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'OSV 预设同步触发失败');
    } finally {
      setPresetSubmitting(false);
    }
  };

  // 统计已选包数
  const selectedPackageCount = useMemo(() => {
    if (!presetsData) return 0;
    let count = 0;
    presetSelected.forEach((key) => {
      const [ecosystem, framework] = key.split('::');
      const eco = presetsData.presets.find((e) => e.ecosystem === ecosystem);
      const fw = eco?.frameworks.find((f) => f.id === framework);
      if (fw) count += fw.count;
    });
    return count;
  }, [presetSelected, presetsData]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const currentPage = Math.floor(skip / PAGE_SIZE) + 1;

  const sourceOptions = useMemo(() => {
    const s = new Set<string>(['nvd', 'osv', 'github_advisory', 'cnvd']);
    if (stats?.by_source) Object.keys(stats.by_source).forEach((k) => s.add(k));
    return Array.from(s);
  }, [stats]);

  return (
    <div className="space-y-6 p-6 cyber-bg-elevated min-h-screen font-mono relative">
      <div className="absolute inset-0 cyber-grid-subtle pointer-events-none" />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 relative z-10">
        <div className="cyber-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="stat-label">CVE 总数</p>
              <p className="stat-value text-primary">{stats?.total ?? '-'}</p>
            </div>
            <div className="stat-icon text-primary">
              <Database className="w-6 h-6" />
            </div>
          </div>
        </div>
        <div className="cyber-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="stat-label">Critical / High</p>
              <p className="stat-value text-red-400">
                {(stats?.by_severity?.CRITICAL ?? 0) + (stats?.by_severity?.HIGH ?? 0)}
              </p>
            </div>
            <div className="stat-icon text-red-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
          </div>
        </div>
        <div className="cyber-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="stat-label">Embedding 已同步</p>
              <p className="stat-value text-emerald-400">
                {stats?.embedding_synced ?? 0}
              </p>
              <p className="text-[10px] text-muted-foreground mt-0.5">
                待同步 {stats?.embedding_pending ?? 0}
              </p>
            </div>
            <div className="stat-icon text-emerald-400">
              <Cpu className="w-6 h-6" />
            </div>
          </div>
        </div>
        <div className="cyber-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="stat-label">最新收录</p>
              <p className="text-sm text-sky-400 font-bold mt-1 truncate">
                {formatDate(stats?.latest_published)}
              </p>
            </div>
            <div className="stat-icon text-sky-400">
              <Clock className="w-6 h-6" />
            </div>
          </div>
        </div>
      </div>

      {/* Action Bar */}
      <div className="cyber-card p-0 relative z-10">
        <div className="cyber-card-header">
          <Terminal className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-bold uppercase tracking-wider text-foreground">
            CVE 知识库
          </h3>
          <span className="text-xs text-muted-foreground ml-3 normal-case">
            NVD · OSV 双源同步 · Postgres 存储 · 供 Agent CVEQueryTool 使用
          </span>
          <div className="ml-auto flex gap-2">
            <Button onClick={() => setNvdOpen(true)} className="cyber-btn-primary h-9">
              <Cloud className="w-4 h-4 mr-2" />
              同步 NVD
            </Button>
            <Button onClick={openPresetDialog} className="cyber-btn-primary h-9">
              <Package className="w-4 h-4 mr-2" />
              OSV 预设同步
            </Button>
            <Button onClick={() => setOsvOpen(true)} className="cyber-btn-secondary h-9" title="手写 ecosystem:name 列表">
              <Terminal className="w-4 h-4 mr-2" />
              高级
            </Button>
            <Button
              onClick={() => setGitOpen(true)}
              className="cyber-btn-secondary h-9"
              title="从 CVEProject 官方 Git 仓库拉取 CVE JSON（NVD/OSV 网络受限时的兜底方案）"
            >
              <GitBranch className="w-4 h-4 mr-2" />
              Git 兜底
            </Button>
            <Button
              onClick={() => {
                loadStats();
                loadLogs();
              }}
              className="cyber-btn-ghost h-9"
              variant="outline"
            >
              <RefreshCw className="w-4 h-4" />
            </Button>
          </div>
        </div>

        <div className="p-4 flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[220px] space-y-2">
            <Label className="text-xs font-bold text-muted-foreground uppercase">
              关键词
            </Label>
            <div className="flex gap-2">
              <Input
                value={keyword}
                onChange={(e) => setKeyword(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                placeholder="cve_id / title / description"
                className="cyber-input"
              />
              <Button onClick={handleSearch} className="cyber-btn-primary h-10">
                <Search className="w-4 h-4" />
              </Button>
            </div>
          </div>
          <div className="w-40 space-y-2">
            <Label className="text-xs font-bold text-muted-foreground uppercase">
              Severity
            </Label>
            <Select
              value={severity}
              onValueChange={(v) => {
                setSeverity(v);
                setSkip(0);
                setTimeout(() => loadList(0), 0);
              }}
            >
              <SelectTrigger className="cyber-input">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="cyber-dialog border-border">
                <SelectItem value="all">全部</SelectItem>
                <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                <SelectItem value="HIGH">HIGH</SelectItem>
                <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                <SelectItem value="LOW">LOW</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="w-40 space-y-2">
            <Label className="text-xs font-bold text-muted-foreground uppercase">
              Source
            </Label>
            <Select
              value={source}
              onValueChange={(v) => {
                setSource(v);
                setSkip(0);
                setTimeout(() => loadList(0), 0);
              }}
            >
              <SelectTrigger className="cyber-input">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="cyber-dialog border-border">
                <SelectItem value="all">全部</SelectItem>
                {sourceOptions.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button onClick={handleReset} className="cyber-btn-ghost h-10" variant="outline">
            重置
          </Button>
        </div>
      </div>

      {/* Main Layout: List + Sync Logs */}
      <div className="grid gap-4 lg:grid-cols-[1fr,340px] relative z-10">
        {/* CVE List */}
        <div className="cyber-card p-0">
          <div className="cyber-card-header">
            <FileWarning className="w-4 h-4 text-primary" />
            <h4 className="text-sm font-bold uppercase tracking-wider">
              CVE 列表 ({total})
            </h4>
            <span className="ml-auto text-xs text-muted-foreground">
              第 {currentPage} / {totalPages} 页
            </span>
          </div>

          {loading ? (
            <div className="p-16 flex items-center justify-center">
              <div className="loading-spinner" />
            </div>
          ) : items.length === 0 ? (
            <div className="p-16 empty-state">
              <Database className="empty-state-icon" />
              <p className="empty-state-title">暂无 CVE 数据</p>
              <p className="empty-state-description">点击右上角 "同步 NVD" 拉取数据</p>
            </div>
          ) : (
            <div className="divide-y divide-border">
              {items.map((c) => (
                <button
                  key={c.id}
                  onClick={() => openDetail(c.cve_id)}
                  className="w-full text-left px-4 py-3 hover:bg-primary/5 transition-colors"
                >
                  <div className="flex items-start gap-3">
                    <div className="flex-shrink-0 pt-0.5">
                      <Shield className="w-4 h-4 text-primary" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className="font-bold text-sm text-foreground">
                          {c.cve_id}
                        </span>
                        {severityBadge(c.severity)}
                        {c.cvss_score !== null && c.cvss_score !== undefined && (
                          <Badge className="cyber-badge-muted">
                            CVSS {c.cvss_score.toFixed(1)}
                          </Badge>
                        )}
                        <Badge className="cyber-badge-info">{c.source}</Badge>
                        {c.embedding_synced === 1 && (
                          <Badge className="cyber-badge-info">
                            <Zap className="w-3 h-3 mr-1" />
                            embedded
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-foreground line-clamp-1">
                        {c.title || '(无标题)'}
                      </p>
                      <div className="flex items-center gap-3 text-[11px] text-muted-foreground mt-1">
                        {c.published_at && (
                          <span>公开 {formatDate(c.published_at)}</span>
                        )}
                        {c.cwe_ids.length > 0 && (
                          <span className="text-sky-400">
                            {c.cwe_ids.slice(0, 3).join(', ')}
                            {c.cwe_ids.length > 3 && ` +${c.cwe_ids.length - 3}`}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}

          {/* Pagination */}
          <div className="p-3 border-t border-border flex items-center justify-between text-xs">
            <span className="text-muted-foreground">
              共 {total} 条 · 每页 {PAGE_SIZE}
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                className="cyber-btn-ghost h-8"
                disabled={skip <= 0 || loading}
                onClick={() => {
                  const next = Math.max(0, skip - PAGE_SIZE);
                  loadList(next);
                }}
              >
                <ChevronLeft className="w-4 h-4" />
              </Button>
              <Button
                variant="outline"
                className="cyber-btn-ghost h-8"
                disabled={skip + PAGE_SIZE >= total || loading}
                onClick={() => loadList(skip + PAGE_SIZE)}
              >
                <ChevronRight className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </div>

        {/* Sync Logs */}
        <div className="cyber-card p-0">
          <div className="cyber-card-header">
            <Activity className="w-4 h-4 text-emerald-400" />
            <h4 className="text-sm font-bold uppercase tracking-wider">同步日志</h4>
            <Button
              onClick={loadLogs}
              variant="outline"
              className="ml-auto cyber-btn-ghost h-7 px-2"
              disabled={logsLoading}
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${logsLoading ? 'animate-spin' : ''}`}
              />
            </Button>
          </div>
          {logs.length === 0 ? (
            <div className="p-8 text-center text-xs text-muted-foreground">
              暂无同步记录
            </div>
          ) : (
            <ScrollArea className="max-h-[560px]">
              <div className="divide-y divide-border">
                {logs.map((log) => (
                  <div key={log.id} className="p-3 space-y-1">
                    <div className="flex items-center gap-2 text-xs">
                      {STATUS_ICON[log.status] || (
                        <Activity className="w-3.5 h-3.5 text-muted-foreground" />
                      )}
                      <span className="font-bold uppercase text-foreground">
                        {log.source}
                      </span>
                      <Badge className="cyber-badge-muted text-[10px] py-0">
                        {log.status}
                      </Badge>
                      <span className="ml-auto text-[10px] text-muted-foreground">
                        {formatDate(log.created_at)}
                      </span>
                    </div>
                    <div className="grid grid-cols-4 gap-1 text-[10px] font-mono">
                      <div className="text-center px-1 py-0.5 border border-border rounded">
                        <div className="text-muted-foreground">Total</div>
                        <div className="text-foreground font-bold">
                          {log.total_count}
                        </div>
                      </div>
                      <div className="text-center px-1 py-0.5 border border-border rounded">
                        <div className="text-muted-foreground">New</div>
                        <div className="text-emerald-400 font-bold">
                          {log.new_count}
                        </div>
                      </div>
                      <div className="text-center px-1 py-0.5 border border-border rounded">
                        <div className="text-muted-foreground">Upd</div>
                        <div className="text-sky-400 font-bold">
                          {log.updated_count}
                        </div>
                      </div>
                      <div className="text-center px-1 py-0.5 border border-border rounded">
                        <div className="text-muted-foreground">Fail</div>
                        <div className="text-red-400 font-bold">
                          {log.failed_count}
                        </div>
                      </div>
                    </div>
                    {log.error_message && (
                      <p className="text-[10px] text-red-400 truncate" title={log.error_message}>
                        {log.error_message}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </div>
      </div>

      {/* Detail Dialog */}
      <Dialog open={detailOpen} onOpenChange={setDetailOpen}>
        <DialogContent className="!w-[min(95vw,1000px)] !max-w-none max-h-[90vh] flex flex-col p-0 gap-0 cyber-dialog border border-border rounded-lg">
          <DialogHeader className="px-6 py-4 border-b border-border flex-shrink-0 bg-muted">
            <DialogTitle className="flex items-center gap-3 font-mono text-foreground">
              <div className="p-2 bg-primary/20 rounded border border-primary/30">
                <Shield className="w-5 h-5 text-primary" />
              </div>
              <div className="min-w-0">
                <span className="text-base font-bold uppercase tracking-wider truncate block">
                  {detail?.cve_id || '加载中...'}
                </span>
                <p className="text-xs text-muted-foreground font-normal mt-0.5">
                  {detail?.source} · {detail?.sync_status}
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
                {/* Header meta */}
                <div className="cyber-card p-4">
                  <h3 className="text-sm font-bold text-foreground mb-2">
                    {detail.title || '(无标题)'}
                  </h3>
                  <div className="flex flex-wrap gap-2 mb-3">
                    {severityBadge(detail.severity)}
                    {detail.cvss_score !== null && detail.cvss_score !== undefined && (
                      <Badge className="cyber-badge-muted">
                        CVSS {detail.cvss_score.toFixed(1)}
                      </Badge>
                    )}
                    <Badge className="cyber-badge-info">{detail.source}</Badge>
                    {detail.cwe_ids.map((cwe) => (
                      <Badge key={cwe} className="cyber-badge-info">
                        {cwe}
                      </Badge>
                    ))}
                  </div>
                  <p className="text-sm text-foreground whitespace-pre-wrap leading-relaxed">
                    {detail.description || '(无描述)'}
                  </p>
                  <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                    <div>公开时间: {formatDate(detail.published_at)}</div>
                    <div>修改时间: {formatDate(detail.modified_at)}</div>
                  </div>
                </div>

                {/* Affected packages */}
                {detail.affected_packages.length > 0 && (
                  <div className="cyber-card p-4">
                    <p className="text-xs font-bold text-muted-foreground uppercase mb-3 flex items-center gap-2">
                      <Package className="w-4 h-4" /> 受影响包 (
                      {detail.affected_packages.length})
                    </p>
                    <div className="space-y-2">
                      {detail.affected_packages.map((pkg, idx) => (
                        <pre
                          key={idx}
                          className="px-3 py-2 text-xs text-emerald-400 border border-border rounded font-mono overflow-x-auto"
                        >
                          {JSON.stringify(pkg, null, 2)}
                        </pre>
                      ))}
                    </div>
                  </div>
                )}

                {/* References */}
                {detail.references.length > 0 && (
                  <div className="cyber-card p-4">
                    <p className="text-xs font-bold text-muted-foreground uppercase mb-3">
                      参考链接 ({detail.references.length})
                    </p>
                    <div className="space-y-1">
                      {detail.references.map((r, idx) => {
                        const url = (r as any)?.url || (r as any)?.URL || '';
                        return (
                          <a
                            key={idx}
                            href={url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="block px-3 py-1.5 text-xs text-sky-400 hover:text-sky-300 hover:bg-primary/10 border border-border hover:border-primary/40 rounded transition-colors font-mono truncate"
                          >
                            {url || JSON.stringify(r)}
                          </a>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Raw data */}
                <div className="cyber-card p-0 overflow-hidden">
                  <div className="cyber-card-header">
                    <Database className="w-4 h-4 text-primary" />
                    <h4 className="text-sm font-bold uppercase tracking-wider">
                      Raw Data
                    </h4>
                  </div>
                  <pre className="p-4 text-[11px] text-emerald-400 whitespace-pre-wrap font-mono overflow-x-auto max-h-[400px] overflow-y-auto">
                    {JSON.stringify(detail.raw_data, null, 2)}
                  </pre>
                </div>
              </div>
            </ScrollArea>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* NVD Sync Dialog */}
      <Dialog open={nvdOpen} onOpenChange={setNvdOpen}>
        <DialogContent className="!w-[min(95vw,520px)] cyber-dialog border border-border rounded-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 font-mono">
              <Cloud className="w-5 h-5 text-primary" />
              NVD 增量同步
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label className="text-xs font-bold uppercase text-muted-foreground">
                回溯天数 (1-365)
              </Label>
              <Input
                type="number"
                min={1}
                max={365}
                value={nvdDaysBack}
                onChange={(e) => setNvdDaysBack(Number(e.target.value) || 30)}
                className="cyber-input"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-xs font-bold uppercase text-muted-foreground">
                最大条数 (1-5000)
              </Label>
              <Input
                type="number"
                min={1}
                max={5000}
                value={nvdMaxResults}
                onChange={(e) => setNvdMaxResults(Number(e.target.value) || 500)}
                className="cyber-input"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-xs font-bold uppercase text-muted-foreground">
                Severity 过滤 (可选)
              </Label>
              <Select value={nvdSeverity} onValueChange={setNvdSeverity}>
                <SelectTrigger className="cyber-input">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="cyber-dialog border-border">
                  <SelectItem value="all">全部</SelectItem>
                  <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                  <SelectItem value="HIGH">HIGH</SelectItem>
                  <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                  <SelectItem value="LOW">LOW</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              提示: NVD API 无 key 时限速 ~1 req/6s；此任务在后台执行，请稍后刷新"同步日志"查看结果。
            </p>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setNvdOpen(false)}
              className="cyber-btn-ghost"
              disabled={nvdSubmitting}
            >
              取消
            </Button>
            <Button
              onClick={submitNVDSync}
              className="cyber-btn-primary"
              disabled={nvdSubmitting}
            >
              {nvdSubmitting ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  提交中
                </>
              ) : (
                <>
                  <Cloud className="w-4 h-4 mr-2" />
                  开始同步
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* OSV Sync Dialog */}
      <Dialog open={osvOpen} onOpenChange={setOsvOpen}>
        <DialogContent className="!w-[min(95vw,600px)] cyber-dialog border border-border rounded-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 font-mono">
              <Package className="w-5 h-5 text-primary" />
              OSV 按包查询同步
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label className="text-xs font-bold uppercase text-muted-foreground">
                包列表（每行一个）
              </Label>
              <Textarea
                rows={8}
                value={osvPackages}
                onChange={(e) => setOsvPackages(e.target.value)}
                className="cyber-input font-mono text-xs"
                placeholder={
                  'npm:lodash\nPyPI:requests\nMaven:org.springframework:spring-core:5.3.0'
                }
              />
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                格式:{' '}
                <code className="text-emerald-400">ecosystem:name</code> 或{' '}
                <code className="text-emerald-400">ecosystem:name:version</code>
                。支持 npm / PyPI / Maven / Go / RubyGems / crates.io / NuGet 等。
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setOsvOpen(false)}
              className="cyber-btn-ghost"
              disabled={osvSubmitting}
            >
              取消
            </Button>
            <Button
              onClick={submitOSVSync}
              className="cyber-btn-primary"
              disabled={osvSubmitting}
            >
              {osvSubmitting ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  提交中
                </>
              ) : (
                <>
                  <Package className="w-4 h-4 mr-2" />
                  开始同步
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* OSV 预设同步 Dialog (多选, 替代手写文本) */}
      <Dialog open={presetOpen} onOpenChange={setPresetOpen}>
        <DialogContent className="!w-[min(95vw,820px)] max-h-[85vh] cyber-dialog border border-border rounded-lg flex flex-col">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 font-mono">
              <Package className="w-5 h-5 text-primary" />
              OSV 预设同步 (多选)
            </DialogTitle>
          </DialogHeader>

          {presetsLoading ? (
            <div className="py-16 flex items-center justify-center">
              <div className="loading-spinner" />
            </div>
          ) : !presetsData ? (
            <div className="py-12 empty-state">
              <p className="empty-state-title">无法加载预设</p>
            </div>
          ) : (
            <>
              <div className="cyber-card p-3 border-l-2 border-l-primary/60 flex-shrink-0">
                <p className="text-xs text-foreground leading-relaxed">
                  <span className="text-primary font-bold">勾选常用技术栈</span>
                  ,后端自动展开为 OSV 包列表并触发同步,无需手写 ecosystem:name 文本。
                </p>
                <div className="flex items-center gap-4 text-[11px] text-muted-foreground mt-2">
                  <span>生态: <span className="text-primary font-bold">{presetsData.stats.ecosystems}</span></span>
                  <span>框架: <span className="text-primary font-bold">{presetsData.stats.frameworks}</span></span>
                  <span>包: <span className="text-primary font-bold">{presetsData.stats.packages}</span></span>
                  <span className="ml-auto">
                    已选: <span className="text-emerald-400 font-bold">{presetSelected.size}</span> 框架
                    ({selectedPackageCount} 包)
                  </span>
                </div>
              </div>

              <Tabs defaultValue={presetsData.presets[0]?.ecosystem} className="flex-1 min-h-0 flex flex-col">
                <TabsList className="flex-shrink-0 flex flex-wrap h-auto">
                  {presetsData.presets.map((eco) => (
                    <TabsTrigger key={eco.ecosystem} value={eco.ecosystem} className="text-xs">
                      {eco.label} <span className="ml-1 text-muted-foreground">({eco.frameworks.length})</span>
                    </TabsTrigger>
                  ))}
                </TabsList>

                {presetsData.presets.map((eco) => (
                  <TabsContent
                    key={eco.ecosystem}
                    value={eco.ecosystem}
                    className="flex-1 min-h-0 overflow-auto pr-2"
                  >
                    <div className="flex items-center justify-between mb-3 sticky top-0 bg-background/95 backdrop-blur py-2 z-10">
                      <p className="text-xs text-muted-foreground">
                        <code className="text-emerald-400">{eco.ecosystem}</code> · {eco.frameworks.length} 框架
                      </p>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => toggleEcoAll(eco, true)}
                          className="h-7 text-xs"
                        >
                          全选
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => toggleEcoAll(eco, false)}
                          className="h-7 text-xs"
                        >
                          全不选
                        </Button>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {eco.frameworks.map((fw) => {
                        const key = `${eco.ecosystem}::${fw.id}`;
                        const checked = presetSelected.has(key);
                        return (
                          <label
                            key={fw.id}
                            className={`flex items-center gap-2 p-2 rounded border cursor-pointer transition-colors ${
                              checked
                                ? 'border-primary/60 bg-primary/10'
                                : 'border-border hover:border-primary/30'
                            }`}
                          >
                            <Checkbox
                              checked={checked}
                              onCheckedChange={() =>
                                togglePreset(eco.ecosystem, fw.id)
                              }
                            />
                            <div className="flex-1 min-w-0">
                              <p className="text-xs font-bold text-foreground truncate">
                                {fw.label}
                              </p>
                              <p className="text-[10px] text-muted-foreground">
                                {fw.id} · {fw.count} 包
                              </p>
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  </TabsContent>
                ))}
              </Tabs>
            </>
          )}

          <DialogFooter className="flex-shrink-0 border-t border-border pt-3 mt-2">
            <div className="flex items-center text-[11px] text-muted-foreground mr-auto">
              {selectedPackageCount > 0
                ? `已选 ${presetSelected.size} 框架,展开为 ${selectedPackageCount} 个 OSV 包`
                : '请勾选至少一个框架'}
            </div>
            <Button
              variant="outline"
              onClick={() => setPresetOpen(false)}
              className="cyber-btn-ghost"
              disabled={presetSubmitting}
            >
              取消
            </Button>
            <Button
              variant="outline"
              onClick={() => submitPresetSync('all')}
              className="cyber-btn-secondary"
              disabled={presetSubmitting}
              title="同步所有 8 个生态的全部预设 (约 100+ 包)"
            >
              <Zap className="w-4 h-4 mr-2" />
              全量同步
            </Button>
            <Button
              onClick={() => submitPresetSync('selected')}
              className="cyber-btn-primary"
              disabled={presetSubmitting || presetSelected.size === 0}
            >
              {presetSubmitting ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  提交中
                </>
              ) : (
                <>
                  <Package className="w-4 h-4 mr-2" />
                  同步已选 ({selectedPackageCount})
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* cvelistV5 Git 兜底同步 Dialog */}
      <Dialog open={gitOpen} onOpenChange={setGitOpen}>
        <DialogContent className="!w-[min(95vw,560px)] cyber-dialog border border-border rounded-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 font-mono">
              <GitBranch className="w-5 h-5 text-primary" />
              cvelistV5 Git 兜底同步
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="cyber-card p-3 border-l-2 border-l-amber-500/60">
              <p className="text-xs text-foreground leading-relaxed">
                <span className="text-amber-400 font-bold">兜底方案</span>
                ：直接从{' '}
                <code className="text-emerald-400">
                  github.com/CVEProject/cvelistV5
                </code>{' '}
                Git 仓库拉取全量 CVE JSON，绕过 NVD/OSV API。
              </p>
              <ul className="text-[11px] text-muted-foreground list-disc list-inside mt-2 space-y-0.5">
                <li>首次全量：clone 仓库（浅克隆，约几百 MB）</li>
                <li>之后增量：<code>git fetch</code> + diff，只处理变更的 CVE 文件</li>
                <li>后端需已安装 <code>git</code>，且能访问 GitHub（可配镜像）</li>
                <li>镜像通过 <code>CVELIST_V5_GIT_REPO</code> 环境变量配置</li>
              </ul>
            </div>

            <div className="space-y-2">
              <label className="flex items-start gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={gitForceFull}
                  onChange={(e) => setGitForceFull(e.target.checked)}
                  className="mt-0.5 accent-primary"
                />
                <div>
                  <p className="text-xs font-bold text-foreground">
                    强制全量同步 (force_full)
                  </p>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">
                    忽略上次同步的 commit hash，重新扫描整个仓库的所有 CVE JSON 文件。
                    首次同步会自动全量，日常增量不需要勾选。
                  </p>
                </div>
              </label>
            </div>

            <p className="text-[11px] text-muted-foreground leading-relaxed">
              提示：任务在后台异步执行，全量首次同步可能耗时 10-30 分钟（取决于网络与 CPU），
              请在"同步日志"查看进度。
            </p>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setGitOpen(false)}
              className="cyber-btn-ghost"
              disabled={gitSubmitting}
            >
              取消
            </Button>
            <Button
              onClick={submitGitSync}
              className="cyber-btn-primary"
              disabled={gitSubmitting}
            >
              {gitSubmitting ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  提交中
                </>
              ) : (
                <>
                  <GitBranch className="w-4 h-4 mr-2" />
                  {gitForceFull ? '开始全量同步' : '开始增量同步'}
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
