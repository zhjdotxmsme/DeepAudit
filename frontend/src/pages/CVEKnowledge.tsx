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
} from 'lucide-react';
import {
  listCVEs,
  getCVE,
  getCVEStats,
  listSyncLogs,
  triggerNVDSync,
  triggerOSVSync,
  type CVEItem,
  type CVEDetail,
  type CVEStats,
  type SyncLogItem,
  type OSVPackage,
} from '@/shared/api/cve';

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
            <Button onClick={() => setOsvOpen(true)} className="cyber-btn-secondary h-9">
              <Package className="w-4 h-4 mr-2" />
              同步 OSV
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
    </div>
  );
}
