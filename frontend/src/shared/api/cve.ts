/**
 * CVE Knowledge Base API — 只读列表/详情 + 触发 NVD/OSV 同步
 */

import { apiClient } from './serverClient';

export interface CVEItem {
  id: string;
  cve_id: string;
  title?: string | null;
  description?: string | null;
  cvss_score?: number | null;
  severity?: string | null;
  cwe_ids: string[];
  source: string;
  sync_status: string;
  embedding_synced: number;
  published_at?: string | null;
  modified_at?: string | null;
  created_at?: string | null;
}

export interface CVEDetail extends CVEItem {
  affected_packages: Record<string, unknown>[];
  references: Record<string, unknown>[];
  raw_data: Record<string, unknown>;
}

export interface CVEListResponse {
  total: number;
  items: CVEItem[];
  skip: number;
  limit: number;
}

export interface CVEStats {
  total: number;
  by_severity: Record<string, number>;
  by_source: Record<string, number>;
  embedding_synced: number;
  embedding_pending: number;
  latest_published?: string | null;
}

export interface SyncLogItem {
  id: string;
  source: string;
  status: string;
  total_count: number;
  new_count: number;
  updated_count: number;
  failed_count: number;
  start_date?: string | null;
  end_date?: string | null;
  error_message?: string | null;
  created_at?: string | null;
}

export interface NVDSyncRequest {
  days_back?: number;
  max_results?: number;
  severity_filter?: string;
}

export interface OSVPackage {
  ecosystem: string;
  name: string;
  version?: string;
}

export interface OSVSyncRequest {
  packages: OSVPackage[];
}

export interface PresetSelection {
  ecosystem: string;
  framework: string;
}

export interface PresetSyncRequest {
  selections: PresetSelection[];
  sync_all?: boolean;
  ecosystem?: string;
}

export interface PresetFramework {
  id: string;
  label: string;
  count: number;
}

export interface PresetEcosystem {
  ecosystem: string;
  label: string;
  frameworks: PresetFramework[];
}

export interface OSVPresetsResponse {
  presets: PresetEcosystem[];
  stats: {
    ecosystems: number;
    frameworks: number;
    packages: number;
  };
}

export interface SyncTriggerResponse {
  accepted: boolean;
  message: string;
}

export async function listCVEs(params?: {
  skip?: number;
  limit?: number;
  severity?: string;
  source?: string;
  keyword?: string;
}): Promise<CVEListResponse> {
  const search = new URLSearchParams();
  if (params?.skip !== undefined) search.set('skip', String(params.skip));
  if (params?.limit !== undefined) search.set('limit', String(params.limit));
  if (params?.severity) search.set('severity', params.severity);
  if (params?.source) search.set('source', params.source);
  if (params?.keyword) search.set('keyword', params.keyword);
  const query = search.toString();
  const response = await apiClient.get(`/cve${query ? `?${query}` : ''}`);
  return response.data;
}

export async function getCVE(cveId: string): Promise<CVEDetail> {
  const response = await apiClient.get(`/cve/${encodeURIComponent(cveId)}`);
  return response.data;
}

export async function getCVEStats(): Promise<CVEStats> {
  const response = await apiClient.get('/cve/stats');
  return response.data;
}

export async function listSyncLogs(params?: {
  limit?: number;
  source?: string;
}): Promise<SyncLogItem[]> {
  const search = new URLSearchParams();
  if (params?.limit !== undefined) search.set('limit', String(params.limit));
  if (params?.source) search.set('source', params.source);
  const query = search.toString();
  const response = await apiClient.get(`/cve/sync/logs${query ? `?${query}` : ''}`);
  return response.data;
}

export async function triggerNVDSync(
  payload: NVDSyncRequest,
): Promise<SyncTriggerResponse> {
  const response = await apiClient.post('/cve/sync/nvd', payload);
  return response.data;
}

export async function triggerOSVSync(
  payload: OSVSyncRequest,
): Promise<SyncTriggerResponse> {
  const response = await apiClient.post('/cve/sync/osv', payload);
  return response.data;
}

/**
 * OSV 增量同步（基于 modified_id.csv）
 * @param ecosystems 逗号分隔的生态系统列表，空字符串 = 全部
 */
export async function triggerOSVIncrementalSync(
  ecosystems: string = '',
): Promise<SyncTriggerResponse> {
  const query = ecosystems ? `?ecosystems=${encodeURIComponent(ecosystems)}` : '';
  const response = await apiClient.post(`/cve/sync/osv/incremental${query}`);
  return response.data;
}

export interface NVDIncrementalSyncRequest {
  max_results?: number;
  severity_filter?: string;
  fallback_days?: number;
}

/**
 * NVD 增量同步：从上次成功同步的 end_date 开始拉取
 */
export async function triggerNVDIncrementalSync(
  payload: NVDIncrementalSyncRequest,
): Promise<SyncTriggerResponse> {
  const response = await apiClient.post('/cve/sync/nvd/incremental', payload);
  return response.data;
}

export interface TechStackSyncRequest {
  keywords?: string[];
  years?: number;
  severity_filter?: string;
  max_per_keyword?: number;
}

/**
 * 技术栈历史 CVE 同步（按关键词批量从 NVD 拉取）
 */
export async function triggerTechStackSync(
  payload: TechStackSyncRequest,
): Promise<SyncTriggerResponse> {
  const response = await apiClient.post('/cve/sync/tech-stack', payload);
  return response.data;
}

/**
 * CVEProject cvelistV5 Git 兜底同步
 *
 * 直接从 GitHub 官方仓库 clone/fetch CVE JSON，绕过 NVD/OSV API。
 * 适用场景：
 *   - NVD API 无 key 限速严重（1 req/6s）
 *   - NVD/OSV 网络受限或超时
 *   - 需要全量历史数据（NVD 单次窗口最多 120 天）
 *
 * @param forceFull true = 忽略增量哈希，重新扫描整个仓库
 */
export async function triggerCvelistV5Sync(
  forceFull: boolean = false,
): Promise<SyncTriggerResponse> {
  const response = await apiClient.post(
    `/cve/sync/cvelist-v5?force_full=${forceFull}`,
  );
  return response.data;
}

/**
 * 获取 OSV 同步预设（按生态/语言/框架分组）
 * 给前端多选 UI 用，避免手写 ecosystem:name
 */
export async function getOSVPresets(): Promise<OSVPresetsResponse> {
  const response = await apiClient.get('/cve/sync/osv/presets');
  return response.data;
}

/**
 * 触发 OSV 预设同步
 * @param payload selections=[{ecosystem, framework}, ...] 或 sync_all=true
 */
export async function triggerOSVPresetSync(
  payload: PresetSyncRequest,
): Promise<SyncTriggerResponse> {
  const response = await apiClient.post('/cve/sync/osv/presets', payload);
  return response.data;
}
