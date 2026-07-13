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
