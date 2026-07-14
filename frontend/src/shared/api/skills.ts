/**
 * Skills API — 文件系统可插拔的审计知识包
 * 后端只读 + reload；写入需在文件系统层完成
 */

import { apiClient } from './serverClient';

export interface SkillSource {
  type?: string;               // git | zip
  git_url?: string;
  branch?: string;
  subdir?: string;
  commit?: string;
  installed_at?: string;
  updated_at?: string;
}

export interface SkillSummary {
  name: string;
  version: string;
  category: string;
  description: string;
  targets: Record<string, unknown>;
  cwe_tags: string[];
  severity_focus: string[];
  tags: string[];
  reference_count: number;
  script_count: number;
  source?: SkillSource;
}

export interface SkillDetail extends SkillSummary {
  body: string;
  references: string[];
  scripts: string[];
  root_dir: string;
}

export interface SkillReference {
  skill: string;
  reference: string;
  content: string;
}

export interface ReloadResult {
  count: number;
  skills: string[];
  search_dirs: string[];
}

export interface ImportSkillGitPayload {
  git_url: string;
  name?: string;
  branch?: string;
  subdir?: string;
}

export interface ImportSkillResponse {
  success: boolean;
  name: string;
  version: string;
  category: string;
  description: string;
  root_dir: string;
}

export interface RegistrySkillItem {
  name: string;
  version: string;
  description: string;
  category: string;
  source: string;
  author: string;
  tags: string[];
}

export interface RegistryListResponse {
  source: string;
  skills: RegistrySkillItem[];
}

export interface DeleteSkillResponse {
  success: boolean;
  name: string;
  message: string;
}

export async function listSkills(params?: {
  category?: string;
  keyword?: string;
}): Promise<SkillSummary[]> {
  const search = new URLSearchParams();
  if (params?.category) search.set('category', params.category);
  if (params?.keyword) search.set('keyword', params.keyword);
  const query = search.toString();
  const response = await apiClient.get(`/skills${query ? `?${query}` : ''}`);
  return response.data;
}

export async function getSkill(name: string): Promise<SkillDetail> {
  const response = await apiClient.get(`/skills/${encodeURIComponent(name)}`);
  return response.data;
}

export async function getSkillReference(
  name: string,
  refPath: string,
): Promise<SkillReference> {
  // refPath already may include or omit `references/` prefix — backend handles both
  const cleaned = refPath.replace(/^references\//, '');
  const response = await apiClient.get(
    `/skills/${encodeURIComponent(name)}/references/${cleaned
      .split('/')
      .map(encodeURIComponent)
      .join('/')}`,
  );
  return response.data;
}

export async function reloadSkills(): Promise<ReloadResult> {
  const response = await apiClient.get('/skills/reload');
  return response.data;
}

export async function importSkillFromGit(payload: ImportSkillGitPayload): Promise<ImportSkillResponse> {
  const response = await apiClient.post('/skills/import/git', payload);
  return response.data;
}

export async function importSkillFromZip(file: File, name?: string): Promise<ImportSkillResponse> {
  const formData = new FormData();
  formData.append('file', file);
  if (name) formData.append('name', name);
  const response = await apiClient.post('/skills/import/zip', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
}

export async function fetchRegistrySkills(registryUrl?: string): Promise<RegistryListResponse> {
  const params = new URLSearchParams();
  if (registryUrl) params.set('registry_url', registryUrl);
  const query = params.toString();
  const response = await apiClient.get(`/skills/registry/available${query ? `?${query}` : ''}`);
  return response.data;
}

export async function installSkillFromRegistry(name: string, registryUrl?: string): Promise<ImportSkillResponse> {
  const response = await apiClient.post('/skills/registry/install', { name, registry_url: registryUrl });
  return response.data;
}

export async function deleteSkill(name: string): Promise<DeleteSkillResponse> {
  const response = await apiClient.delete(`/skills/${encodeURIComponent(name)}`);
  return response.data;
}

export async function updateSkill(name: string, gitUrl?: string): Promise<ImportSkillResponse> {
  const response = await apiClient.post(`/skills/${encodeURIComponent(name)}/update`, null, {
    params: gitUrl ? { git_url: gitUrl } : undefined,
  });
  return response.data;
}

export interface SkillUpdateCheckItem {
  name: string;
  git_url: string;
  branch: string;
  local_commit?: string | null;
  remote_commit?: string | null;
  has_update: boolean;
  error?: string | null;
}

export interface SkillUpdateCheckResponse {
  count: number;
  updates_available: number;
  items: SkillUpdateCheckItem[];
}

export async function checkSkillUpdates(): Promise<SkillUpdateCheckResponse> {
  const response = await apiClient.get('/skills/updates/check');
  return response.data;
}
