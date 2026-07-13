/**
 * Skills API — 文件系统可插拔的审计知识包
 * 后端只读 + reload；写入需在文件系统层完成
 */

import { apiClient } from './serverClient';

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
