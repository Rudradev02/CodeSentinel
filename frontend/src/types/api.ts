/**
 * TypeScript contracts mirroring CodeSentinel Backend & Analyzer DTOs.
 */

export interface LocationDTO {
  file_path: string;
  line_start: number;
  line_end?: number | null;
  column_start?: number | null;
  column_end?: number | null;
}

export interface EvidenceDTO {
  snippet: string;
  language: string;
  highlight_lines: number[];
}

export interface FindingDTO {
  id: string;
  rule_id: string;
  rule_name: string;
  message: string;
  category: 'SECURITY' | 'ARCHITECTURE' | string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | string;
  description: string;
  remediation: string;
  location: LocationDTO;
  evidence: EvidenceDTO;
  cwe_id?: string | null;
  owasp_category?: string | null;
}

export interface ComponentCouplingDTO {
  afferent: number;
  efferent: number;
  instability: number;
  total_loc: number;
  file_count: number;
}

export interface ComponentNodeDTO {
  id: string;
  name: string;
  path: string;
  layer?: string | null;
  coupling: ComponentCouplingDTO;
  files: string[];
}

export interface ComponentEdgeDTO {
  id: string;
  source: string;
  target: string;
  weight: number;
  is_cycle: boolean;
}

export interface ComponentGraphDTO {
  nodes: ComponentNodeDTO[];
  edges: ComponentEdgeDTO[];
  circular_components_count: number;
  cycles: string[][];
}

export interface DeductionDTO {
  category: string;
  rule_id: string;
  points_deducted: number;
  reason: string;
  finding_id?: string | null;
  item_count: number;
}

export interface SubScoreDTO {
  score: number;
  grade: string;
  deductions: DeductionDTO[];
}

export interface HealthScoreDTO {
  overall_score: number;
  overall_grade: string;
  architecture_health: SubScoreDTO;
  security_posture: SubScoreDTO;
  total_deductions_count: number;
  summary?: string | null;
}

export interface AnalysisSummaryDTO {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total_modules: number;
  circular_dependencies_count: number;
  total_files: number;
  total_loc: number;
  duration_seconds: number;
}

export interface DiagnosticDTO {
  file_path: string;
  source_module: string;
  line_number?: number | null;
  diagnostic_type: string;
  message: string;
  reason: string;
  assigned_category: string;
}

export interface AnalysisResultDTO {
  id: string;
  status: string;
  repository_path: string;
  repository_name: string;
  summary: AnalysisSummaryDTO;
  health?: HealthScoreDTO | null;
  findings: FindingDTO[];
  component_graph?: ComponentGraphDTO | null;
  diagnostics: DiagnosticDTO[];
}

export interface RuleMetadataDTO {
  rule_id: string;
  name: string;
  category: string;
  evidence_type: string;
  severity: string;
  confidence: string;
  description: string;
  remediation: string;
  supported_languages: string[];
  frameworks: string[];
  cwe_id?: string | null;
  owasp_category?: string | null;
  rationale?: string | null;
}

export interface RuleListResponse {
  total_rules: number;
  rules: RuleMetadataDTO[];
}

export interface APIErrorResponse {
  code: string;
  message: string;
  details?: Record<string, unknown> | null;
}
