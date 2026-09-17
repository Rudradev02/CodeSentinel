/**
 * TypeScript contracts mirroring the CodeSentinel Backend & Analyzer schemas.
 */

export type EvidenceType = 'DETERMINISTIC' | 'HEURISTIC' | 'AI_ASSISTED';
export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingConfidence = 'HIGH' | 'MEDIUM' | 'LOW';
export type FindingCategory = 'SECURITY' | 'ARCHITECTURE' | 'QUALITY';
export type AIValidationStatus = 'CONFIRMED' | 'PROBABLE_FALSE_POSITIVE' | 'NEEDS_REVIEW';

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  environment: string;
  uptime_seconds: number;
  timestamp: string;
  components: Record<string, string>;
}

export interface SourceLocation {
  file_path: string;
  line_start: number;
  line_end: number;
  col_start?: number | null;
  col_end?: number | null;
}

export interface AIFindingEnrichment {
  provider: string;
  model: string;
  validation_status: AIValidationStatus;
  explanation: string;
  remediation_suggestion: string;
  unified_diff?: string | null;
  confidence: number;
  timestamp: string;
}

export interface Finding {
  id: string;
  rule_id: string;
  rule_name: string;
  category: FindingCategory;
  evidence_type: EvidenceType;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  location: SourceLocation;
  code_snippet: string;
  description: string;
  remediation: string;
  cwe_id?: string | null;
  owasp_category?: string | null;
  ai_enrichment?: AIFindingEnrichment | null;
  created_at?: string | null;
}

export interface DependencyNode {
  id: string;
  file_path: string;
  module_name: string;
  language: string;
  loc: number;
  fan_in: number;
  fan_out: number;
  is_god_module: boolean;
}

export interface DependencyEdge {
  id: string;
  source: string;
  target: string;
  import_type: 'STATIC' | 'DYNAMIC' | 'TYPE_ONLY';
  is_circular: boolean;
  line_number?: number | null;
}

export interface CircularDependency {
  cycle_id: string;
  modules: string[];
  length: number;
}

export interface CouplingMetrics {
  total_modules: number;
  total_edges: number;
  density: number;
  average_fan_in: number;
  average_fan_out: number;
  max_fan_out: number;
  circular_cycles_count: number;
}

export interface ArchitectureGraph {
  nodes: DependencyNode[];
  edges: DependencyEdge[];
  circular_dependencies: CircularDependency[];
  metrics: CouplingMetrics;
}

export interface RepositoryInfo {
  name: string;
  local_path: string;
  commit_hash?: string | null;
  branch?: string | null;
  detected_languages: Record<string, number>;
  detected_frameworks: string[];
  total_files: number;
  total_loc: number;
}

export interface AnalysisResult {
  id: string;
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
  repository: RepositoryInfo;
  security_summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    deterministic_count: number;
    heuristic_count: number;
    ai_enriched_count: number;
  };
  architecture_summary: {
    total_modules: number;
    circular_dependencies_count: number;
    god_modules_count: number;
    total_findings: number;
  };
  security_findings: Finding[];
  architecture_findings: Finding[];
  graph: ArchitectureGraph;
  error_message?: string | null;
}
