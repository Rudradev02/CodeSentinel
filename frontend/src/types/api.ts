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

export interface TaintStepDTO {
  step: number;
  line: number;
  column: number;
  operation: string;
  from_symbol?: string | null;
  to_symbol?: string | null;
  expression: string;
}

export interface TaintTraceDTO {
  flow_type: string;
  source: {
    file_path: string;
    line: number;
    column: number;
    symbol_name?: string;
    expression: string;
    source_id?: string;
  };
  propagation: TaintStepDTO[];
  sanitizer?: {
    sanitizer_id: string;
    callee_pattern: string;
    strength: string;
  } | null;
  sink: {
    file_path: string;
    line: number;
    column: number;
    callee: string;
    sink_id: string;
    argument_index: number;
    tainted_argument?: string;
  };
  path_summary: string;
}

export interface CallChainStepDTO {
  caller_function: string;
  callee_function: string;
  caller_file: string;
  callee_file: string;
  call_site_line: number;
  call_site_col: number;
  argument_index: number;
  callee_param_name: string;
  taint_action: string;
}

export interface InterproceduralTaintTraceDTO {
  flow_type: 'INTER_PROCEDURAL_TAINT';
  source: TaintTraceDTO['source'];
  call_chain: CallChainStepDTO[];
  sanitizer?: TaintTraceDTO['sanitizer'];
  sink: TaintTraceDTO['sink'];
  path_summary: string;
  total_depth: number;
  files_involved: string[];
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
  dataflow_evidence?: TaintTraceDTO | InterproceduralTaintTraceDTO | null;
}

export interface ComponentCouplingDTO {
  afferent: number;
  efferent: number;
  instability: number;
  total_loc: number;
  file_count: number;
  betweenness_centrality?: number;
  in_degree_centrality?: number;
  out_degree_centrality?: number;
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

export interface CallGraphSummaryDTO {
  analysis_id: string;
  total_functions: number;
  total_call_edges: number;
  resolved_local: number;
  resolved_import: number;
  unresolved: number;
  resolution_rate: number;
  summarized_functions: number;
  unsummarized_functions: number;
  interprocedural_findings_count: number;
  max_call_depth_reached: number;
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
  call_graph_summary?: CallGraphSummaryDTO | null;
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

// Phase 9: Differential Baseline Analysis Models
export type FindingTransition = 'NEW' | 'RESOLVED' | 'UNCHANGED' | 'MODIFIED';

export interface DifferentialFindingDTO {
  finding: FindingDTO;
  transition: FindingTransition | string;
  baseline_finding_id?: string | null;
  match_method?: string | null;
  detail?: string | null;
}

export interface HealthDeltaDTO {
  score_delta: number;
  baseline_score?: number | null;
  current_score?: number | null;
  baseline_grade?: string | null;
  current_grade?: string | null;
  grade_changed: boolean;
  architecture_score_delta?: number | null;
  security_score_delta?: number | null;
}

export interface ComponentDeltaDTO {
  new_components: string[];
  removed_components: string[];
  instability_deltas: Record<string, number>;
  new_cycles: string[][];
  resolved_cycles: string[][];
}

export interface ComparisonSummaryDTO {
  total_current: number;
  total_baseline: number;
  new_count: number;
  resolved_count: number;
  unchanged_count: number;
  modified_count: number;
  new_by_severity: Record<string, number>;
  resolved_by_severity: Record<string, number>;
}

export interface ComparisonResponseDTO {
  baseline_id?: string | null;
  current_id: string;
  baseline_commit?: string | null;
  current_commit?: string | null;
  compared_at: string;
  summary: ComparisonSummaryDTO;
  findings: DifferentialFindingDTO[];
  health_delta?: HealthDeltaDTO | null;
  component_delta?: ComponentDeltaDTO | null;
}

export interface CompareRequest {
  baseline_path?: string | null;
  current_path?: string | null;
  baseline_json?: Record<string, unknown> | null;
  current_json?: Record<string, unknown> | null;
}

// Phase 10: Persistent Analysis Storage & Repository Catalog
export interface RepositoryDTO {
  id: string;
  name: string;
  path: string;
  created_at: string;
  updated_at: string;
  analysis_count: number;
}

export interface RepositoryListDTO {
  items: RepositoryDTO[];
  total: number;
  skip: number;
  limit: number;
}

export interface AnalysisSnapshotSummaryDTO {
  id: string;
  repository_id: string;
  created_at: string;
  commit_hash?: string | null;
  branch?: string | null;
  is_dirty?: boolean | null;
  analyzer_version: string;
  status: string;
  duration_seconds: number;
  overall_score: number;
  overall_grade: string;
  architecture_score: number;
  architecture_grade: string;
  security_score: number;
  security_grade: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
}

export interface AnalysisHistoryDTO {
  items: AnalysisSnapshotSummaryDTO[];
  total: number;
  skip: number;
  limit: number;
}

// Phase 11: Asynchronous Analysis Orchestration & SSE Progress
export interface AnalysisJobDTO {
  id: string;
  repository_id: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED' | string;
  snapshot_id?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  progress_percent: number;
  progress_stage?: string | null;
  progress_message?: string | null;
  error_message?: string | null;
  stream_url: string;
  configuration?: Record<string, unknown> | null;
}

export interface JobListDTO {
  items: AnalysisJobDTO[];
  total: number;
  skip: number;
  limit: number;
}

export interface SSEProgressEvent {
  job_id: string;
  status: string;
  progress_percent: number;
  progress_stage?: string | null;
  progress_message?: string | null;
  snapshot_id?: string | null;
  error_message?: string | null;
}

// Phase 12: Bounded Context AI Enrichment & Remediation
export interface ProposedPatchDTO {
  file_path: string;
  original_snippet: string;
  patched_snippet: string;
  unified_diff: string;
  explanation: string;
}

export interface AIEnrichmentDTO {
  id: string;
  finding_id: string;
  snapshot_id: string;
  repository_id: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'DISABLED' | string;
  provider: string;
  model: string;
  prompt_version: string;
  is_likely_true_positive?: boolean | null;
  confidence_score?: number | null;
  risk_summary?: string | null;
  technical_reasoning?: string | null;
  assumptions_limitations?: string[];
  prescribed_remediation?: string | null;
  proposed_patch?: ProposedPatchDTO | null;
  error_message?: string | null;
  created_at: string;
  completed_at?: string | null;
}

export interface EnrichFindingRequest {
  provider?: string;
  model?: string;
  force_refresh?: boolean;
}

export interface EnrichFindingAcceptedResponse {
  enrichment_id: string;
  finding_id: string;
  status: string;
  message: string;
}

// Phase 14: Longitudinal Trend Intelligence
export interface TimelinePoint {
  snapshot_id: string;
  created_at: string;
  commit_hash?: string | null;
  branch?: string | null;
  overall_score: number;
  architecture_score: number;
  security_score: number;
  overall_grade: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
}

export interface DefectVelocityPoint {
  snapshot_id: string;
  created_at: string;
  new_defects: number;
  resolved_defects: number;
  net_change: number;
}

export interface ComponentDriftSummary {
  component_id: string;
  name: string;
  baseline_instability?: number | null;
  current_instability: number;
  instability_drift: number;
  current_centrality: number;
}

export interface LongitudinalTrendDTO {
  repository_id: string;
  branch?: string | null;
  total_snapshots: number;
  window_days?: number | null;
  health_trajectory: TimelinePoint[];
  defect_velocity: DefectVelocityPoint[];
  severity_trajectories: {
    CRITICAL: number[];
    HIGH: number[];
    MEDIUM: number[];
    LOW: number[];
    INFO: number[];
    [key: string]: number[];
  };
  component_drift: ComponentDriftSummary[];
  overall_health_delta: number;
  defect_burndown_rate: number;
}


