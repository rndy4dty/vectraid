/**
 * VECTRAID API client.
 *
 * Thin typed wrapper around fetch. All types are hand-written to match
 * the OpenAPI schema from Phase 9h. When the backend schema changes,
 * update these types.
 */

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const API_KEY = process.env.NEXT_PUBLIC_API_KEY ?? "";

// ---------- types ----------
export type CaseStatus = "new" | "investigating" | "resolved" | "closed";
export type CasePriority = "low" | "medium" | "high" | "critical";
export type RiskClassification =
  | "informational"
  | "low"
  | "medium"
  | "high"
  | "critical"
  | "insufficient_data";

export interface CaseEvent {
  timestamp: string;
  actor: string;
  action: string;
  detail: Record<string, unknown>;
}

export interface CaseNote {
  timestamp: string;
  author: string;
  text: string;
}

export interface CaseDecision {
  timestamp: string;
  analyst: string;
  outcome: string;
  rationale: string;
  evidence_reference: string | null;
}

export interface CaseResponse {
  case_id: string;
  title: string;
  status: CaseStatus;
  priority: CasePriority;
  created_by: string;
  assignee: string | null;
  evidence_ids: string[];
  decisions: CaseDecision[];
  notes: CaseNote[];
  history: CaseEvent[];
}

export interface EvidenceResponse {
  evidence_id: string;
  case_id: string;
  source_module: string;
  evidence_type: string;
  raw_reference: string;
  finding: string;
  timestamp: string;
  confidence: number;
  provenance: Record<string, unknown>;
}

export interface EnrichmentEntry {
  provider: string;
  classification: string;
  confidence: number;
  error: string | null;
}

export interface AnalyzeResult {
  indicator: string;
  ioc_type: string;
  enrichment: EnrichmentEntry[];
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  properties: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  module: string;
  confidence: number;
  timestamp: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphOverview {
  node_count: number;
  edge_count: number;
  ioc_count: number;
  evidence_count: number;
}

export interface HealthResponse {
  status: string;
  app: string;
  version: string;
}

// ---------- fetch wrapper ----------
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (API_KEY) {
    headers["X-API-Key"] = API_KEY;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    cache: "no-store",
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(
      `API ${res.status} ${res.statusText}: ${body || "unknown error"}`,
    );
  }

  return (await res.json()) as T;
}

// ---------- endpoints ----------
export const api = {
  health: () => request<HealthResponse>("/health"),

  listCases: (params?: { status?: CaseStatus }) => {
    const q = params?.status ? `?status=${params.status}` : "";
    return request<CaseResponse[]>(`/api/v1/cases${q}`);
  },

  getCase: (id: string) =>
    request<CaseResponse>(`/api/v1/cases/${id}`),

  createCase: (payload: {
    title: string;
    priority: CasePriority;
    created_by: string;
  }) =>
    request<CaseResponse>("/api/v1/cases", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  transitionCase: (id: string, to: CaseStatus, by: string) =>
    request<CaseResponse>(`/api/v1/cases/${id}/transition`, {
      method: "POST",
      body: JSON.stringify({ to, by }),
    }),

  assignCase: (id: string, assignee: string, by: string) =>
    request<CaseResponse>(`/api/v1/cases/${id}/assign`, {
      method: "POST",
      body: JSON.stringify({ assignee, by }),
    }),

  addNote: (id: string, note: string, by: string) =>
    request<CaseResponse>(`/api/v1/cases/${id}/notes`, {
      method: "POST",
      body: JSON.stringify({ note, by }),
    }),

  addDecision: (
    id: string,
    outcome: string,
    rationale: string,
    by: string,
    evidence_reference?: string,
  ) =>
    request<CaseResponse>(`/api/v1/cases/${id}/decisions`, {
      method: "POST",
      body: JSON.stringify({
        outcome,
        rationale,
        by,
        evidence_reference,
      }),
    }),

  listEvidence: (case_id?: string) => {
    const q = case_id ? `?case_id=${case_id}` : "";
    return request<EvidenceResponse[]>(`/api/v1/evidence${q}`);
  },

  getEvidence: (id: string) =>
    request<EvidenceResponse>(`/api/v1/evidence/${id}`),

  createEvidence: (payload: Omit<EvidenceResponse, "provenance"> & {
    provenance: Record<string, unknown>;
  }) =>
    request<EvidenceResponse>("/api/v1/evidence", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  linkEvidence: (case_id: string, evidence_id: string, by: string) =>
    request<CaseResponse>(`/api/v1/cases/${case_id}/evidence`, {
      method: "POST",
      body: JSON.stringify({ evidence_id, by }),
    }),

  getReport: (case_id: string) =>
    request<unknown>(`/api/v1/cases/${case_id}/report`),

  graphOverview: () =>
    request<GraphOverview>("/api/v1/graph/overview"),

  pivotGraph: (ioc_id: string, max_depth: number = 2) =>
    request<GraphData>(
      `/api/v1/graph/pivot/${encodeURIComponent(ioc_id)}?max_depth=${max_depth}`,
    ),

  analyzeIOC: (indicator: string, ioc_type: string) =>
    request<AnalyzeResult>("/api/v1/analyze/ioc", {
      method: "POST",
      body: JSON.stringify({ indicator, ioc_type }),
    }),
};
