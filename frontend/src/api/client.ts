import type { AnalysisResponse, SimulationResponse } from './types';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');

async function request<T>(path: string, init: RequestInit): Promise<T> {
  let response: Response;
  try { response = await fetch(`${API_BASE_URL}${path}`, init); }
  catch { throw new Error(`Backend unavailable at ${API_BASE_URL}. Start the API and retry.`); }
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try { const body = await response.json() as { detail?: string }; detail = body.detail || detail; } catch { /* retain status */ }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

export function analyzePcap(file: File): Promise<AnalysisResponse> {
  const body = new FormData(); body.append('file', file);
  return request('/api/v1/analyze/pcap', { method: 'POST', body });
}

export function simulateSecurity(currentEvidence: Record<string, unknown>, changes: Record<string, unknown>): Promise<SimulationResponse> {
  return request('/api/v1/simulate/security', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ current_evidence: currentEvidence, changes }) });
}
