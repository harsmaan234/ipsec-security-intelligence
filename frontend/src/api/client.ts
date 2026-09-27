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
export type ReportType = 'executive' | 'technical';

export async function generateReport(
  file: File,
  reportType: ReportType,
): Promise<{ blob: Blob; filename: string }> {
  const body = new FormData();
  body.append('file', file);
  body.append('report_type', reportType);

  let response: Response;

  try {
    response = await fetch(
      `${API_BASE_URL}/api/v1/reports/generate`,
      {
        method: 'POST',
        body,
      },
    );
  } catch {
    throw new Error(
      `Backend unavailable at ${API_BASE_URL}. Start the API and retry.`,
    );
  }

  if (!response.ok) {
    let detail = `Report generation failed (${response.status})`;

    try {
      const errorBody = (await response.json()) as {
        detail?: string;
      };

      detail = errorBody.detail || detail;
    } catch {
      // Keep the HTTP status message.
    }

    throw new Error(detail);
  }

  const blob = await response.blob();

  const disposition = response.headers.get(
    'content-disposition',
  );

  let filename =
    reportType === 'executive'
      ? 'ipsec-security-executive-report.pdf'
      : 'ipsec-security-technical-report.pdf';

  const filenameMatch = disposition?.match(
    /filename="?([^"]+)"?/i,
  );

  if (filenameMatch?.[1]) {
    filename = filenameMatch[1];
  }

  return {
    blob,
    filename,
  };
}
