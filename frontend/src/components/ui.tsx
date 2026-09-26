import type { ReactNode } from 'react';
import { AlertTriangle, CircleHelp, Minus, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { Provenance } from '../api/types';

export const cx = (...values: Array<string | false | null | undefined>) => values.filter(Boolean).join(' ');
export function formatValue(value: unknown, fallback = 'N/A'): string {
  if (value === null || value === undefined || value === '') return fallback;
  if (typeof value === 'number') return Number.isFinite(value) ? new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 }).format(value) : fallback;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return String(value);
}
export function formatBytes(value?: number | null): string {
  if (value == null || !Number.isFinite(value)) return 'N/A';
  if (value < 1024) return `${formatValue(value)} B`;
  const units = ['KB', 'MB', 'GB', 'TB']; let n = value / 1024; let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(1)} ${units[i]}`;
}
export function ProvenanceBadge({ value }: { value?: Provenance | null }) {
  const p = value || 'NOT_ASSESSED';
  return <span className={`provenance provenance-${p.toLowerCase()}`}><i />{p.replace(/_/g, ' ')}</span>;
}
export function Tag({ children, tone = 'default' }: { children: ReactNode; tone?: 'default' | 'green' | 'amber' | 'red' | 'blue' }) { return <span className={`tag tag-${tone}`}>{children}</span>; }
export function Card({ children, className = '', title, eyebrow, action }: { children: ReactNode; className?: string; title?: string; eyebrow?: string; action?: ReactNode }) {
  return <section className={`panel ${className}`}>{(title || action) && <header className="panel-head"><div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}{title && <h2>{title}</h2>}</div>{action}</header>}{children}</section>;
}
export function SectionTitle({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="section-title"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{action}</div>;
}
export function EmptyState({ title, description }: { title: string; description: string }) { return <div className="empty-state"><div className="empty-icon"><CircleHelp size={20}/></div><strong>{title}</strong><p>{description}</p></div>; }
export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) { return <div className="error-banner"><AlertTriangle size={17}/><span>{message}</span>{onRetry && <button className="text-button" onClick={onRetry}>Retry</button>}</div>; }
export function StatusIcon({ status }: { status?: string }) { const normalized = status?.toUpperCase(); if (normalized === 'ASSESSED') return <ShieldCheck size={17} className="text-green"/>; if (normalized === 'NOT_APPLICABLE') return <Minus size={17} className="muted-icon"/>; if (normalized === 'NOT_ASSESSED') return <CircleHelp size={17} className="text-amber"/>; return <ShieldAlert size={17} className="text-red"/>; }
export function StatCard({ label, value, note, icon, color = 'cyan' }: { label: string; value: ReactNode; note?: ReactNode; icon: ReactNode; color?: 'cyan' | 'green' | 'amber' | 'red' }) {
  return <div className="stat-card"><div className="stat-top"><span>{label}</span><span className={`stat-icon icon-${color}`}>{icon}</span></div><div className="stat-value">{value}</div>{note && <div className="stat-note">{note}</div>}</div>;
}
