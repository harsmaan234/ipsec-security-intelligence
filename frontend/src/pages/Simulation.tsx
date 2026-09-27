import { useState } from 'react';
import { ArrowRight, FlaskConical, RotateCcw, Sparkles } from 'lucide-react';
import type { AnalysisResponse, SimulationResponse } from '../api/types';
import { simulateSecurity } from '../api/client';
import { Card, ErrorBanner, formatValue, ProvenanceBadge, SectionTitle, Tag } from '../components/ui';

const encryptions = ['AES-GCM-256', 'AES-GCM-128', 'AES-CBC-256', 'AES-CBC-128', '3DES', 'CHACHA20-POLY1305'];
const dhGroups = ['MODP-1024', 'MODP-2048', 'MODP-3072', 'MODP-4096', 'ECP-256', 'ECP-384', 'ECP-521'];

export function SimulationPage({ data }: { data: AnalysisResponse | null }) {
  const currentEncryption = data?.ike?.selected_proposal?.encryption || '';
  const currentDh = data?.ike?.selected_proposal?.dh_group || '';
  const [encryption, setEncryption] = useState('AES-GCM-256');
  const [dhGroup, setDhGroup] = useState('ECP-256');
  const [result, setResult] = useState<SimulationResponse | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const run = async () => {
    if (!data?.ike) { setError('Analyze a PCAP with an IKE object before running a simulation.'); return; }
    setLoading(true); setError(''); setResult(null);
    try { setResult(await simulateSecurity({ ike: data.ike }, { 'ike.selected_proposal.encryption': encryption, 'ike.selected_proposal.dh_group': dhGroup })); }
    catch (e) { setError(e instanceof Error ? e.message : 'Simulation failed.'); }
    finally { setLoading(false); }
  };
  const current = result?.current?.score?.score;
  const projected = result?.projected?.score?.score;
  return <div className="page-stack">
    <SectionTitle eyebrow="DETERMINISTIC SECURITY SIMULATION" title="What-if analysis" description="Explore how hypothetical proposal values affect deterministic rule findings and scoring." action={<Tag tone="amber"><FlaskConical size={12}/> DETERMINISTIC SIMULATION</Tag>}/>
    <div className="simulation-banner"><Sparkles size={17}/><span><strong>Simulation only.</strong> Changes are evaluated against security rules and are not applied to a live VPN or network device.</span></div>
    <div className="simulation-layout">
      <Card title="Scenario inputs" eyebrow="HYPOTHETICAL PROPOSAL" className="simulation-input-card">
        <p className="sim-intro">Choose alternative IKE proposal values. Only the simulation evidence is changed.</p>
        <div className="sim-value-pair"><span>ENCRYPTION</span><div><strong>{formatValue(currentEncryption, 'Not observed')}</strong><ArrowRight size={14}/><strong className="sim-hypothetical">{encryption}</strong></div><small>Current value → Hypothetical value</small></div>
        <label className="field-label" htmlFor="sim-encryption">Hypothetical encryption</label>
        <select id="sim-encryption" value={encryption} onChange={e => setEncryption(e.target.value)}>{encryptions.map(value => <option key={value}>{value}</option>)}</select>
        <div className="sim-value-pair"><span>DH GROUP</span><div><strong>{formatValue(currentDh, 'Not observed')}</strong><ArrowRight size={14}/><strong className="sim-hypothetical">{dhGroup}</strong></div><small>Current value → Hypothetical value</small></div>
        <label className="field-label" htmlFor="sim-dh">Hypothetical DH group</label>
        <select id="sim-dh" value={dhGroup} onChange={e => setDhGroup(e.target.value)}>{dhGroups.map(value => <option key={value}>{value}</option>)}</select>
        <div className="sim-field-note">Simulation inputs: <span className="mono">ike.selected_proposal.encryption</span> and <span className="mono">ike.selected_proposal.dh_group</span>.</div>
        <button className="button button-primary full-button" onClick={run} disabled={loading || !data?.ike}>{loading ? <><span className="spinner"/>Running simulation…</> : <><FlaskConical size={16}/> Run deterministic simulation</>}</button>
        {!data && <p className="sim-hint">Upload a capture first to provide current IKE evidence.</p>}
      </Card>
      <div className="simulation-results">
        {error && <ErrorBanner message={error} onRetry={data?.ike ? run : undefined}/>}
        {!result && !error && <div className="simulation-empty"><div className="sim-empty-icon"><FlaskConical size={22}/></div><strong>Scenario results will appear here</strong><p>Run a simulation to compare current and projected scores and findings.</p><Tag tone="blue">NO LIVE CHANGES APPLIED</Tag></div>}
        {result && <>
          <div className="score-compare"><div className="compare-score"><span>CURRENT SCORE</span><strong>{current == null ? 'N/A' : `${formatValue(current)} / 100`}</strong><small>{result.current?.score?.risk_level || 'NOT ASSESSED'}</small></div><ArrowRight size={18}/><div className="compare-score projected"><span>PROJECTED SCORE</span><strong>{projected == null ? 'N/A' : `${formatValue(projected)} / 100`}</strong><small>{result.projected?.score?.risk_level || 'NOT ASSESSED'}</small></div><div className={`delta-score ${(result.score_delta || 0) > 0 ? 'delta-up' : (result.score_delta || 0) < 0 ? 'delta-down' : ''}`}><span>SCORE DELTA</span><strong>{result.score_delta == null ? 'N/A' : `${result.score_delta > 0 ? '+' : ''}${formatValue(result.score_delta)}`}</strong></div></div>
          <Card title="Applied scenario changes" eyebrow="SIMULATION INPUT DELTA"><div className="change-list">{result.changes?.map((change, i) => <div className="change-row" key={i}><span className="mono">{formatValue(change.field)}</span><span>{formatValue(change.previous_value, 'Not observed')}</span><ArrowRight size={14}/><strong>{formatValue(change.projected_value)}</strong></div>)}</div></Card>
          <Card title="Projected findings" eyebrow="DETERMINISTIC RULE OUTPUT" action={<Tag>{formatValue(result.projected?.assessment?.finding_count, 'N/A')} findings</Tag>}>{result.projected?.assessment?.findings?.length ? <div className="projected-findings">{result.projected.assessment.findings.map((finding, i) => <div className="projected-finding" key={finding.rule_id || i}><span><strong>{formatValue(finding.name)}</strong><small>{formatValue(finding.category)}</small></span><Tag tone={finding.severity === 'high' || finding.severity === 'critical' ? 'red' : finding.severity === 'medium' ? 'amber' : 'green'}>{formatValue(finding.severity)}</Tag><ProvenanceBadge value={finding.provenance}/><p>{formatValue(finding.description)}</p></div>)}</div> : <div className="sim-no-findings">No projected findings returned.</div>}</Card>
          <div className="simulation-foot"><RotateCcw size={13}/><span>{result.live_changes_applied === false ? 'No live changes applied' : 'Simulation result'} · Deterministic security rules · Source: {formatValue(result.source, 'deterministic_security_rules')}</span></div>
        </>}
      </div>
    </div>
  </div>;
}
