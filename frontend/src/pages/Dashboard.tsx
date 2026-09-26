import { Activity, ArrowDownRight, ArrowUpRight, Bot, Crosshair, Eye, Fingerprint, Gauge, Layers3, LockKeyhole, Radio, Shield, ShieldCheck, Sparkles } from 'lucide-react';
import type { AnalysisResponse } from '../api/types';
import { CategoryChart } from '../components/Charts';
import { Card, EmptyState, formatValue, ProvenanceBadge, StatCard, Tag } from '../components/ui';

export function Dashboard({ data, onAnalyze }: { data: AnalysisResponse | null; onAnalyze: () => void }) {
 const score = data?.score; const ike = data?.ike; const esp = data?.esp; const assessment = data?.assessment; const flows = data?.traffic_intelligence?.flows || [];
 const confidenceValues = flows.map((flow) => flow.classification?.confidence).filter((value): value is number => value != null);
 const confidence = confidenceValues.length ? confidenceValues.reduce((sum, value) => sum + value, 0) / confidenceValues.length : null;
 const metadataCounts = flows.map((flow) => flow.metadata_exposure?.finding_count).filter((value): value is number => value != null);
 const metadataFindingCount = metadataCounts.length ? metadataCounts.reduce((sum, value) => sum + value, 0) : null;
 return <div className="page-stack">
  <div className="welcome-banner"><div><div className="eyebrow"><span className="live-dot"/> IPSEC SECURITY INTELLIGENCE</div><h1>Security operations, <span>in focus.</span></h1><p>Evidence led analysis for encrypted network traffic.</p></div><button className="button button-primary" onClick={onAnalyze}><Crosshair size={16}/> Analyze a PCAP</button><div className="welcome-art"><div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="orbit-core"><Shield size={30}/></div></div></div>
  {!data && <div className="intro-note"><Sparkles size={15}/> Upload a capture to begin. Dashboard values will reflect backend analysis only.</div>}
  <div className="stat-grid">
   <StatCard label="SECURITY SCORE" value={score?.score == null ? 'N/A' : <>{formatValue(score.score)}<small className="suffix">/100</small></>} note={<><Tag tone={score?.risk_level === 'NOT_ASSESSED' || !score?.risk_level ? 'amber' : score.risk_level.toUpperCase() === 'LOW' ? 'green' : 'amber'}>{score?.risk_level || 'NOT ASSESSED'}</Tag><span>deterministic assessment</span></>} icon={<Gauge size={17}/>} color="cyan"/>
   <StatCard label="SCORING COVERAGE" value={score?.scoring_coverage == null ? 'N/A' : `${formatValue(score.scoring_coverage)}%`} note="Weighted categories assessed" icon={<Layers3 size={17}/>} color="green"/>
   <StatCard label="IKE VERSION" value={ike?.observed ? formatValue(ike.version, 'Not observed') : 'Not observed'} note={ike?.observed ? <ProvenanceBadge value="OBSERVED"/> : 'No IKE evidence'} icon={<Radio size={17}/>} color="cyan"/>
   <StatCard label="ESP PACKETS" value={formatValue(esp?.packet_count, 'Not observed')} note={esp?.observed ? <ProvenanceBadge value="OBSERVED"/> : 'No ESP evidence'} icon={<Activity size={17}/>} color="green"/>
   <StatCard label="TRAFFIC FLOWS" value={formatValue(data?.traffic_intelligence?.flow_count, 'N/A')} note="Bidirectional endpoint flows" icon={<Fingerprint size={17}/>} color="cyan"/>
   <StatCard label="AI CONFIDENCE" value={confidence == null ? 'N/A' : `${formatValue(confidence * 100)}%`} note={<><ProvenanceBadge value="INFERRED"/> metadata based</>} icon={<Bot size={17}/>} color="amber"/>
  </div>
  <div className="grid-two">
   <CategoryChart score={score}/>
   <Card title="Negotiated cryptography" eyebrow="DIRECT PROTOCOL EVIDENCE"><div className="crypto-list">
    {[['Encryption', ike?.selected_proposal?.encryption, <LockKeyhole size={15}/>],['PRF', ike?.selected_proposal?.prf, <ShieldCheck size={15}/>],['Integrity', ike?.selected_proposal?.integrity, <ShieldCheck size={15}/>],['DH group', ike?.selected_proposal?.dh_group, <Layers3 size={15}/>]].map(([label,value,icon])=><div className="crypto-row" key={String(label)}><span className="crypto-icon">{icon}</span><span className="crypto-label">{label}</span><strong>{ike?.observed ? formatValue(value, 'Not observed') : 'Not observed'}</strong></div>)}
    </div><div className="card-foot"><span>Proposal fields are packet observations.</span><ProvenanceBadge value={ike?.selected_proposal?.provenance || 'NOT_ASSESSED'}/></div></Card>
  </div>
  <div className="grid-two">
   <Card title="Traffic inference" eyebrow="AI-ASSISTED METADATA-BASED TRAFFIC INFERENCE" action={<Tag tone="blue">INFERRED</Tag>}>
    {flows.length ? <div className="inference-list">{flows.slice(0,3).map((flow,index)=><div className="inference-row" key={index}><span className="flow-index">0{index+1}</span><span className="flow-main"><strong>{flow.classification?.predicted_class || 'N/A'}</strong><small>{formatValue(flow.features?.flow_source, 'Not observed')} <ArrowUpRight size={12}/> {formatValue(flow.features?.flow_destination, 'Not observed')}</small></span><span className="flow-confidence">{flow.classification?.confidence == null ? 'N/A' : `${formatValue(flow.classification.confidence*100)}%`}<small>confidence</small></span></div>)}</div> : <EmptyState title="No traffic flows" description={data ? 'No class predictions were returned for this capture.' : 'Analyze a PCAP to view inferred traffic classes.'}/>}
    <div className="notice"><Eye size={14}/> Encrypted payloads are not decrypted or inspected.</div>
   </Card>
   <Card title="Metadata exposure" eyebrow="OBSERVABLE TRAFFIC CHARACTERISTICS">
    {flows.length ? <div className="exposure-summary"><div className="exposure-level"><span className={`exposure-pip exposure-${(flows[0]?.metadata_exposure?.overall_exposure || 'none').toLowerCase()}`}/><strong>{flows[0]?.metadata_exposure?.overall_exposure || 'N/A'}</strong></div><p>{flows[0]?.metadata_exposure?.summary || 'Not assessed'}</p><div className="exposure-bottom"><span>{formatValue(metadataFindingCount, 'N/A')} metadata findings</span><ProvenanceBadge value="ASSESSED"/></div></div> : <EmptyState title="Not assessed" description="Metadata exposure summaries appear when traffic flows are available."/>}
   <div className="notice"><ArrowDownRight size={14}/> Findings describe potential inference from metadata.</div>
   </Card>
  </div>
  <div className="bottomline"><span><ShieldCheck size={15}/> {formatValue(assessment?.finding_count, 'N/A')} security findings</span><span>Capture: {formatValue(data?.pcap?.filename, 'No PCAP analyzed')}</span><span>Source: direct capture evidence</span></div>
 </div>;
}
