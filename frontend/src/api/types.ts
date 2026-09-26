export type Provenance = 'OBSERVED' | 'INFERRED' | 'ASSESSED' | 'NOT_ASSESSED' | 'NOT_APPLICABLE' | string;
export interface PcapInfo { path?: string | null; filename?: string | null }
export interface IKEExchange { frame?: number | null; source?: string | null; destination?: string | null; version?: string | null; exchange_type?: string | null; provenance?: Provenance }
export interface IKEProposal { frame?: number | null; source?: string | null; destination?: string | null; initiator_spi?: string | null; responder_spi?: string | null; encryption?: string | null; encryption_id?: number | null; prf?: string | null; prf_id?: number | null; integrity?: string | null; dh_group?: string | null; dh_group_id?: number | null; provenance?: Provenance }
export interface EvidenceItem { type?: string; provenance?: Provenance; source?: string; field?: string; value?: unknown }
export interface IKEData { observed?: boolean; protocol?: string; version?: string | null; exchanges?: IKEExchange[]; selected_proposal?: IKEProposal | null; evidence?: EvidenceItem[] }
export interface ESPPacket { frame?: number | null; timestamp?: number | null; length?: number | null; source?: string | null; destination?: string | null; spi?: string | null; sequence?: number | null; provenance?: Provenance }
export interface ESPDirection { source?: string | null; destination?: string | null; spi?: string | null; packet_count?: number | null; first_sequence?: number | null; last_sequence?: number | null; provenance?: Provenance }
export interface ESPData { observed?: boolean; protocol?: string; packet_count?: number | null; packets?: ESPPacket[]; directions?: ESPDirection[]; sequence_analysis?: { observed?: boolean; note?: string }; evidence?: EvidenceItem[] }
export interface Observation { field?: string; value?: unknown; provenance?: Provenance; source?: string }
export interface Control { control_id?: string; name?: string; status?: Provenance; reason?: string; category?: string | null; evidence_refs?: string[] }
export interface Finding { rule_id?: string; name?: string; category?: string; severity?: string; description?: string; recommendation?: string; provenance?: Provenance; evidence?: { field?: string; value?: unknown } }
export interface Assessment { observations?: Observation[]; controls?: Control[]; findings?: Finding[]; finding_count?: number; coverage?: { assessed?: number; total_applicable?: number; percentage?: number } }
export interface ScoreCategory { score?: number | null; weight?: number | null; finding_count?: number | null; assessed_control_count?: number | null }
export interface Score { score?: number | null; risk_level?: string | null; category_scores?: Record<string, ScoreCategory>; scoring_coverage?: number | null; assessed_control_count?: number | null }
export interface FlowFeatures { flow_source?: string | null; flow_destination?: string | null; packet_count?: number | null; total_bytes?: number | null; mean_packet_size?: number | null; std_packet_size?: number | null; min_packet_size?: number | null; max_packet_size?: number | null; mean_interarrival?: number | null; std_interarrival?: number | null; flow_duration?: number | null; packets_per_second?: number | null; bytes_per_second?: number | null; forward_packet_count?: number | null; reverse_packet_count?: number | null; forward_bytes?: number | null; reverse_bytes?: number | null; direction_ratio?: number | null; burst_count?: number | null; [key: string]: number | string | null | undefined }
export interface TopFeature { feature?: string; value?: number | null; shap_value?: number | null; direction?: string }
export interface Explanation { predicted_class?: string; confidence?: number; provenance?: Provenance; explanation_method?: string; top_features?: TopFeature[] }
export interface Classification { predicted_class?: string | null; confidence?: number | null; provenance?: Provenance; model_version?: string | null; model_type?: string | null; class_probabilities?: Record<string, number | null>; explanation?: Explanation | null }
export interface MetadataFinding { feature?: string; observed_value?: unknown; potential_inference?: string; exposure_level?: string; explanation?: string; recommendation?: string; provenance?: Provenance }
export interface MetadataExposure { observed?: boolean; provenance?: Provenance; overall_exposure?: string | null; finding_count?: number | null; summary?: string | null; findings?: MetadataFinding[] }
export interface TrafficFlow { features?: FlowFeatures; classification?: Classification; metadata_exposure?: MetadataExposure }
export interface TrafficIntelligence { flow_count?: number | null; flows?: TrafficFlow[] }
export interface AnalysisResponse { pcap?: PcapInfo; ike?: IKEData; esp?: ESPData; assessment?: Assessment; score?: Score; traffic_intelligence?: TrafficIntelligence }
export interface SimulationChange { field?: string; previous_value?: unknown; projected_value?: unknown }
export interface SimulationSide { assessment?: Assessment; score?: Score }
export interface SimulationResponse { simulation?: boolean; live_changes_applied?: boolean; source?: string; changes?: SimulationChange[]; current?: SimulationSide; projected?: SimulationSide; score_delta?: number | null }
