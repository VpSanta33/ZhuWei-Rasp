export interface AppInfo {
  id: number; name: string; env: string; language: string; owner: string; description: string
  app_key: string; app_secret?: string; policy_rev: number; created_at: number; updated_at: number
  online: number; total: number
}
export interface Install { app: AppInfo; properties: string; command: string }
export interface Instance {
  agent_id: string; app_id: number; app_name: string; hostname: string; ips: string; pid: number
  agent_version: string; language: string; runtime: string; server_type: string; os: string
  start_mode: string; config_version: string; metrics: string; registered_at: number; last_heartbeat: number; online: boolean
}
export interface Alarm {
  event_id: string; app_id: number; app_name: string; agent_id: string; hostname: string
  event_time: number; received_at: number; attack_type: string; algorithm: string; action: string
  confidence: number; url: string; client_ip: string; reason: string; matched_input: string; raw?: string; status: string
}
export interface Count { key: string; count: number }
export interface Stats {
  days: number; by_attack_type: Count[] | null; by_action: Count[] | null; by_client_ip: Count[] | null
  by_app: Count[] | null; by_day: Count[] | null; instances_total: number; instances_online: number
  instances_breaker: number; apps_total: number; kill_switch: boolean
}
export interface ComponentInfo { group: string; artifact: string; version: string; source: string; sha1: string; apps: string; instances: number }
export interface ComponentUse { app_name: string; env: string; agent_id: string; hostname: string; path: string }
export interface Whitelist { id: number; app_id: number; url: string; match: string; types: string; note: string; created_by: string; created_at: number }
export interface Audit { id: number; at: number; user: string; action: string; target: string; detail: string }
export interface Policy {
  mode: 'off' | 'monitor' | 'block'; checks: Record<string, { enabled: boolean; action: string }>
  [key: string]: unknown
}
export interface Settings { kill_switch: string; notify_webhook: string; notify_level: string; alarm_retention_days: string }
export interface SigningInfo { alg: string; key_id: string; public_key: string; pem: string }
export interface BlockConfirm { app: string; env: string; rules: string[]; prev_mode?: string; instances: number }
export interface InstanceMetrics { config_rejected?: number; config_reject_reason?: string; breaker_state?: string; [key: string]: unknown }
