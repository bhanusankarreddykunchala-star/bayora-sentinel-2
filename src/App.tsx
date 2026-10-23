import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
const API_BASE_URL = import.meta.env.VITE_API_URL || '';
import {
  AlertTriangle,
  ArrowRight,
  Bell,
  CheckCircle2,
  Cpu,
  Database,
  Gauge,
  KeyRound,
  LayoutGrid,
  Lock,
  Network,
  Radar,
  Search,
  Shield,
  ShieldCheck,
  ShieldOff,
  Sparkles,
  Target,
  TerminalSquare,
  UserCheck,
  Workflow,
  type LucideIcon,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

type EventEntry = {
  id: string;
  timestamp: string;
  actor_id: string;
  actor_role: string;
  tenant_id: string;
  event_type: string;
  outcome: string;
  severity: string;
  message: string;
  policy_id?: string;
  session_id?: string;
  acknowledged?: boolean;
  acknowledged_by?: string | null;
  acknowledged_at?: string | null;
};

type NavItem = {
  id: PageId;
  label: string;
  icon: LucideIcon;
};

type PageId =
  | 'overview'
  | 'red-team'
  | 'blue-team'
  | 'client-ai'
  | 'agent-sessions'
  | 'identity-access'
  | 'tools-policies'
  | 'leakage-detection'
  | 'isolation-testing'
  | 'security-alerts'
  | 'audit-trail'
  | 'compliance'
  | 'reports'
  | 'settings';

type AuditRow = {
  event_id: string;
  timestamp: string;
  actor_id: string;
  actor_role: string;
  tenant_id: string;
  event_type: string;
  outcome: string;
  policy_id: string;
  current_hash: string;
};

type RedTeamSession = {
  session_id: string;
  tenant_id: string;
  status: string;
  scenario: string;
};

type BlueTeamPolicy = {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  status: string;
  private: boolean;
};

const navItems: NavItem[] = [
  { id: 'overview', label: 'Overview', icon: LayoutGrid },
  { id: 'red-team', label: 'Red Team', icon: Target },
  { id: 'blue-team', label: 'Blue Team', icon: ShieldCheck },
  { id: 'client-ai', label: 'Client AI Sandbox', icon: Network },
  { id: 'agent-sessions', label: 'Agent Sessions', icon: Workflow },
  { id: 'identity-access', label: 'Identity & Access', icon: UserCheck },
  { id: 'tools-policies', label: 'Tools & Policies', icon: KeyRound },
  { id: 'leakage-detection', label: 'Leakage Detection', icon: Radar },
  { id: 'isolation-testing', label: 'Isolation Testing', icon: Lock },
  { id: 'security-alerts', label: 'Security Alerts', icon: AlertTriangle },
  { id: 'audit-trail', label: 'Audit Trail', icon: Database },
  { id: 'compliance', label: 'Compliance & Evidence', icon: Shield },
  { id: 'reports', label: 'Reports', icon: TerminalSquare },
  { id: 'settings', label: 'Settings', icon: Sparkles },
];

const timelineStages = [
  'Test Request',
  'Threat Classification',
  'Test Plan',
  'Policy Enforcement',
  'Model Execution',
  'Response Inspection',
  'Audit Recording',
];

const chartData = [
  { name: '01', latency: 220, hardened: 240 },
  { name: '03', latency: 190, hardened: 210 },
  { name: '05', latency: 240, hardened: 255 },
  { name: '07', latency: 260, hardened: 290 },
  { name: '09', latency: 230, hardened: 280 },
  { name: '11', latency: 210, hardened: 250 },
  { name: '13', latency: 185, hardened: 215 },
];

const defaultOverview = {
  overall_status: 'Unavailable',
  security_score: 0,
  active_sessions: 0,
  blocked_access_attempts: 0,
  detected_canaries: 0,
  audit_status: 'Unavailable',
  isolation_tests: 0,
  avg_latency_ms: 0,
  security_overhead_pct: 0,
  recent_events: [] as EventEntry[],
};

const formatHash = (value?: string) => {
  if (!value) return 'n/a';
  if (value.length <= 12) return value;
  return `${value.slice(0, 6)}…${value.slice(-6)}`;
};

export default function App() {
  const [activeSection, setActiveSection] = useState<PageId>(() => (
    navItems.find(({ id }) => id === window.location.hash.slice(1))?.id ?? 'overview'
  ));
  const [searchOpen, setSearchOpen] = useState(false);
  const [eventQuery, setEventQuery] = useState('');
  const [showRunDetails, setShowRunDetails] = useState(false);
  const [detailEvent, setDetailEvent] = useState<EventEntry | null>(null);
  const [overview, setOverview] = useState(defaultOverview);
  const [events, setEvents] = useState<EventEntry[]>([]);
  const [audit, setAudit] = useState<{
    verified: boolean;
    total_verified_events: number;
    failed_integrity_checks: string[];
    verification_timestamp: string;
    records: AuditRow[];
  } | null>(null);
  const [scorecard, setScorecard] = useState<Record<string, any> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [canaryPayload, setCanaryPayload] = useState({
    session_id: 'session-red-1',
    tenant_id: 'tenant-red',
    content: 'User password=CANARY-RED-42; internal token should stay within tenant-red',
  });
  const [canaryResult, setCanaryResult] = useState<{ detections: number; matches: any[]; boundary: string | null; message?: string } | null>(null);
  const [canaryError, setCanaryError] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [canaryHistory, setCanaryHistory] = useState<Array<{ id: string; session_id: string; tenant_id: string; detections: number; boundary: string | null; timestamp: string }>>([]);
  const [securityAlerts, setSecurityAlerts] = useState<EventEntry[]>([]);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [acknowledgingAlertId, setAcknowledgingAlertId] = useState<string | null>(null);
  const [alertActionMessage, setAlertActionMessage] = useState<string | null>(null);
  const [alertActionError, setAlertActionError] = useState<string | null>(null);
  const [moduleLoading, setModuleLoading] = useState(false);
  const [moduleError, setModuleError] = useState<string | null>(null);
  const [redTeamSessions, setRedTeamSessions] = useState<RedTeamSession[]>([]);
  const [blueTeamPolicies, setBlueTeamPolicies] = useState<BlueTeamPolicy[]>([]);
  const [selectedAgentSessionId, setSelectedAgentSessionId] = useState('');
  const [agentSessionQuery, setAgentSessionQuery] = useState('');
  const [selectedClientSessionId, setSelectedClientSessionId] = useState('session-red-1');
  const [clientSession, setClientSession] = useState<Record<string, string> | null>(null);
  const [identity, setIdentity] = useState<{ username: string; role: string; tenant_id: string } | null>(null);
  const [latestReport, setLatestReport] = useState<Record<string, any> | null>(null);

  const loadSecurityAlerts = useCallback(async () => {
    if (!token) return;

    setAlertsLoading(true);
    setAlertActionError(null);
    try {
      const response = await fetch(`${API_BASE_URL}/api/security-alerts`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) {
        const result = await response.json();
        throw new Error(result.detail || 'Could not load security alerts.');
      }

      const result = await response.json();
      if (!Array.isArray(result.alerts)) {
        throw new Error('The security alerts endpoint returned an invalid response.');
      }
      setSecurityAlerts(result.alerts);
    } catch (loadError) {
      setAlertActionError(loadError instanceof Error ? loadError.message : 'Could not load security alerts.');
    } finally {
      setAlertsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (activeSection === 'security-alerts') {
      void loadSecurityAlerts();
    }
  }, [activeSection, loadSecurityAlerts]);

  useEffect(() => {
    if (!token) return;

    const loadModuleData = async () => {
      const request = async (url: string) => {
        const response = await fetch(`${API_BASE_URL}${url}`, { headers: { Authorization: `Bearer ${token}` } });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || `Could not load ${activeSection}.`);
        }
        return result;
      };

      setModuleError(null);
      if (!['red-team', 'blue-team', 'client-ai', 'agent-sessions', 'identity-access', 'tools-policies', 'reports'].includes(activeSection)) {
        return;
      }

      setModuleLoading(true);
      try {
        switch (activeSection) {
          case 'red-team':
          case 'agent-sessions': {
            const result = await request('/api/red-team/sessions');
            if (!Array.isArray(result.sessions)) throw new Error('The sessions endpoint returned an invalid response.');
            setRedTeamSessions(result.sessions);
            setSelectedAgentSessionId((current) => current || result.sessions[0]?.session_id || '');
            break;
          }
          case 'blue-team':
          case 'tools-policies': {
            const result = await request('/api/blue-team/policies');
            if (!Array.isArray(result.policies)) throw new Error('The policies endpoint returned an invalid response.');
            setBlueTeamPolicies(result.policies);
            break;
          }
          case 'client-ai':
            setClientSession(await request(`/api/client-sandbox/session/${encodeURIComponent(selectedClientSessionId)}`));
            break;
          case 'identity-access':
            setIdentity(await request('/api/me'));
            break;
          case 'reports':
            setLatestReport(await request('/api/reports/latest'));
            break;
        }
      } catch (loadError) {
        setModuleError(loadError instanceof Error ? loadError.message : `Could not load ${activeSection}.`);
      } finally {
        setModuleLoading(false);
      }
    };

    void loadModuleData();
  }, [activeSection, selectedClientSessionId, token]);

  const handleAcknowledgeAlert = async (alert: EventEntry) => {
    if (!token || alert.acknowledged) return;

    setAcknowledgingAlertId(alert.id);
    setAlertActionMessage(null);
    setAlertActionError(null);
    try {
      const response = await fetch(`${API_BASE_URL}/api/security-alerts/${encodeURIComponent(alert.id)}/acknowledge`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.detail || `Could not acknowledge alert ${alert.id}.`);
      }
      if (result.event_id !== alert.id || result.acknowledged !== true) {
        throw new Error('The backend did not confirm this alert acknowledgment.');
      }

      setSecurityAlerts((previous) => previous.map((item) => item.id === alert.id
        ? { ...item, acknowledged: true, acknowledged_by: result.acknowledged_by, acknowledged_at: result.acknowledged_at }
        : item));
      setAlertActionMessage(`Alert ${alert.id} acknowledged by ${result.acknowledged_by}. This state is kept until the API restarts.`);
    } catch (acknowledgeError) {
      setAlertActionError(acknowledgeError instanceof Error ? acknowledgeError.message : `Could not acknowledge alert ${alert.id}.`);
    } finally {
      setAcknowledgingAlertId(null);
    }
  };

  const downloadLatestReport = () => {
    if (!latestReport) return;

    const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: 'application/json' });
    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = `${latestReport.report_id || 'bayora-latest-report'}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
  };

  useEffect(() => {
    const login = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: 'admin', password: 'adminpass' }),
        });
        if (!response.ok) throw new Error('Login failed');
        const result = await response.json();
        setToken(result.access_token);
      } catch {
        setError('Backend is unavailable. Live telemetry and authenticated actions require the FastAPI service.');
        setLoading(false);
      }
    };

    void login();
  }, []);

  useEffect(() => {
    if (!token) return;

    const loadData = async () => {
      try {
        const [overviewResponse, eventsResponse, auditResponse, scorecardResponse] = await Promise.all([
          fetch(`${API_BASE_URL}/api/overview`, { headers: { Authorization: `Bearer ${token}` } }),
          fetch(`${API_BASE_URL}/api/events`, { headers: { Authorization: `Bearer ${token}` } }),
          fetch(`${API_BASE_URL}/api/audit/verify`, { headers: { Authorization: `Bearer ${token}` } }),
          fetch(`${API_BASE_URL}/api/scorecard`, { headers: { Authorization: `Bearer ${token}` } }),
        ]);

        if (!overviewResponse.ok || !eventsResponse.ok || !auditResponse.ok || !scorecardResponse.ok) {
          throw new Error('Could not load telemetry');
        }

        const overviewData = await overviewResponse.json();
        const eventsData = await eventsResponse.json();
        const auditData = await auditResponse.json();
        const scoreData = await scorecardResponse.json();

        setOverview(overviewData);
        setEvents(eventsData.events || []);
        setAudit({
          verified: auditData.verified,
          total_verified_events: auditData.total_verified_events || 0,
          failed_integrity_checks: auditData.failed_integrity_checks || [],
          verification_timestamp: auditData.verification_timestamp || '',
          records: Array.isArray(auditData.records) ? auditData.records.slice(0, 4).map((entry: any) => ({
            event_id: entry.event_id,
            timestamp: entry.timestamp,
            actor_id: entry.actor_id,
            actor_role: entry.actor_role,
            tenant_id: entry.tenant_id,
            event_type: entry.event_type,
            outcome: entry.outcome,
            policy_id: entry.policy_id,
            current_hash: entry.current_hash,
          })) : [],
        });
        setScorecard(scoreData.scorecard || null);
        setLoading(false);
      } catch {
        setError('Backend telemetry could not be loaded. Live values are unavailable until the API connection is restored.');
        setLoading(false);
      }
    };

    void loadData();
  }, [token]);

  const metricPayload = useMemo(() => {
    const eventStatus = audit ? (audit.verified ? 'Chain valid' : 'Verification failed') : 'Awaiting audit';
    return [
      { label: 'Active sessions', value: error ? 'Unavailable' : `${overview.active_sessions}`, detail: 'Monitored workloads', tone: 'blue' },
      { label: 'Blocked requests', value: error ? 'Unavailable' : `${overview.blocked_access_attempts}`, detail: 'Deny-by-default controls', tone: 'amber' },
      { label: 'Canary exposures', value: error ? 'Unavailable' : `${overview.detected_canaries}`, detail: 'Synthetic leak monitoring', tone: 'red' },
      { label: 'Verified audit events', value: audit ? `${audit.total_verified_events}` : 'Unavailable', detail: eventStatus, tone: 'green' },
      { label: 'Isolation tests', value: error ? 'Unavailable' : `${overview.isolation_tests}%`, detail: 'Backend-reported aggregate', tone: 'violet' },
      { label: 'Evidence score', value: error ? 'Unavailable' : `${overview.security_score}%`, detail: overview.overall_status, tone: 'cyan' },
    ];
  }, [audit, error, overview]);

  const scoreAggregate = useMemo(() => {
    if (!scorecard || Object.keys(scorecard).length === 0) {
      return error ? 0 : overview.security_score;
    }
    const total = Object.values(scorecard).reduce((sum: number, item: any) => {
      const tests = Number(item?.tests ?? 0);
      const passed = Number(item?.passed ?? 0);
      return sum + (tests > 0 ? (passed / tests) * 100 : 0);
    }, 0);
    return Math.round(total / Object.keys(scorecard).length);
  }, [error, overview.security_score, scorecard]);

  const liveAlertItems = (events.length ? events : overview.recent_events).slice(0, 4);

  const filteredEvents = useMemo(() => {
    const query = eventQuery.trim().toLowerCase();
    if (!query) return events;
    return events.filter((event) => [
      event.id,
      event.timestamp,
      event.actor_id,
      event.actor_role,
      event.tenant_id,
      event.event_type,
      event.outcome,
      event.severity,
      event.message,
      event.policy_id,
      event.session_id,
    ].some((value) => value?.toLowerCase().includes(query)));
  }, [eventQuery, events]);

  const auditCards = useMemo(() => {
    if (audit?.records?.length) {
      return audit.records.map((row) => ({
        event_id: row.event_id,
        timestamp: new Date(row.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) || row.timestamp,
        event_type: row.event_type,
        outcome: row.outcome,
        hash: formatHash(row.current_hash),
      }));
    }
    return [];
  }, [audit]);

  const closeEventSearch = () => {
    setSearchOpen(false);
    setEventQuery('');
  };

  const handleNavigation = (section: PageId) => {
    if (activeSection !== section) {
      window.history.pushState({}, '', `#${section}`);
    }
    setActiveSection(section);
    closeEventSearch();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  useEffect(() => {
    const handleHistoryNavigation = () => {
      const section = navItems.find(({ id }) => id === window.location.hash.slice(1))?.id ?? 'overview';
      setActiveSection(section);
      closeEventSearch();
    };
    window.addEventListener('popstate', handleHistoryNavigation);
    return () => window.removeEventListener('popstate', handleHistoryNavigation);
  }, []);

  const handleCanaryScan = async (event?: FormEvent<HTMLFormElement>) => {
    event?.preventDefault();

    if (!token) {
      setCanaryError('Authenticate first to use the live canary endpoint.');
      setCanaryResult(null);
      return;
    }
    if (!canaryPayload.session_id.trim() || !canaryPayload.tenant_id.trim() || !canaryPayload.content.trim()) {
      setCanaryError('Session ID, tenant ID, and synthetic content are required.');
      setCanaryResult(null);
      return;
    }

    setCanaryError(null);
    setCanaryResult(null);
    setIsScanning(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/canaries/scan`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(canaryPayload),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || 'Canary scan failed.');
      }
      if (typeof data.detections !== 'number' || !Array.isArray(data.matches)) {
        throw new Error('The canary scan endpoint returned an invalid response.');
      }
      setCanaryResult(data);
      setCanaryError(null);
      setCanaryHistory((previous) => [{
        id: `scan-${Date.now()}`,
        session_id: canaryPayload.session_id,
        tenant_id: canaryPayload.tenant_id,
        detections: Number(data.detections ?? 0),
        boundary: data.boundary ?? null,
        timestamp: new Date().toISOString(),
      }, ...previous].slice(0, 6));
    } catch (scanError) {
      setCanaryError(scanError instanceof Error ? scanError.message : 'Canary scan endpoint unavailable.');
      setCanaryResult(null);
    } finally {
      setIsScanning(false);
    }
  };

  const renderSection = () => {
    switch (activeSection) {
      case 'overview':
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Overview</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('reports')}>View evidence</button>
            </div>
            <div className="stack-grid">
              <div className="mini-card"><label>Security posture</label><strong>{error ? 'Unavailable' : `${scoreAggregate}%`}</strong><span>Evidence-based score</span></div>
              <div className="mini-card"><label>Blocked requests</label><strong>{error ? 'Unavailable' : overview.blocked_access_attempts}</strong><span>Deny-by-default controls</span></div>
              <div className="mini-card"><label>Audit status</label><strong>{audit ? (audit.verified ? 'Verified' : 'Failed') : 'Unverified'}</strong><span>{audit ? `${audit.total_verified_events} events checked` : 'Awaiting backend verification'}</span></div>
            </div>
          </div>
        );
      case 'red-team':
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Red team operations</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('audit-trail')}>Open run log</button>
            </div>
            {moduleError && <div className="status-danger" role="alert">{moduleError}</div>}
            {moduleLoading ? <div className="empty-state" role="status">Loading backend red-team sessions…</div> : (
              <div className="session-list">
                {redTeamSessions.map((session) => (
                  <article className="session-card" key={session.session_id}>
                    <div><span>Session</span><strong>{session.session_id}</strong></div>
                    <div><span>Scenario</span><strong>{session.scenario}</strong></div>
                    <div><span>Tenant</span><strong>{session.tenant_id}</strong></div>
                    <div><span>Backend status</span><strong>{session.status}</strong></div>
                  </article>
                ))}
                {redTeamSessions.length === 0 && <div className="empty-state">No sessions were returned by the backend.</div>}
              </div>
            )}
            <div className="module-note">The backend exposes existing session records but has no red-team test submission endpoint. No test result is generated here.</div>
          </div>
        );
      case 'blue-team':
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Blue team defense</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('tools-policies')}>Review policy</button>
            </div>
            {moduleError && <div className="status-danger" role="alert">{moduleError}</div>}
            {moduleLoading ? <div className="empty-state" role="status">Loading backend policies…</div> : (
              <div className="policy-list">
                {blueTeamPolicies.map((policy) => (
                  <article className="policy-card" key={policy.id}>
                    <div><span>{policy.id} · {policy.tenant_id}</span><strong>{policy.name}</strong></div>
                    <p>{policy.description}</p>
                    <span className="policy-status">{policy.status}{policy.private ? ' · private' : ''}</span>
                  </article>
                ))}
                {blueTeamPolicies.length === 0 && <div className="empty-state">No policies were returned by the backend.</div>}
              </div>
            )}
            <div className="module-note">Policies are read-only in the available backend API; policy editing and saving are not implemented.</div>
          </div>
        );
      case 'client-ai':
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Client AI sandbox</h3>
              <label className="session-picker">Session
                <select value={selectedClientSessionId} onChange={(event) => setSelectedClientSessionId(event.target.value)}>
                  <option value="session-red-1">session-red-1</option>
                  <option value="session-blue-1">session-blue-1</option>
                </select>
              </label>
            </div>
            {moduleError && <div className="status-danger" role="alert">{moduleError}</div>}
            {moduleLoading ? <div className="empty-state" role="status">Loading backend session…</div> : clientSession && (
              <div className="stack-grid">
                <div className="mini-card"><label>Model</label><strong>{clientSession.model}</strong><span>Reported by backend</span></div>
                <div className="mini-card"><label>Context scope</label><strong>{clientSession.context_scope}</strong><span>Session-scoped history</span></div>
                <div className="mini-card"><label>Status / tenant</label><strong>{clientSession.status}</strong><span>{clientSession.tenant_id}</span></div>
              </div>
            )}
            <div className="module-note">The backend supports reading isolated session metadata, but does not expose a model prompt or execution endpoint.</div>
          </div>
        );
      case 'agent-sessions': {
        const visibleAgentSessions = redTeamSessions.filter((session) => [
          session.session_id, session.tenant_id, session.status, session.scenario,
        ].some((value) => value.toLowerCase().includes(agentSessionQuery.trim().toLowerCase())));
        const selectedAgentSession = redTeamSessions.find((session) => session.session_id === selectedAgentSessionId);
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Agent sessions</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('client-ai')}>Open runtime</button>
            </div>
            {moduleError && <div className="status-danger" role="alert">{moduleError}</div>}
            <label className="module-search">Search sessions
              <input value={agentSessionQuery} onChange={(event) => setAgentSessionQuery(event.target.value)} placeholder="Session, tenant, status, or scenario" />
            </label>
            {moduleLoading ? <div className="empty-state" role="status">Loading backend sessions…</div> : (
              <div className="session-browser">
                <div className="session-list">
                  {visibleAgentSessions.map((session) => (
                    <button
                      type="button"
                      key={session.session_id}
                      className={`session-card session-select ${selectedAgentSessionId === session.session_id ? 'selected' : ''}`}
                      onClick={() => setSelectedAgentSessionId(session.session_id)}
                    >
                      <strong>{session.session_id}</strong><span>{session.scenario}</span><span>{session.status} · {session.tenant_id}</span>
                    </button>
                  ))}
                  {visibleAgentSessions.length === 0 && <div className="empty-state">No matching backend sessions.</div>}
                </div>
                {selectedAgentSession && (
                  <dl className="session-details">
                    <div><dt>Session ID</dt><dd>{selectedAgentSession.session_id}</dd></div>
                    <div><dt>Scenario</dt><dd>{selectedAgentSession.scenario}</dd></div>
                    <div><dt>Status</dt><dd>{selectedAgentSession.status}</dd></div>
                    <div><dt>Tenant</dt><dd>{selectedAgentSession.tenant_id}</dd></div>
                  </dl>
                )}
              </div>
            )}
          </div>
        );
      }
      case 'identity-access':
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Identity & access</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('tools-policies')}>Review policy</button>
            </div>
            {moduleError && <div className="status-danger" role="alert">{moduleError}</div>}
            {moduleLoading && <div className="empty-state" role="status">Loading authenticated identity…</div>}
            {identity && (
              <div className="stack-grid">
                <div className="mini-card"><label>Authenticated user</label><strong>{identity.username}</strong><span>Loaded from /api/me</span></div>
                <div className="mini-card"><label>Role</label><strong>{identity.role}</strong><span>Backend-enforced authorization</span></div>
                <div className="mini-card"><label>Tenant boundary</label><strong>{identity.tenant_id}</strong><span>Current authenticated tenant</span></div>
              </div>
            )}
            {!identity && !moduleLoading && !moduleError && !error && <div className="stack-grid">
              <div className="mini-card"><label>Auth</label><strong>Bearer token</strong><span>JWT-free local token flow</span></div>
              <div className="mini-card"><label>Roles</label><strong>Administrator / Red / Blue</strong><span>Least-privilege enforcement</span></div>
              <div className="mini-card"><label>Boundary</label><strong>{error ? 'Demo mode' : 'Tenant isolation'}</strong><span>Cross-tenant checks enforced</span></div>
            </div>}
          </div>
        );
      case 'tools-policies':
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Tools & policies</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('blue-team')}>View blue-team controls</button>
            </div>
            {moduleError && <div className="status-danger" role="alert">{moduleError}</div>}
            {moduleLoading && <div className="empty-state" role="status">Loading backend policy set…</div>}
            {!moduleLoading && !moduleError && blueTeamPolicies.length > 0 && (
              <div className="policy-list">
                {blueTeamPolicies.map((policy) => (
                  <article className="policy-card" key={policy.id}>
                    <div><span>{policy.id} · {policy.tenant_id}</span><strong>{policy.name}</strong></div>
                    <p>{policy.description}</p>
                    <span className="policy-status">{policy.status}{policy.private ? ' · private' : ''}</span>
                  </article>
                ))}
              </div>
            )}
            {!moduleLoading && !moduleError && blueTeamPolicies.length === 0 && <div className="empty-state">No policies were returned by the backend.</div>}
            <div className="module-note">The backend exposes policies as read-only; policy creation, editing, and saving are not available.</div>
          </div>
        );
      case 'leakage-detection':
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Leakage detection</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('reports')}>View evidence</button>
            </div>
            <div className="leakage-layout">
              <form className="leakage-form" onSubmit={handleCanaryScan}>
                <div className="field-group">
                  <label htmlFor="session-id">Session ID</label>
                  <input
                    id="session-id"
                    required
                    value={canaryPayload.session_id}
                    onChange={(event) => setCanaryPayload((previous) => ({ ...previous, session_id: event.target.value }))}
                  />
                </div>
                <div className="field-group">
                  <label htmlFor="tenant-id">Tenant ID</label>
                  <input
                    id="tenant-id"
                    required
                    value={canaryPayload.tenant_id}
                    onChange={(event) => setCanaryPayload((previous) => ({ ...previous, tenant_id: event.target.value }))}
                  />
                </div>
                <div className="field-group">
                  <label htmlFor="canary-content">Synthetic content</label>
                  <textarea
                    id="canary-content"
                    rows={5}
                    required
                    value={canaryPayload.content}
                    onChange={(event) => setCanaryPayload((previous) => ({ ...previous, content: event.target.value }))}
                  />
                </div>
                <button type="submit" className="primary-button" disabled={isScanning} aria-busy={isScanning}>
                  {isScanning ? 'Running test…' : 'Run Test'}
                </button>
              </form>

              <div className="leakage-results">
                <div className="result-header">Detection results</div>
                {canaryError && <div className="status-danger">{canaryError}</div>}
                {canaryResult ? (
                  <>
                    <div className="result-summary">
                      <strong>{canaryResult.detections}</strong>
                      <span>canary detections</span>
                    </div>
                    <div className="result-block">
                      <label>Boundary</label>
                      <strong>{canaryResult.boundary || 'No tenant boundary configured'}</strong>
                    </div>
                    {canaryResult.message && <div className="result-message">{canaryResult.message}</div>}
                    {canaryResult.matches.length > 0 ? (
                      <ul className="match-list">
                        {canaryResult.matches.map((match, index) => (
                          <li key={`${match.session_id}-${index}`}>
                            <span>{match.session_id}</span>
                            <strong>{match.observed_value_hash}</strong>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <div className="empty-state">No matching canary values observed in the supplied content.</div>
                    )}
                  </>
                ) : (
                  <div className="empty-state">Run a scan to inspect synthetic canary leakage.</div>
                )}
              </div>
            </div>

            <div className="history-panel">
              <div className="result-header">Event history</div>
              {canaryHistory.length === 0 ? (
                <div className="empty-state">No scans recorded yet.</div>
              ) : (
                <div className="history-list">
                  {canaryHistory.map((entry) => (
                    <div key={entry.id} className="history-item">
                      <div><span>{entry.timestamp}</span><strong>{entry.session_id}</strong></div>
                      <div>{entry.tenant_id}</div>
                      <div>{entry.detections} hits</div>
                      <div>{entry.boundary || 'n/a'}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        );
      case 'isolation-testing':
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Isolation testing</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('client-ai')}>Open sandbox</button>
            </div>
            <div className="stack-grid">
              <div className="mini-card"><label>Tenant boundaries</label><strong>{error ? 'Unavailable' : `${overview.isolation_tests}%`}</strong><span>Backend-reported aggregate</span></div>
              <div className="mini-card"><label>Canary exposures</label><strong>{error ? 'Unavailable' : overview.detected_canaries}</strong><span>Backend overview telemetry</span></div>
              <div className="mini-card"><label>Run capability</label><strong>Not available</strong><span>No isolation-test execution endpoint exists in the backend.</span></div>
            </div>
            <div className="module-note">The percentage shown is the aggregate supplied by /api/overview, not the result of a new isolation test run.</div>
          </div>
        );
      case 'security-alerts': {
        const unacknowledgedAlerts = securityAlerts.filter((alert) => !alert.acknowledged);
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Security alerts</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('audit-trail')}>Review event trail</button>
            </div>
            <div className="stack-grid">
              <div className="mini-card"><label>Unacknowledged events</label><strong>{unacknowledgedAlerts.length}</strong><span>Backend event stream</span></div>
              <div className="mini-card"><label>Blocked</label><strong>{error ? 'Unavailable' : overview.blocked_access_attempts}</strong><span>Denied by policy</span></div>
              <div className="mini-card"><label>Risk</label><strong>{error ? 'Unavailable' : (scoreAggregate > 80 ? 'Managed' : 'Elevated')}</strong><span>Current security posture</span></div>
            </div>
            {alertActionError && <div className="status-danger" role="alert">{alertActionError}</div>}
            {alertActionMessage && <div className="status-success" role="status">{alertActionMessage}</div>}
            {alertsLoading ? <div className="empty-state" role="status">Loading backend security events…</div> : (
              <div className="alert-list">
                {securityAlerts.map((alert) => (
                  <article className={`security-alert ${alert.acknowledged ? 'acknowledged' : ''}`} key={alert.id}>
                    <div className="security-alert-main">
                      <span className={`alert-severity severity-${alert.severity.toLowerCase()}`}>{alert.severity}</span>
                      <div>
                        <strong>{alert.event_type}</strong>
                        <p>{alert.message}</p>
                        <span>{alert.timestamp} · {alert.actor_id} · {alert.tenant_id}</span>
                      </div>
                    </div>
                    <div className="security-alert-actions">
                      {alert.acknowledged ? (
                        <span className="acknowledged-label">
                          Acknowledged by {alert.acknowledged_by} · {alert.acknowledged_at}
                        </span>
                      ) : (
                        <button
                          className="tiny-button"
                          type="button"
                          disabled={acknowledgingAlertId !== null}
                          aria-busy={acknowledgingAlertId === alert.id}
                          onClick={() => void handleAcknowledgeAlert(alert)}
                        >
                          {acknowledgingAlertId === alert.id ? 'Acknowledging…' : 'Acknowledge'}
                        </button>
                      )}
                    </div>
                  </article>
                ))}
                {securityAlerts.length === 0 && !alertActionError && <div className="empty-state">No backend security events are available.</div>}
              </div>
            )}
            <div className="module-note">Acknowledgment status is stored in API process memory and is cleared when the backend restarts.</div>
          </div>
        );
      }
      case 'audit-trail':
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Audit trail</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('compliance')}>View evidence</button>
            </div>
            <div className="audit-table">
              {auditCards.map((row) => (
                <div key={row.event_id} className="audit-row">
                  <div><span>{row.timestamp}</span><strong>{row.event_id}</strong></div>
                  <div>{row.event_type}</div>
                  <div>{row.outcome}</div>
                  <div>{row.hash}</div>
                </div>
              ))}
              {auditCards.length === 0 && <div className="empty-state">No verified audit records are available.</div>}
            </div>
          </div>
        );
      case 'compliance':
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Compliance & evidence</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('reports')}>Open report</button>
            </div>
            <div className="stack-grid">
              <div className="mini-card"><label>Audit verify</label><strong>{audit ? (audit.verified ? 'Verified' : 'Failed') : 'Unavailable'}</strong><span>Chain integrity status</span></div>
              <div className="mini-card"><label>Scorecard</label><strong>{error ? 'Unavailable' : `${scoreAggregate}/100`}</strong><span>Evidence-backed aggregate</span></div>
              <div className="mini-card"><label>Limitations</label><strong>Known</strong><span>Side-channel exposure remains</span></div>
            </div>
          </div>
        );
      case 'reports':
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Reports</h3>
              <button className="ghost-button" type="button" onClick={downloadLatestReport} disabled={!latestReport}>
                {latestReport ? 'Download latest report' : 'Report unavailable'}
              </button>
            </div>
            {moduleError && <div className="status-danger" role="alert">{moduleError}</div>}
            {moduleLoading && <div className="empty-state" role="status">Loading latest backend report…</div>}
            {latestReport && (
              <article className="report-card">
                <div><span>Backend report</span><strong>{latestReport.report_id}</strong></div>
                <div><span>Evaluation date</span><strong>{latestReport.evaluation_date}</strong></div>
                <div><span>Environment</span><strong>{latestReport.environment}</strong></div>
                <p>{latestReport.architecture_summary}</p>
                <div className="report-tests">
                  {Array.isArray(latestReport.tests) && latestReport.tests.map((test: { id: string; name: string; result: string; evidence_ref: string }) => (
                    <div key={test.id}><strong>{test.name}</strong><span>{test.result} · {test.evidence_ref}</span></div>
                  ))}
                </div>
              </article>
            )}
            <div className="stack-grid">
              <div className="mini-card"><label>Local status</label><strong>{audit ? (audit.verified ? 'Verified' : 'Failed') : 'Unavailable'}</strong><span>Audit verification state</span></div>
              <div className="mini-card"><label>Evidence score</label><strong>{error ? 'Unavailable' : `${scoreAggregate}/100`}</strong><span>From backend scorecard</span></div>
              <div className="mini-card"><label>Security overhead</label><strong>{error ? 'Unavailable' : `${overview.security_overhead_pct}%`}</strong><span>Backend overview telemetry</span></div>
            </div>
          </div>
        );
      case 'settings':
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Settings</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('tools-policies')}>Open policy controls</button>
            </div>
            <div className="stack-grid">
              <div className="mini-card"><label>Environment</label><strong>{error ? 'Demo only' : 'Local backend'}</strong><span>Current runtime state</span></div>
              <div className="mini-card"><label>Execution source</label><strong>{error ? 'Unavailable' : 'Live backend'}</strong><span>Runtime context</span></div>
              <div className="mini-card"><label>Audit export</label><strong>Not implemented</strong><span>Only the latest report JSON can be downloaded.</span></div>
            </div>
          </div>
        );
      default:
        return (
          <div className="section-panel">
            <div className="section-header">
              <h3>Overview</h3>
              <button className="ghost-button" type="button" onClick={() => handleNavigation('reports')}>View evidence</button>
            </div>
            <div className="stack-grid">
              <div className="mini-card"><label>Security posture</label><strong>{error ? 'Unavailable' : `${scoreAggregate}%`}</strong><span>Evidence-based score</span></div>
              <div className="mini-card"><label>Blocked requests</label><strong>{error ? 'Unavailable' : overview.blocked_access_attempts}</strong><span>Deny-by-default controls</span></div>
              <div className="mini-card"><label>Audit status</label><strong>{audit ? (audit.verified ? 'Verified' : 'Failed') : 'Unverified'}</strong><span>{audit ? `${audit.total_verified_events} events checked` : 'Awaiting backend verification'}</span></div>
            </div>
          </div>
        );
    }
  };

  const auditStatus = audit ? (audit.verified ? 'Verified' : 'Not fully verified') : 'Unavailable';
  const riskLabel = error ? 'Unavailable' : 'Live evidence';

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-row">
          <div className="brand-mark">B</div>
          <div>
            <div className="brand-name">Bayora Sentinel</div>
            <div className="brand-subtitle">Security Control Plane</div>
          </div>
        </div>

        <nav className="nav-menu">
          {navItems.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={`nav-item ${activeSection === id ? 'active' : ''}`}
              aria-current={activeSection === id ? 'page' : undefined}
              onClick={() => handleNavigation(id)}
              type="button"
            >
              <Icon size={16} />
              <span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="system-status-card">
          <div className="mini-label">System status</div>
          <div className="status-line"><span className={`status-dot ${error ? 'warn' : 'ok'}`} /> {error ? 'Backend unavailable' : 'Live system active'}</div>
          <div className="status-line"><span className="status-dot warn" /> {liveAlertItems.length} backend events</div>
          <div className="status-line"><span className="status-dot ok" /> {auditStatus}</div>
        </div>
      </aside>

      <main className="main-panel">
        <header className="top-bar">
          <div className="top-left">
            <div className="top-badge">AI SECURITY EXECUTION</div>
            <div className="top-title">{navItems.find((item) => item.id === activeSection)?.label || 'Overview'}</div>
          </div>
          <div className="top-right">
            <div className={`search-box ${searchOpen ? 'search-box-open' : ''}`}>
              <Search size={14} aria-hidden="true" />
              {searchOpen ? (
                <input
                  autoFocus
                  aria-label="Search event stream"
                  placeholder="Search event stream"
                  value={eventQuery}
                  onChange={(event) => setEventQuery(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Escape') {
                      closeEventSearch();
                    }
                  }}
                />
              ) : (
                <button
                  type="button"
                  className="search-trigger"
                  aria-expanded={searchOpen}
                  aria-controls="event-search-results"
                  onClick={() => setSearchOpen(true)}
                >
                  Search event stream
                </button>
              )}
            </div>
            <button
              className="ghost-button"
              type="button"
              onClick={() => {
                closeEventSearch();
                setDetailEvent(null);
                setShowRunDetails(true);
              }}
            >
              View run details
            </button>
          </div>
        </header>

        {searchOpen && (
          <section className="event-search-results" id="event-search-results" aria-label="Event search results">
            <div className="search-results-heading">
              <strong>{eventQuery.trim() ? `${filteredEvents.length} matching events` : 'Recent events'}</strong>
              <button className="tiny-button" type="button" onClick={closeEventSearch}>Close search</button>
            </div>
            {filteredEvents.length > 0 ? (
              <div className="search-results-list">
                {filteredEvents.slice(0, 20).map((event) => (
                  <button
                    className="search-result-row"
                    key={event.id}
                    type="button"
                    onClick={() => {
                      closeEventSearch();
                      setDetailEvent(event);
                      setShowRunDetails(true);
                    }}
                  >
                    <span>{event.timestamp}</span>
                    <strong>{event.event_type}</strong>
                    <span>{event.actor_id} · {event.tenant_id}</span>
                    <span className="search-result-outcome">{event.outcome}</span>
                  </button>
                ))}
              </div>
            ) : (
              <div className="empty-state">{events.length ? 'No events match this search.' : 'No backend event records are available to search.'}</div>
            )}
          </section>
        )}

        {activeSection !== 'overview' && (
          <section className="content-card active-page-content">
            {renderSection()}
          </section>
        )}

        {activeSection === 'overview' && <>
        <div className="timeline-card">
          <div className="timeline-stages">
            {timelineStages.map((stage, index) => (
              <div key={stage} className={`stage ${index <= 5 ? 'active' : ''}`}>
                <div className="stage-index">{index + 1}</div>
                <div className="stage-label">{stage}</div>
              </div>
            ))}
          </div>
        </div>

        <section className="execution-panel">
          <div className="panel-header compact">
            <div className="panel-kicker">Backend event records ({events.length})</div>
            <div className="panel-meta">Latest session: {events[0]?.session_id || 'Unavailable'}</div>
          </div>

          <div className="execution-table">
            <div className="table-header">
              <span>Event ID</span>
              <span>Event type</span>
              <span>Actor</span>
              <span>Tenant</span>
              <span>Policy</span>
              <span>Outcome</span>
              <span>Timestamp</span>
            </div>
            {events.slice(0, 5).map((event) => (
              <div key={event.id} className="table-row">
                <span>{event.id}</span>
                <span>{event.event_type}</span>
                <span>{event.actor_id}</span>
                <span>{event.tenant_id}</span>
                <span>{event.policy_id || 'Not recorded'}</span>
                <span className={`status-pill status-${event.outcome.toLowerCase()}`}>{event.outcome}</span>
                <span>{event.timestamp}</span>
              </div>
            ))}
            {events.length === 0 && <div className="empty-state">No backend event records are available.</div>}
          </div>
        </section>

        <section className="control-panel">
          <div className="control-plane">
            <div className="control-line allowed red-line" />
            <div className="control-line allowed blue-line" />
            <div className="control-line blocked path-line" />

            <div className="workload workload-left">
              <div className="workload-header">Red team workspace</div>
              <div className="workload-meta">Tenant: tenant-red</div>
              <div className="stat-block"><span>Events</span><strong>{error ? 'Unavailable' : events.length}</strong></div>
              <div className="stat-row"><span>Active sessions</span><strong>{error ? 'Unavailable' : overview.active_sessions}</strong></div>
            </div>

            <div className="workload workload-middle">
              <div className="workload-header">Security control plane</div>
              <div className="control-core"><ShieldCheck size={30} /></div>
              <div className="control-chip">Identity enforcement</div>
              <div className="control-chip secondary">Leakage detection</div>
            </div>

            <div className="workload workload-right">
              <div className="workload-header">Blue team defense</div>
              <div className="workload-meta">Private policies</div>
              <div className="stat-block"><span>Policies loaded</span><strong>{blueTeamPolicies.length || 'Not loaded'}</strong></div>
              <div className="stat-row"><span>Blocked</span><strong>{error ? 'Unavailable' : overview.blocked_access_attempts}</strong></div>
            </div>

            <div className="workload workload-bottom">
              <div className="workload-header">Client AI sandbox</div>
              <div className="workload-meta">{clientSession?.model || 'Select a session to load model metadata'}</div>
              <div className="stat-block"><span>Active sessions</span><strong>{error ? 'Unavailable' : overview.active_sessions}</strong></div>
              <div className="stat-row"><span>Context</span><strong>{clientSession?.context_scope || 'Not loaded'}</strong></div>
            </div>

            <div className="path-tag path-allowed">Permitted</div>
            <div className="path-tag path-blocked">Blocked</div>
          </div>
        </section>

        <section className="kpi-grid">
          {metricPayload.map((metric) => (
            <div key={metric.label} className="kpi-card">
              <div className="kpi-label">{metric.label}</div>
              <div className={`kpi-value ${metric.tone}`}>{metric.value}</div>
              <div className="kpi-detail">{metric.detail}</div>
            </div>
          ))}
        </section>

        <section className="content-card">
          {renderSection()}
        </section>

        <section className="audit-bar">
          <div className="audit-heading">
            <span>Audit trail</span>
            <button className="ghost-button" type="button" onClick={() => handleNavigation('audit-trail')}>View full audit log</button>
          </div>

          <div className="audit-cards">
            {auditCards.map((entry) => (
              <div key={entry.event_id} className="audit-card">
                <div className="audit-topline">{entry.timestamp}</div>
                <div className="audit-title">{entry.event_type}</div>
                <div className="audit-meta">{entry.event_id}</div>
                <div className="audit-status">{entry.outcome}</div>
                <div className="audit-hash">{entry.hash}</div>
              </div>
            ))}
            {auditCards.length === 0 && <div className="empty-state">No verified audit records are available.</div>}
          </div>
        </section>
        </>}
      </main>

      <aside className="side-panel">
        <div className="risk-card">
          <div className="panel-kicker">Risk gauge</div>
          <div className="score-ring">
            <div className="ring-core">
              <span>{error ? '—' : scoreAggregate}</span>
              <small>{riskLabel}</small>
            </div>
          </div>
          <div className="risk-scale">
            <span>Low</span>
            <span>Moderate</span>
            <span>High</span>
          </div>
          <div className="risk-note">{error ? 'Risk score unavailable because backend telemetry could not be loaded.' : 'Evidence score from current backend telemetry. Not a production certification.'}</div>
        </div>

        <div className="panel-card">
          <div className="panel-header compact lighter">
            <span>Live security alerts</span>
            <button className="tiny-button" type="button" onClick={() => handleNavigation('security-alerts')}>Review alerts</button>
          </div>
          {liveAlertItems.map((item) => (
            <div key={item.id} className="alert-item">
              <div className="alert-badge">{item.severity}</div>
              <div>
                <strong>{item.event_type}</strong>
                <div className="alert-time">{item.timestamp}</div>
              </div>
            </div>
          ))}
        </div>

        <div className="panel-card">
          <div className="panel-header compact lighter">
            <span>Resource monitoring</span>
          </div>
          <div className="resource-metric">
            <div className="metric-row"><span>CPU</span><strong>Not reported by API</strong></div>
          </div>
          <div className="resource-metric">
            <div className="metric-row"><span>Memory</span><strong>Not reported by API</strong></div>
          </div>
          <div className="resource-metric">
            <div className="metric-row"><span>Backend latency</span><strong>{error ? 'Unavailable' : `${overview.avg_latency_ms} ms`}</strong></div>
            <div className="metric-row subtle"><span>Baseline</span><strong>Not reported by API</strong></div>
          </div>
        </div>

        <div className="panel-card">
          <div className="panel-header compact lighter">
            <span>Compliance & assurance</span>
          </div>
          <div className="assurance-list">
            <div className="assurance-item"><ShieldCheck size={14} /> Access control: {error ? 'unavailable' : 'backend telemetry loaded'}</div>
            <div className="assurance-item"><ShieldCheck size={14} /> Tenant isolation: {error ? 'unavailable' : 'aggregate telemetry only'}</div>
            <div className="assurance-item"><ShieldCheck size={14} /> Canary detection: {error ? 'unavailable' : 'backend telemetry loaded'}</div>
            <div className="assurance-item"><ShieldCheck size={14} /> Audit chain: {auditStatus}</div>
            <div className="assurance-item"><ShieldOff size={14} /> Residual side-channel risk remains</div>
          </div>
        </div>
      </aside>

      {loading && (
        <div className="modal-backdrop">
          <div className="loading-box">Loading Bayora Sentinel telemetry…</div>
        </div>
      )}

      {showRunDetails && (
        <div className="modal-backdrop details-backdrop" onClick={() => setShowRunDetails(false)}>
          <section
            className="details-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="run-details-title"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="details-modal-header">
              <div>
                <div className="panel-kicker">Backend event records</div>
                <h2 id="run-details-title">Run details</h2>
              </div>
              <button className="ghost-button" type="button" onClick={() => setShowRunDetails(false)}>Close</button>
            </div>
            {events.length === 0 ? (
              <div className="empty-state">No backend run records are available. Start the API and load telemetry to see run details.</div>
            ) : (
              <div className="details-modal-body">
                <div className="details-event-list">
                  {events.slice(0, 20).map((event) => (
                    <button
                      className={`details-event-item ${detailEvent?.id === event.id ? 'selected' : ''}`}
                      key={event.id}
                      type="button"
                      onClick={() => setDetailEvent(event)}
                    >
                      <span>{event.timestamp}</span>
                      <strong>{event.event_type}</strong>
                      <small>{event.outcome} · {event.actor_id}</small>
                    </button>
                  ))}
                </div>
                {detailEvent && (
                  <dl className="details-event-fields">
                    <div><dt>Event ID</dt><dd>{detailEvent.id}</dd></div>
                    <div><dt>Session</dt><dd>{detailEvent.session_id || 'Not recorded'}</dd></div>
                    <div><dt>Tenant</dt><dd>{detailEvent.tenant_id}</dd></div>
                    <div><dt>Actor</dt><dd>{detailEvent.actor_id} ({detailEvent.actor_role})</dd></div>
                    <div><dt>Policy</dt><dd>{detailEvent.policy_id || 'Not recorded'}</dd></div>
                    <div><dt>Message</dt><dd>{detailEvent.message || 'Not recorded'}</dd></div>
                  </dl>
                )}
              </div>
            )}
          </section>
        </div>
      )}

      {error && <div className="toast" role="status">{error}</div>}
    </div>
  );
}
