import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Bell,
  Database,
  FileText,
  FileUp,
  Globe2,
  Shield,
  ShieldCheck,
  Trash2,
  Wifi,
  WifiOff,
  Gauge,
  RefreshCw,
  ChevronDown,
  Search,
  LayoutGrid,
  BarChart3,
  Radio,
  Settings,
  ServerCog,
} from 'lucide-react';
import './style.css';

const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api';

async function fetchApi(input, options) {
  try {
    return await fetch(input, options);
  } catch (error) {
    if (error instanceof TypeError) {
      window.dispatchEvent(new Event('nids:backend-unreachable'));
      const unavailable = new Error(`Backend not reachable at ${API}`);
      unavailable.name = 'BackendUnavailableError';
      throw unavailable;
    }
    throw error;
  }
}

const NAV_ITEMS = [
  { key: 'overview', label: 'Overview', icon: LayoutGrid },
  { key: 'monitor', label: 'Real-Time Monitor', icon: Radio },
  { key: 'traffic', label: 'Network Traffic', icon: BarChart3 },
  { key: 'pcap', label: 'PCAP Analyzer', icon: FileUp },
  { key: 'alerts', label: 'Security Alerts', icon: AlertTriangle },
  { key: 'incidents', label: 'Incident Management', icon: Shield },
  { key: 'assets', label: 'Network Assets', icon: Database },
  { key: 'intel', label: 'Threat Intelligence', icon: Globe2 },
  { key: 'rules', label: 'Detection Rules', icon: FileText },
  { key: 'reports', label: 'Reports', icon: FileText },
  { key: 'health', label: 'System Health', icon: Activity },
  { key: 'audit', label: 'Audit Logs', icon: Bell },
  { key: 'settings', label: 'Settings', icon: Settings },
];

const severityBadge = (value) => {
  const normalized = (value || '').toLowerCase();
  if (normalized.includes('critical')) return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  if (normalized === 'low') return 'low';
  return 'info';
};

const statusBadge = (value) => {
  const normalized = (value || '').toLowerCase();
  if (normalized.includes('resolve')) return 'resolved';
  if (normalized.includes('investig') || normalized.includes('ack')) return 'investigating';
  return 'new';
};

const formatDate = (value) => {
  if (!value) return '—';
  try {
    return `${new Date(value).toLocaleString()} ${Intl.DateTimeFormat().resolvedOptions().timeZone}`;
  } catch {
    return value;
  }
};

const formatBytes = (value) => {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let scaled = bytes;
  let unitIndex = -1;
  do {
    scaled /= 1024;
    unitIndex += 1;
  } while (scaled >= 1024 && unitIndex < units.length - 1);
  return `${scaled.toFixed(1)} ${units[unitIndex]}`;
};

const parseEvidence = (value) => {
  try {
    return typeof value === 'string' ? JSON.parse(value || '{}') : (value || {});
  } catch {
    return {};
  }
};

async function apiRequest(path, options = {}) {
  const token = window.localStorage.getItem('nids-access-token');
  const response = await fetchApi(`${API}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
    ...options,
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const error = new Error(body.detail || body.message || 'Request failed');
    if (response.status === 401) {
      error.status = 401;
      if (token && !path.startsWith('/auth/')) {
        window.localStorage.removeItem('nids-access-token');
        window.dispatchEvent(new Event('nids:auth-expired'));
      }
    }
    throw error;
  }
  return body;
}

function App() {
  const [authReady, setAuthReady] = useState(false);
  const [authSetupRequired, setAuthSetupRequired] = useState(false);
  const [user, setUser] = useState(null);
  const [authError, setAuthError] = useState('');
  const [backendUnavailable, setBackendUnavailable] = useState(false);
  const [page, setPage] = useState('overview');
  const [overview, setOverview] = useState({ alerts: [], severity_counts: {}, top_sources: [], top_destinations: [], protocol_counts: [] });
  const [stats, setStats] = useState({ total_alerts: 0, severity: {}, unique_sources: 0, total_packets: 0, open_incidents: 0, active_flows: 0 });
  const [alerts, setAlerts] = useState([]);
  const [traffic, setTraffic] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [analysts, setAnalysts] = useState([]);
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [assets, setAssets] = useState([]);
  const [rules, setRules] = useState([]);
  const [ruleHistory, setRuleHistory] = useState([]);
  const [ruleHistoryId, setRuleHistoryId] = useState(null);
  const [customRuleDefinition, setCustomRuleDefinition] = useState('{\n  "name": "Custom network indicator",\n  "description": "Describe a measurable indicator",\n  "severity": "medium",\n  "threshold": 10,\n  "time_window": 60,\n  "enabled": true,\n  "configuration": {}\n}');
  const [audit, setAudit] = useState([]);
  const [health, setHealth] = useState({});
  const [settings, setSettings] = useState({ monitoring: {}, retention_days: 30, severity_threshold: 'medium' });
  const [monitor, setMonitor] = useState({ available: false, interfaces: [], reason: null, session: { id: null, state: 'Not Configured' } });
  const [replay, setReplay] = useState({ id: null, state: 'Idle' });
  const [pcapResult, setPcapResult] = useState(null);
  const [pcapHistory, setPcapHistory] = useState([]);
  const [replaySpeed, setReplaySpeed] = useState(1);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [alertSearch, setAlertSearch] = useState('');
  const [alertFilter, setAlertFilter] = useState('all');
  const [alertSeverityFilter, setAlertSeverityFilter] = useState('all');
  const [alertPage, setAlertPage] = useState(0);
  const [alertSort, setAlertSort] = useState('timestamp');
  const [selectedAlertIds, setSelectedAlertIds] = useState([]);
  const [alertNotes, setAlertNotes] = useState([]);
  const [newAlertNote, setNewAlertNote] = useState('');
  const [trafficSearch, setTrafficSearch] = useState('');
  const [trafficFilter, setTrafficFilter] = useState('all');
  const [reportType, setReportType] = useState('alerts');
  const [reportData, setReportData] = useState(null);
  const [reportStart, setReportStart] = useState('');
  const [reportEnd, setReportEnd] = useState('');

  const initializeAuth = async () => {
    setAuthReady(false);
    setBackendUnavailable(false);
    setAuthError('');
    try {
      const status = await apiRequest('/auth/status');
      setAuthSetupRequired(!!status.setup_required);
      const token = window.localStorage.getItem('nids-access-token');
      if (!token) {
        setUser(null);
        return;
      }
      try {
        setUser(await apiRequest('/auth/me'));
      } catch (error) {
        window.localStorage.removeItem('nids-access-token');
        setUser(null);
        if (error.name === 'BackendUnavailableError' || error instanceof TypeError) throw error;
        setAuthError('Your saved session is invalid or expired. Please sign in again.');
      }
    } catch (error) {
      if (error.name === 'BackendUnavailableError' || error instanceof TypeError) {
        setBackendUnavailable(true);
      } else {
        setAuthError(error.message);
      }
    } finally {
      setAuthReady(true);
    }
  };

  useEffect(() => {
    initializeAuth();
  }, []);

  useEffect(() => {
    const handleAuthExpired = () => {
      setUser(null);
      setAuthError('Your session expired. Please sign in again.');
    };
    const handleBackendUnavailable = () => setBackendUnavailable(true);
    window.addEventListener('nids:auth-expired', handleAuthExpired);
    window.addEventListener('nids:backend-unreachable', handleBackendUnavailable);
    return () => {
      window.removeEventListener('nids:auth-expired', handleAuthExpired);
      window.removeEventListener('nids:backend-unreachable', handleBackendUnavailable);
    };
  }, []);

  const selectedAlert = useMemo(
    () => alerts.find((alert) => alert.id === Number(selectedAlertId)) || alerts[0] || null,
    [alerts, selectedAlertId],
  );

  const selectedIncident = useMemo(
    () => incidents.find((incident) => incident.id === Number(selectedIncidentId)) || incidents[0] || null,
    [incidents, selectedIncidentId],
  );

  const loadOverview = async () => {
    try {
      const [overviewData, statsData] = await Promise.all([
        apiRequest('/overview'),
        apiRequest('/stats'),
      ]);
      setOverview(overviewData || { alerts: [], severity_counts: {}, top_sources: [], top_destinations: [], protocol_counts: [] });
      setStats(statsData || { total_alerts: 0, severity: {}, unique_sources: 0, total_packets: 0, open_incidents: 0, active_flows: 0 });
    } catch (err) {
      setMessage(err.message);
    }
  };

  const loadAlerts = async () => {
    try {
      const params = new URLSearchParams({
        limit: '50',
        offset: String(alertPage * 50),
        sort_by: alertSort,
        order: 'desc',
      });
      if (alertSearch) params.set('search', alertSearch);
      if (alertFilter !== 'all') params.set('status', alertFilter);
      if (alertSeverityFilter !== 'all') params.set('severity', alertSeverityFilter);
      const data = await apiRequest(`/alerts?${params.toString()}`);
      setAlerts(data || []);
      if (!selectedAlertId && data.length) setSelectedAlertId(data[0].id);
    } catch (err) {
      setMessage(err.message);
    }
  };

  const loadAnalysts = async () => {
    try {
      setAnalysts(await apiRequest('/auth/users'));
    } catch (err) {
      setMessage(err.message);
    }
  };

  const loadTraffic = async () => {
    try {
      const data = await apiRequest(`/traffic/flows?limit=100&search=${encodeURIComponent(trafficSearch)}${trafficFilter !== 'all' ? `&protocol=${encodeURIComponent(trafficFilter)}` : ''}`);
      setTraffic(data || []);
    } catch (err) {
      setMessage(err.message);
    }
  };

  const loadIncidents = async () => {
    try {
      const data = await apiRequest('/incidents');
      setIncidents(data || []);
    } catch (err) {
      setMessage(err.message);
    }
  };

  const loadAssets = async () => {
    try {
      const data = await apiRequest('/assets');
      setAssets(data || []);
    } catch (err) {
      setMessage(err.message);
    }
  };

  const loadRules = async () => {
    try {
      const data = await apiRequest('/rules');
      setRules(data || []);
    } catch (err) {
      setMessage(err.message);
    }
  };

  const loadHealth = async () => {
    try {
      const data = await apiRequest('/system/health');
      setHealth(data || {});
    } catch (err) {
      setMessage(err.message);
    }
  };

  const loadMonitor = async () => {
    try {
      const [ifaceData, sessionData, settingsData] = await Promise.all([
        apiRequest('/monitor/interfaces'),
        apiRequest('/monitor/session'),
        apiRequest('/settings'),
      ]);
      setMonitor({
        available: !!ifaceData?.available,
        interfaces: ifaceData?.interfaces || [],
        reason: ifaceData?.reason || null,
        session: sessionData || { id: null, state: 'Not Configured' },
      });
      setSettings(settingsData || { monitoring: {}, retention_days: 30, severity_threshold: 'medium' });
    } catch (err) {
      setMessage(err.message);
    }
  };

  const loadReplayStatus = async () => {
    try {
      setReplay(await apiRequest('/monitor/replay/status'));
    } catch (err) {
      setMessage(err.message);
    }
  };

  const loadPcapHistory = async () => {
    try {
      setPcapHistory(await apiRequest('/pcap/history'));
    } catch (err) {
      setMessage(err.message);
    }
  };

  const loadAudit = async () => {
    try {
      const data = await apiRequest('/audit');
      setAudit(data || []);
    } catch (err) {
      setMessage(err.message);
    }
  };

  const loadReport = async () => {
    try {
      const params = new URLSearchParams({ report_type: reportType });
      if (reportStart) params.set('start', new Date(reportStart).toISOString());
      if (reportEnd) params.set('end', new Date(reportEnd).toISOString());
      const data = await apiRequest(`/reports?${params.toString()}`);
      setReportData(data || { report_type: reportType, records: [] });
    } catch (err) {
      setMessage(err.message);
    }
  };

  useEffect(() => {
    if (!user) return;
    if (page === 'overview') {
      loadOverview();
      loadMonitor();
    }
    if (page === 'alerts') {
      loadAlerts();
      loadAnalysts();
    }
    if (page === 'traffic') loadTraffic();
    if (page === 'incidents') loadIncidents();
    if (page === 'assets') loadAssets();
    if (page === 'rules') loadRules();
    if (page === 'health') loadHealth();
    if (page === 'monitor') loadMonitor();
    if (page === 'audit') loadAudit();
    if (page === 'settings') loadMonitor();
    if (page === 'reports') loadReport();
    if (page === 'pcap') loadPcapHistory();
    loadReplayStatus();
  }, [page, alertSearch, alertFilter, alertSeverityFilter, alertPage, alertSort, trafficSearch, trafficFilter, reportType, reportStart, reportEnd, user?.username]);

  useEffect(() => {
    if (!user || page !== 'alerts' || !selectedAlert) return;
    apiRequest(`/alerts/${selectedAlert.id}/notes`)
      .then(setAlertNotes)
      .catch((err) => setMessage(err.message));
  }, [page, selectedAlert?.id, user?.username]);

  useEffect(() => {
    if (!user || page !== 'incidents' || !selectedIncident) return;
    apiRequest(`/incidents/${selectedIncident.id}`)
      .then(setIncidentDetail)
      .catch((err) => setMessage(err.message));
  }, [page, selectedIncident?.id, user?.username]);

  useEffect(() => {
    if (!user) return undefined;
    const timer = setInterval(() => {
      if (page === 'overview') loadOverview();
      if (page === 'alerts') loadAlerts();
      if (page === 'traffic') loadTraffic();
      if (page === 'incidents') loadIncidents();
      if (page === 'assets') loadAssets();
      if (page === 'rules') loadRules();
      if (page === 'health') loadHealth();
      loadReplayStatus();
    }, 15000);
    return () => clearInterval(timer);
  }, [page, alertSearch, alertFilter, alertSeverityFilter, alertPage, alertSort, trafficSearch, trafficFilter, user?.username]);

  useEffect(() => {
    if (!user) return undefined;
    const timer = setInterval(loadReplayStatus, 1500);
    return () => clearInterval(timer);
  }, [user?.username]);

  const authenticate = async (credentials, setup) => {
    setAuthError('');
    try {
      const result = await apiRequest(setup ? '/auth/setup' : '/auth/login', {
        method: 'POST',
        body: JSON.stringify(credentials),
      });
      window.localStorage.setItem('nids-access-token', result.access_token);
      setAuthSetupRequired(false);
      setUser(result.user);
    } catch (error) {
      setAuthError(error.message);
    }
  };

  const logout = () => {
    window.localStorage.removeItem('nids-access-token');
    setUser(null);
    setPage('overview');
  };

  const uploadPcap = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setBusy(true);
    setMessage('');
    try {
      const form = new FormData();
      form.append('file', file);
      const token = window.localStorage.getItem('nids-access-token');
      const response = await fetchApi(`${API}/pcap`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: form,
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail || 'PCAP analysis failed');
      setPcapResult(payload);
      setMessage(`Analyzed ${payload.packets} packets and produced ${payload.alerts} alerts.`);
      await loadOverview();
      await loadAlerts();
      await loadTraffic();
      await loadPcapHistory();
    } catch (err) {
      setMessage(err.message);
      setPcapResult(null);
    } finally {
      setBusy(false);
      event.target.value = '';
    }
  };

  const refreshData = async () => {
    setMessage('Refreshing data from backend...');
    await Promise.all([loadOverview(), loadAlerts(), loadTraffic(), loadIncidents(), loadAssets(), loadRules(), loadHealth(), loadAudit(), loadMonitor()]);
    setMessage('Data refreshed.');
  };

  const clearAlertsAction = async () => {
    if (!window.confirm('Clear all stored alerts?')) return;
    try {
      const result = await apiRequest('/alerts', { method: 'DELETE' });
      setMessage(`Deleted ${result.deleted} alerts.`);
      await loadAlerts();
      await loadOverview();
    } catch (err) {
      setMessage(err.message);
    }
  };

  const closeIncident = async () => {
    if (!selectedIncident) return;
    const closureReason = window.prompt('Enter the incident closure reason:');
    if (!closureReason?.trim()) return;
    try {
      await apiRequest(`/incidents/${selectedIncident.id}/close`, {
        method: 'POST',
        body: JSON.stringify({ closure_reason: closureReason.trim() }),
      });
      await loadIncidents();
      setIncidentDetail(await apiRequest(`/incidents/${selectedIncident.id}`));
    } catch (err) {
      setMessage(err.message);
    }
  };

  const updateAlert = async (alertId, updates) => {
    try {
      await apiRequest(`/alerts/${alertId}`, { method: 'PATCH', body: JSON.stringify(updates) });
      await loadAlerts();
      setMessage(`Alert ${alertId} updated.`);
    } catch (err) {
      setMessage(err.message);
    }
  };

  const addAlertNote = async () => {
    if (!selectedAlert || !newAlertNote.trim()) return;
    try {
      await apiRequest(`/alerts/${selectedAlert.id}/notes`, { method: 'POST', body: JSON.stringify({ note: newAlertNote }) });
      setNewAlertNote('');
      setAlertNotes(await apiRequest(`/alerts/${selectedAlert.id}/notes`));
    } catch (err) {
      setMessage(err.message);
    }
  };

  const bulkUpdateAlerts = async (status) => {
    if (!selectedAlertIds.length) return;
    try {
      await apiRequest('/alerts/bulk', {
        method: 'POST',
        body: JSON.stringify({ alert_ids: selectedAlertIds, status }),
      });
      setSelectedAlertIds([]);
      await loadAlerts();
    } catch (err) {
      setMessage(err.message);
    }
  };

  const createIncidentFromAlert = async () => {
    if (!selectedAlert) return;
    try {
      const payload = {
        title: `Incident for ${selectedAlert.detection || selectedAlert.title}`,
        severity: selectedAlert.severity || 'medium',
        summary: `${selectedAlert.title} from ${selectedAlert.source_ip || 'unknown source'}`,
        assigned_analyst: user?.username || 'unassigned',
        alert_ids: [selectedAlert.id],
      };
      const result = await apiRequest('/incidents', { method: 'POST', body: JSON.stringify(payload) });
      setMessage(`Incident ${result.id} created.`);
      await loadIncidents();
      setSelectedIncidentId(result.id);
    } catch (err) {
      setMessage(err.message);
    }
  };

  const toggleRule = async (rule) => {
    try {
      await apiRequest(`/rules/${rule.id}`, { method: 'PATCH', body: JSON.stringify({ enabled: !rule.enabled }) });
      await loadRules();
      setMessage(`Rule ${rule.name} updated.`);
    } catch (err) {
      setMessage(err.message);
    }
  };

  const saveRuleChanges = async (rule, changes) => {
    try {
      await apiRequest(`/rules/${rule.id}`, { method: 'PATCH', body: JSON.stringify(changes) });
      await loadRules();
      setMessage(`Rule ${rule.name} updated.`);
    } catch (err) {
      setMessage(err.message);
    }
  };

  const createCustomRule = async () => {
    try {
      await apiRequest('/rules/custom', {
        method: 'POST',
        body: JSON.stringify({ definition: customRuleDefinition }),
      });
      await loadRules();
      setMessage('Custom detection rule created.');
    } catch (err) {
      setMessage(err.message);
    }
  };

  const showRuleHistory = async (ruleId) => {
    try {
      setRuleHistory(await apiRequest(`/rules/${ruleId}/history`));
      setRuleHistoryId(ruleId);
    } catch (err) {
      setMessage(err.message);
    }
  };

  const saveSettings = async () => {
    try {
      const result = await apiRequest('/settings', { method: 'POST', body: JSON.stringify(settings) });
      setMessage(result.saved ? 'Settings saved.' : 'Settings update failed.');
    } catch (err) {
      setMessage(err.message);
    }
  };

  const startReplay = async (analysisId) => {
    try {
      await apiRequest(`/pcap/${analysisId}/replay?speed=${encodeURIComponent(replaySpeed)}`, { method: 'POST' });
      await loadReplayStatus();
      setMessage('PCAP replay started. All pages will be marked REPLAY while playback is active.');
    } catch (err) {
      setMessage(err.message);
    }
  };

  const stopReplay = async () => {
    try {
      await apiRequest('/monitor/replay/stop', { method: 'POST' });
      await loadReplayStatus();
    } catch (err) {
      setMessage(err.message);
    }
  };

  const downloadReport = async (format) => {
    try {
      const params = new URLSearchParams({ report_type: reportType === 'summary' ? 'alerts' : reportType, format });
      if (reportStart) params.set('start', new Date(reportStart).toISOString());
      if (reportEnd) params.set('end', new Date(reportEnd).toISOString());
      const token = window.localStorage.getItem('nids-access-token');
      const response = await fetchApi(`${API}/reports/export?${params}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) {
        const body = await response.json();
        throw new Error(body.detail || 'Report export failed');
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = href;
      link.download = `nids-${reportType}.${format}`;
      link.click();
      URL.revokeObjectURL(href);
    } catch (err) {
      setMessage(err.message);
    }
  };

  const renderOverview = () => (
    <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Monitoring / Overview</p>
          <h1>Network overview</h1>
        </div>
        <div className="header-actions">
          <button onClick={refreshData} className="ghost-btn"><RefreshCw size={14} /> Refresh</button>
        </div>
      </div>

      <div className="kpi-grid">
        <MetricCard title="Total Alerts" value={stats.total_alerts || 0} subtitle="Stored detections" icon={<AlertTriangle size={16} />} />
        <MetricCard title="Critical Alerts" value={stats.severity?.critical || 0} subtitle="Severe events" icon={<ShieldCheck size={16} />} tone="critical" />
        <MetricCard title="High Severity" value={stats.severity?.high || 0} subtitle="Priority review" icon={<AlertTriangle size={16} />} tone="high" />
        <MetricCard title="Open Incidents" value={stats.open_incidents || 0} subtitle="Active investigations" icon={<Shield size={16} />} tone="warning" />
        <MetricCard title="Total Packets" value={stats.total_packets || 0} subtitle="Observed packet flow" icon={<BarChart3 size={16} />} />
        <MetricCard title="Active Flows" value={stats.active_flows || 0} subtitle="Current flow set" icon={<Gauge size={16} />} />
        <MetricCard title="Unique Sources" value={stats.unique_sources || 0} subtitle="Distinct source IPs" icon={<Globe2 size={16} />} />
        <MetricCard title="Capture State" value={monitor.session?.state || 'Offline PCAP'} subtitle={monitor.reason || 'Offline PCAP analysis'} icon={monitor.session?.state === 'Running' ? <Wifi size={16} /> : <WifiOff size={16} />} tone={monitor.session?.state === 'Running' ? 'good' : 'muted'} />
      </div>

      <div className="chart-grid">
        <Panel title="Alert severity distribution">
          <div className="bar-chart">
            {Object.keys(overview.severity_counts || {}).length ? Object.entries(overview.severity_counts).map(([label, value]) => (
              <div key={label} className="bar-row">
                <span>{label}</span>
                <div className="bar-track"><div className={`bar-fill ${severityBadge(label)}`} style={{ width: `${Math.min((Number(value) / Math.max(...Object.values(overview.severity_counts || {0:1})), 1) * 100, 100)}%` }} /></div>
                <strong>{value}</strong>
              </div>
            )) : <EmptyState text="No alert severity data available yet." />}
          </div>
        </Panel>
        <Panel title="Top source IPs">
          <ul className="list-stack">
            {overview.top_sources?.length ? overview.top_sources.map((row) => (
              <li key={row.label}><span>{row.label}</span><strong>{row.value}</strong></li>
            )) : <EmptyState text="No source activity recorded." />}
          </ul>
        </Panel>
        <Panel title="Protocol activity">
          <ul className="list-stack">
            {overview.protocol_counts?.length ? overview.protocol_counts.map((row) => (
              <li key={row.label}><span>{row.label}</span><strong>{row.value}</strong></li>
            )) : <EmptyState text="No protocol distribution yet." />}
          </ul>
        </Panel>
        <Panel title="Destination hotspots">
          <ul className="list-stack">
            {overview.top_destinations?.length ? overview.top_destinations.map((row) => (
              <li key={row.label}><span>{row.label}</span><strong>{row.value}</strong></li>
            )) : <EmptyState text="No destination data recorded." />}
          </ul>
        </Panel>
      </div>

      <Panel title="Recent security alerts">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Detection</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {overview.alerts?.length ? overview.alerts.map((alert) => (
                <tr key={alert.id} onClick={() => setSelectedAlertId(alert.id)}>
                  <td><span className={`badge ${severityBadge(alert.severity)}`}>{alert.severity}</span></td>
                  <td>{alert.title}</td>
                  <td>{alert.source_ip || '—'}</td>
                  <td>{alert.destination_ip || '—'}</td>
                  <td>{formatDate(alert.timestamp)}</td>
                </tr>
              )) : <tr><td colSpan="5"><EmptyState text="No recent alerts available." /></td></tr>}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );

  const renderMonitor = () => (
    <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Monitoring / Real-Time Monitor</p>
          <h1>Live monitoring</h1>
        </div>
      </div>
      <Panel title="Capture status">
        <div className="monitor-grid">
          <label className="field-box">
            <span>Network interface</span>
            <select
              value={settings.monitoring?.interface || ''}
              onChange={(event) => setSettings({ ...settings, monitoring: { ...(settings.monitoring || {}), interface: event.target.value } })}
              disabled={!monitor.interfaces.length}
            >
              {!monitor.interfaces.length && <option value="">No capture-capable interfaces</option>}
              {monitor.interfaces.map((item) => (
                <option
                  key={item.identifier || item.name}
                  value={item.name}
                  title={`${item.description || ''} — ${item.identifier || item.name}`}
                >
                  {item.friendly_name}{item.ip_address ? ` (${item.ip_address})` : ''}
                </option>
              ))}
            </select>
            {!!settings.monitoring?.interface && (
              <details>
                <summary>Adapter technical details</summary>
                <span>{monitor.interfaces.find((item) => item.name === settings.monitoring.interface)?.identifier || settings.monitoring.interface}</span>
              </details>
            )}
          </label>
          <Field label="State">{monitor.session?.state || 'Offline PCAP'}</Field>
          <Field label="Session ID">{monitor.session?.id || 'Unavailable'}</Field>
          <Field label="Capture readiness">{monitor.available ? 'Ready' : monitor.session?.state || 'Permission Required'}</Field>
          <Field label="Capture duration">{monitor.session?.state === 'Running' ? 'Live' : 'Not available in offline mode'}</Field>
          <Field label="Packet count">{monitor.session?.total_packets ?? 0}</Field>
          <Field label="Bytes/sec">{monitor.session?.bytes_per_second ?? 0}</Field>
        </div>
        <div className="button-row">
          <button
            onClick={() => apiRequest(`/monitor/start?interface_name=${encodeURIComponent(settings.monitoring?.interface || monitor.interfaces[0]?.name || '')}`, { method: 'POST' }).then(() => loadMonitor())}
            disabled={!monitor.available}
          >
            Start Monitoring
          </button>
          <button className="ghost-btn" onClick={() => apiRequest('/monitor/stop', { method: 'POST' }).then(() => loadMonitor())}>Stop Monitoring</button>
        </div>
        {monitor.reason && <p className="status-note">{monitor.reason}</p>}
      </Panel>
    </div>
  );

  const renderTraffic = () => (
    <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Monitoring / Network Traffic</p>
          <h1>Traffic analysis</h1>
        </div>
      </div>
      <div className="toolbar">
        <div className="search-wrap"><Search size={14} /><input value={trafficSearch} onChange={(e) => setTrafficSearch(e.target.value)} placeholder="Search IP address" /></div>
        <select value={trafficFilter} onChange={(e) => setTrafficFilter(e.target.value)}>
          <option value="all">All protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="ICMP">ICMP</option>
        </select>
      </div>
      <Panel title="Observed flows">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Source Port</th>
                <th>Destination Port</th>
                <th>Protocol</th>
                <th>Packet Count</th>
                <th>Bytes</th>
              </tr>
            </thead>
            <tbody>
              {traffic.length ? traffic.map((row) => (
                <tr key={row.id}>
                  <td>{formatDate(row.timestamp)}</td>
                  <td>{row.source_ip || '—'}</td>
                  <td>{row.destination_ip || '—'}</td>
                  <td>{row.source_port || '—'}</td>
                  <td>{row.destination_port || '—'}</td>
                  <td>{row.protocol || '—'}</td>
                  <td>{row.packet_count || 0}</td>
                  <td>{formatBytes(row.bytes)}</td>
                </tr>
              )) : <tr><td colSpan="8"><EmptyState text="No traffic observed yet." /></td></tr>}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );

  const renderPcap = () => (
    <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Monitoring / PCAP Analyzer</p>
          <h1>PCAP analysis</h1>
        </div>
      </div>
      <Panel title="Upload and analyze">
        <div className="upload-box">
          <label className="file-label">
            <FileUp size={16} /> {busy ? 'Uploading and analyzing...' : 'Choose PCAP or PCAPNG'}
            <input type="file" accept=".pcap,.pcapng" onChange={uploadPcap} disabled={busy} />
          </label>
          <div className="status-note">PCAP size limit: 50 MB. Files are processed locally and stored in the project data directory.</div>
          <label className="field-block">
            <span>Replay speed</span>
            <select value={replaySpeed} onChange={(event) => setReplaySpeed(Number(event.target.value))}>
              <option value="0.5">0.5×</option>
              <option value="1">1×</option>
              <option value="2">2×</option>
              <option value="5">5×</option>
              <option value="10">10×</option>
            </select>
          </label>
        </div>
        {pcapResult && (
          <div className="stats-grid">
            <MetricCard title="Packets" value={pcapResult.packets} subtitle="Analyzed packets" />
            <MetricCard title="Alerts" value={pcapResult.alerts} subtitle="New stored detections" />
            <MetricCard title="Flows" value={pcapResult.flows} subtitle="Aggregated 5-tuples" />
            <MetricCard title="Unique IPs" value={pcapResult.unique_ips} subtitle="Observed endpoints" />
          </div>
        )}
      </Panel>
      {pcapResult && (
        <div className="chart-grid">
          <Panel title="Protocol distribution">
            <ul className="list-stack">
              {Object.entries(pcapResult.protocols || {}).map(([protocol, count]) => <li key={protocol}><span>{protocol}</span><strong>{count}</strong></li>)}
            </ul>
          </Panel>
          <Panel title="Top talkers by bytes">
            <ul className="list-stack">
              {(pcapResult.top_talkers || []).map((row) => <li key={row.ip}><span>{row.ip}</span><strong>{formatBytes(row.bytes)}</strong></li>)}
            </ul>
          </Panel>
        </div>
      )}
      <Panel title="Analysis history">
        <div className="table-wrap">
          <table>
            <thead><tr><th>Capture</th><th>Analyzed</th><th>Packets</th><th>Alerts</th><th>SHA-256</th><th>Action</th></tr></thead>
            <tbody>
              {pcapHistory.length ? pcapHistory.map((analysis) => (
                <tr key={analysis.id}>
                  <td>{analysis.file_name}</td>
                  <td>{formatDate(analysis.created_at)}</td>
                  <td>{analysis.total_packets}</td>
                  <td>{analysis.generated_alerts}</td>
                  <td><code>{analysis.sha256 || 'Replay result'}</code></td>
                  <td>{analysis.sha256 ? <button type="button" onClick={() => startReplay(analysis.id)} disabled={replay.state === 'Running' || replay.state === 'Starting'}>Replay</button> : '—'}</td>
                </tr>
              )) : <tr><td colSpan="6"><EmptyState text="No PCAP analyses have been stored." /></td></tr>}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );

  const renderAlerts = () => (
    <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Security / Alerts</p>
          <h1>Security alerts</h1>
        </div>
        <div className="header-actions">
          {user.role === 'admin' && <button onClick={clearAlertsAction} className="ghost-btn danger"><Trash2 size={14} /> Clear</button>}
        </div>
      </div>
      <div className="toolbar">
        <div className="search-wrap"><Search size={14} /><input value={alertSearch} onChange={(e) => setAlertSearch(e.target.value)} placeholder="Search alerts" /></div>
        <select value={alertFilter} onChange={(e) => setAlertFilter(e.target.value)}>
          <option value="all">All statuses</option>
          <option value="New">New</option>
          <option value="Acknowledged">Acknowledged</option>
          <option value="Investigating">Investigating</option>
          <option value="False Positive">False Positive</option>
          <option value="Resolved">Resolved</option>
        </select>
        <select value={alertSeverityFilter} onChange={(e) => setAlertSeverityFilter(e.target.value)}>
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select value={alertSort} onChange={(e) => setAlertSort(e.target.value)}>
          <option value="timestamp">Sort by time</option>
          <option value="severity">Sort by severity</option>
          <option value="status">Sort by status</option>
        </select>
      </div>
      {user.role !== 'viewer' && (
        <div className="toolbar">
          <span>{selectedAlertIds.length} selected</span>
          <div className="button-row">
            <button type="button" onClick={() => bulkUpdateAlerts('Acknowledged')}>Acknowledge selected</button>
            <button type="button" onClick={() => bulkUpdateAlerts('False Positive')}>Mark false positive</button>
          </div>
        </div>
      )}
      <div className="split-layout">
        <Panel title="Alert queue">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Select</th>
                  <th>Severity</th>
                  <th>Detection</th>
                  <th>Source</th>
                  <th>Source type</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {alerts.length ? alerts.map((alert) => (
                  <tr key={alert.id} className={selectedAlert?.id === alert.id ? 'row-selected' : ''} onClick={() => setSelectedAlertId(alert.id)}>
                    <td onClick={(event) => event.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selectedAlertIds.includes(alert.id)}
                        onChange={(event) => setSelectedAlertIds((current) => event.target.checked ? [...new Set([...current, alert.id])] : current.filter((id) => id !== alert.id))}
                        aria-label={`Select alert ${alert.id}`}
                      />
                    </td>
                    <td><span className={`badge ${severityBadge(alert.severity)}`}>{alert.severity}</span></td>
                    <td>{alert.title}</td>
                    <td>{alert.source_ip || '—'}</td>
                    <td><span className={`badge ${alert.source === 'replay' ? 'warning' : 'info'}`}>{alert.source || 'pcap'}</span></td>
                    <td>{formatDate(alert.timestamp)}</td>
                  </tr>
                )) : <tr><td colSpan="6"><EmptyState text="No alerts found." /></td></tr>}
              </tbody>
            </table>
          </div>
        </Panel>
        <Panel title={selectedAlert ? `Alert detail #${selectedAlert.id}` : 'Alert detail'}>
          {selectedAlert ? (
            <div className="detail-panel">
              <div className="detail-line"><strong>Detection</strong><span>{selectedAlert.title}</span></div>
              <div className="detail-line"><strong>Severity</strong><span className={`badge ${severityBadge(selectedAlert.severity)}`}>{selectedAlert.severity}</span></div>
              <div className="detail-line"><strong>Status</strong><span className={`badge ${statusBadge(selectedAlert.status)}`}>{selectedAlert.status}</span></div>
              <div className="detail-line"><strong>Source</strong><span>{selectedAlert.source_ip || '—'}</span></div>
              <div className="detail-line"><strong>Destination</strong><span>{selectedAlert.destination_ip || '—'}</span></div>
              <div className="detail-line"><strong>Protocol</strong><span>{selectedAlert.protocol || '—'}</span></div>
              <div className="detail-line"><strong>Rule</strong><span>{selectedAlert.rule_id || selectedAlert.detection || 'Unmapped'}</span></div>
              <div className="detail-line"><strong>MITRE ATT&amp;CK</strong><span>
                {selectedAlert.mitre_technique_id && selectedAlert.mitre_technique_name
                  ? `${selectedAlert.mitre_technique_id} · ${selectedAlert.mitre_technique_name}`
                  : selectedAlert.mitre_technique || 'Not mapped'}
              </span></div>
              <div className="detail-line"><strong>Evidence</strong>
                <div className="evidence-fields">
                  {Object.entries(parseEvidence(selectedAlert.evidence_json)).map(([key, value]) => (
                    <div className="evidence-item" key={key}><small>{key.replaceAll('_', ' ')}</small><strong>{String(value)}</strong></div>
                  ))}
                  <details><summary>Raw evidence JSON</summary><pre>{JSON.stringify(parseEvidence(selectedAlert.evidence_json), null, 2)}</pre></details>
                </div>
              </div>
              {user.role !== 'viewer' && (
                <>
                  <div className="detail-line"><strong>Workflow</strong>
                    <div className="button-row">
                      <select value={selectedAlert.status} onChange={(event) => updateAlert(selectedAlert.id, { status: event.target.value })}>
                        {['New', 'Acknowledged', 'Investigating', 'False Positive', 'Resolved'].map((status) => <option key={status}>{status}</option>)}
                      </select>
                      <select value={selectedAlert.classification || ''} onChange={(event) => updateAlert(selectedAlert.id, { classification: event.target.value })}>
                        <option value="">Unclassified</option>
                        <option value="true_positive">True positive</option>
                        <option value="false_positive">False positive</option>
                        <option value="benign">Benign</option>
                      </select>
                    </div>
                  </div>
                  <label className="field-block">
                    <span>Assigned analyst</span>
                    <select
                      value={selectedAlert.assigned_analyst || ''}
                      onChange={(event) => updateAlert(selectedAlert.id, { assigned_analyst: event.target.value || null })}
                    >
                      <option value="">Unassigned</option>
                      {analysts.map((analyst) => (
                        <option key={analyst.id} value={analyst.username}>{analyst.username} · {analyst.role}</option>
                      ))}
                    </select>
                  </label>
                  <div className="notes-box">
                    <strong>Investigation notes</strong>
                    {alertNotes.map((note) => <p key={note.id}><b>{note.author}</b> · {formatDate(note.created_at)}<br />{note.note}</p>)}
                    <textarea value={newAlertNote} onChange={(event) => setNewAlertNote(event.target.value)} maxLength={4000} placeholder="Add an analyst note" />
                    <button type="button" onClick={addAlertNote} disabled={!newAlertNote.trim()}>Add note</button>
                  </div>
                </>
              )}
              <div className="detail-actions">
                {user.role !== 'viewer' && <button onClick={createIncidentFromAlert}>Create Incident</button>}
              </div>
            </div>
          ) : <EmptyState text="Select an alert to investigate." />}
        </Panel>
      </div>
      <div className="button-row">
        <button type="button" disabled={alertPage === 0} onClick={() => setAlertPage((pageIndex) => Math.max(0, pageIndex - 1))}>Previous alerts</button>
        <span>Page {alertPage + 1}</span>
        <button type="button" disabled={alerts.length < 50} onClick={() => setAlertPage((pageIndex) => pageIndex + 1)}>Next alerts</button>
      </div>
    </div>
  );

  const renderIncidents = () => (
    <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Operations / Incident Management</p>
          <h1>Incident management</h1>
        </div>
      </div>
      <div className="split-layout">
        <Panel title="Incidents">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Owner</th>
                </tr>
              </thead>
              <tbody>
                {incidents.length ? incidents.map((incident) => (
                  <tr key={incident.id} className={selectedIncident?.id === incident.id ? 'row-selected' : ''} onClick={() => setSelectedIncidentId(incident.id)}>
                    <td>INC-{incident.id}</td>
                    <td>{incident.title}</td>
                    <td><span className={`badge ${severityBadge(incident.severity)}`}>{incident.severity}</span></td>
                    <td><span className={`badge ${statusBadge(incident.status)}`}>{incident.status}</span></td>
                    <td>{incident.assigned_analyst || 'Unassigned'}</td>
                  </tr>
                )) : <tr><td colSpan="5"><EmptyState text="No incidents created yet." /></td></tr>}
              </tbody>
            </table>
          </div>
        </Panel>
        <Panel title={selectedIncident ? `Incident ${selectedIncident.id}` : 'Incident detail'}>
          {selectedIncident ? (
            <div className="detail-panel">
              <div className="detail-line"><strong>Title</strong><span>{selectedIncident.title}</span></div>
              <div className="detail-line"><strong>Summary</strong><span>{selectedIncident.summary || 'No summary'}</span></div>
              <div className="detail-line"><strong>Status</strong><span className={`badge ${statusBadge(selectedIncident.status)}`}>{selectedIncident.status}</span></div>
              <div className="detail-line"><strong>Assigned</strong><span>{selectedIncident.assigned_analyst || 'Unassigned'}</span></div>
              <div className="detail-line"><strong>Created</strong><span>{formatDate(selectedIncident.created_at)}</span></div>
              <div className="detail-line"><strong>Closure</strong><span>{incidentDetail?.closure_reason || 'Open'}</span></div>
              <div className="detail-line"><strong>Linked alerts</strong>
                <ul className="list-stack">
                  {(incidentDetail?.alerts || []).map((alert) => <li key={alert.id}><span>#{alert.id} {alert.title}</span><strong>{alert.severity}</strong></li>)}
                </ul>
              </div>
              <div className="detail-line"><strong>Timeline</strong>
                <ul className="list-stack">
                  {(incidentDetail?.timeline || []).map((event) => <li key={event.id}><span>{formatDate(event.created_at)} · {event.action} by {event.actor}</span><strong>{event.details}</strong></li>)}
                </ul>
              </div>
              <div className="detail-line"><strong>Notes</strong><pre>{selectedIncident.notes || 'No notes recorded.'}</pre></div>
              {user.role !== 'viewer' && selectedIncident.status !== 'Resolved' && (
                <button type="button" onClick={closeIncident}>Close incident</button>
              )}
            </div>
          ) : <EmptyState text="Select an incident to view details." />}
        </Panel>
      </div>
    </div>
  );

  const renderAssets = () => (
    <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Operations / Network Assets</p>
          <h1>Network assets</h1>
        </div>
      </div>
      <Panel title="Passively discovered hosts">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>MAC Address</th>
                <th>First Seen</th>
                <th>Last Seen</th>
                <th>Packet Count</th>
                <th>Traffic Volume</th>
              </tr>
            </thead>
            <tbody>
              {assets.length ? assets.map((asset) => (
                <tr key={asset.id}>
                  <td>{asset.ip}</td>
                  <td>{asset.mac_address || 'Unknown'}</td>
                  <td>{formatDate(asset.first_seen)}</td>
                  <td>{formatDate(asset.last_seen)}</td>
                  <td>{asset.packet_count || 0}</td>
                  <td>{formatBytes(asset.traffic_volume)}</td>
                </tr>
              )) : <tr><td colSpan="6"><EmptyState text="No assets discovered yet." /></td></tr>}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );

  const renderIntel = () => (
    <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Threat Intelligence</p>
          <h1>External reputation</h1>
        </div>
      </div>
      <Panel title="Provider status">
        <div className="status-grid">
          <StatusCard label="VirusTotal" state="Not Configured" detail="API key required." />
          <StatusCard label="AbuseIPDB" state="Not Configured" detail="API token required." />
          <StatusCard label="Internal lookup" state="Operational" detail="Local SQLite records only." />
        </div>
      </Panel>
    </div>
  );

  const renderRules = () => (
    <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Detection / Rules</p>
          <h1>Detection rules</h1>
        </div>
      </div>
      <Panel title="Rule configuration">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Severity</th>
                <th>Threshold</th>
                <th>Window</th>
                <th>Enabled</th>
                <th>History</th>
              </tr>
            </thead>
            <tbody>
              {rules.length ? rules.map((rule) => (
                <tr key={rule.id}>
                  <td>{rule.name}</td>
                  <td>
                    <select value={rule.severity} disabled={user.role !== 'admin'} onChange={(event) => saveRuleChanges(rule, { severity: event.target.value })}>
                      {['info', 'low', 'medium', 'high', 'critical'].map((severity) => <option key={severity}>{severity}</option>)}
                    </select>
                  </td>
                  <td><input type="number" min="1" defaultValue={rule.threshold} disabled={user.role !== 'admin'} onBlur={(event) => {
                    if (Number(event.target.value) !== rule.threshold) saveRuleChanges(rule, { threshold: Number(event.target.value) });
                  }} /></td>
                  <td><input type="number" min="1" defaultValue={rule.time_window} disabled={user.role !== 'admin'} onBlur={(event) => {
                    if (Number(event.target.value) !== rule.time_window) saveRuleChanges(rule, { time_window: Number(event.target.value) });
                  }} />s</td>
                  <td><button className={`toggle ${rule.enabled ? 'on' : 'off'}`} disabled={user.role !== 'admin'} onClick={() => toggleRule(rule)}>{rule.enabled ? 'Enabled' : 'Disabled'}</button></td>
                  <td><button type="button" onClick={() => showRuleHistory(rule.id)}>View</button></td>
                </tr>
              )) : <tr><td colSpan="6"><EmptyState text="No detection rules configured." /></td></tr>}
            </tbody>
          </table>
        </div>
      </Panel>
      {ruleHistoryId && (
        <Panel title={`Change history for rule ${ruleHistoryId}`}>
          <div className="list-stack">
            {ruleHistory.map((entry) => <li key={entry.id}><span>{formatDate(entry.created_at)} · {entry.actor}</span><strong>{entry.changes_json}</strong></li>)}
            {!ruleHistory.length && <EmptyState text="No changes recorded for this rule." />}
          </div>
        </Panel>
      )}
      {user.role === 'admin' && (
        <Panel title="Custom rule definition (JSON or YAML)">
          <div className="upload-box">
            <textarea value={customRuleDefinition} onChange={(event) => setCustomRuleDefinition(event.target.value)} rows={10} />
            <button type="button" onClick={createCustomRule}>Validate and create rule</button>
          </div>
        </Panel>
      )}
    </div>
  );

  const renderReports = () => {
    const records = Array.isArray(reportData?.records)
      ? reportData.records
      : (reportData?.records && typeof reportData.records === 'object' ? [reportData.records] : []);
    const columns = records.length ? Object.keys(records[0]) : [];
    return (
      <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Reporting</p>
          <h1>Reports</h1>
        </div>
        <div className="header-actions">
          <select value={reportType} onChange={(e) => setReportType(e.target.value)}>
            <option value="alerts">Security Alert Report</option>
            <option value="incidents">Incident Report</option>
            <option value="assets">Asset Report</option>
            <option value="summary">Executive Summary</option>
          </select>
        </div>
      </div>
      <Panel title="Report filters and exports">
        <div className="toolbar">
          <label className="field-block"><span>From</span><input type="datetime-local" value={reportStart} onChange={(event) => setReportStart(event.target.value)} /></label>
          <label className="field-block"><span>To</span><input type="datetime-local" value={reportEnd} onChange={(event) => setReportEnd(event.target.value)} /></label>
          <div className="button-row">
            <button type="button" onClick={() => downloadReport('pdf')}>PDF</button>
            <button type="button" onClick={() => downloadReport('csv')}>CSV</button>
            <button type="button" onClick={() => downloadReport('html')}>HTML</button>
          </div>
        </div>
      </Panel>
      <Panel title={`Preview · ${reportType} · ${records.length} records`}>
        {records.length && columns.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr>{columns.map((column) => <th key={column}>{column.replaceAll('_', ' ')}</th>)}</tr></thead>
              <tbody>{records.slice(0, 100).map((record, rowIndex) => (
                <tr key={record.id || rowIndex}>{columns.map((column) => <td key={column}>{typeof record[column] === 'object' ? JSON.stringify(record[column]) : String(record[column] ?? '—')}</td>)}</tr>
              ))}</tbody>
            </table>
          </div>
        ) : <EmptyState text="No report records available for this selection." />}
      </Panel>
      </div>
    );
  };

  const renderHealth = () => (
    <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Operations / System Health</p>
          <h1>System health</h1>
        </div>
      </div>
      <div className="status-grid">
        <StatusCard label="Backend API" state={health.backend || 'Operational'} detail="FastAPI service" />
        <StatusCard label="Database" state={health.database || 'Operational'} detail="SQLite data store" />
        <StatusCard label="Packet Capture" state={health.packet_capture_engine || 'Not Configured'} detail="Scapy / Npcap" />
        <StatusCard label="Detection Engine" state={health.detection_engine || 'Operational'} detail="Packet analysis" />
        <StatusCard label="Frontend API Connection" state={health.frontend_api_connection || 'Operational'} detail="UI to API" />
        <StatusCard label="Threat Intelligence" state={health.threat_intelligence || 'Not Configured'} detail="External providers" />
      </div>
    </div>
  );

  const renderAudit = () => (
    <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Audit / Change Log</p>
          <h1>Audit logs</h1>
        </div>
      </div>
      <Panel title="Recent activity">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Actor</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {audit.length ? audit.map((event) => (
                <tr key={event.id}>
                  <td>{formatDate(event.timestamp)}</td>
                  <td>{event.action}</td>
                  <td>{event.actor}</td>
                  <td>{event.details}</td>
                </tr>
              )) : <tr><td colSpan="4"><EmptyState text="No audit events recorded." /></td></tr>}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );

  const renderSettings = () => (
    <div className="page-stack">
      <div className="page-header">
        <div>
          <p className="eyebrow">Administration / Settings</p>
          <h1>System settings</h1>
        </div>
      </div>
      <Panel title="Configuration">
        <div className="settings-grid">
          <label className="field-block">
            <span>Monitoring interface</span>
            {monitor.interfaces.length ? (
              <select value={settings.monitoring?.interface || ''} onChange={(e) => setSettings({ ...settings, monitoring: { ...(settings.monitoring || {}), interface: e.target.value } })}>
                <option value="">Select interface</option>
                {monitor.interfaces.map((item) => (
                  <option key={item.identifier || item.name} value={item.name}>{item.friendly_name || item.name}</option>
                ))}
              </select>
            ) : (
              <input value={settings.monitoring?.interface || ''} onChange={(e) => setSettings({ ...settings, monitoring: { ...(settings.monitoring || {}), interface: e.target.value } })} />
            )}
          </label>
          <label className="field-block">
            <span>Retention days</span>
            <input type="number" value={settings.retention_days || 30} onChange={(e) => setSettings({ ...settings, retention_days: Number(e.target.value) })} />
          </label>
          <label className="field-block">
            <span>Severity threshold</span>
            <select value={settings.severity_threshold || 'medium'} onChange={(e) => setSettings({ ...settings, severity_threshold: e.target.value })}>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>
        </div>
        <div className="button-row">
          <button onClick={saveSettings}>Save settings</button>
        </div>
      </Panel>
    </div>
  );

  if (!authReady) return <div className="auth-shell">Checking authentication…</div>;
  if (backendUnavailable) {
    return <BackendUnavailableScreen apiUrl={API} onRetry={initializeAuth} />;
  }
  if (!user) {
    return (
      <AuthScreen
        setupRequired={authSetupRequired}
        error={authError}
        onSubmit={authenticate}
      />
    );
  }

  const pages = {
    overview: renderOverview(),
    monitor: renderMonitor(),
    traffic: renderTraffic(),
    pcap: renderPcap(),
    alerts: renderAlerts(),
    incidents: renderIncidents(),
    assets: renderAssets(),
    intel: renderIntel(),
    rules: renderRules(),
    reports: renderReports(),
    health: renderHealth(),
    audit: renderAudit(),
    settings: renderSettings(),
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-box">
          <div className="brand-icon"><ShieldCheck size={18} /></div>
          <div>
            <strong>Sentinel NIDS</strong>
            <small>Security Operations</small>
          </div>
        </div>
        <nav className="nav-menu">
          {NAV_ITEMS.map(({ key, label, icon: Icon }) => (
            <button key={key} className={`nav-item ${page === key ? 'active' : ''}`} onClick={() => setPage(key)}>
              <Icon size={15} />
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-status">
          <div className="user-session">
            <span>{user.username} · {user.role}</span>
            <button type="button" className="ghost-btn" onClick={logout}>Sign out</button>
          </div>
          <div className="sensor-pill">
            <span className="pulse" />
            <div>
              <strong>{monitor.session?.state || (monitor.available ? 'Offline PCAP' : 'Permission Required')}</strong>
              <small>{monitor.reason || 'Safe local analysis only'}</small>
            </div>
          </div>
        </div>
      </aside>
      <main className="content-area">
        {message && <div className="banner" onClick={() => setMessage('')}>{message}<span>×</span></div>}
        {['Starting', 'Running'].includes(replay.state) && (
          <div className="replay-banner" role="status">
            <strong>REPLAY MODE</strong>
            <span>Stored PCAP replay at {replay.speed}× — not live network capture</span>
            <button type="button" onClick={stopReplay}>Stop replay</button>
          </div>
        )}
        {pages[page]}
      </main>
    </div>
  );
}

function AuthScreen({ setupRequired, error, onSubmit }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    await onSubmit({ username, password }, setupRequired);
    setBusy(false);
  };

  return (
    <main className="auth-shell">
      <form className="auth-card" onSubmit={submit}>
        <div className="brand-icon"><ShieldCheck size={18} /></div>
        <p className="eyebrow">Sentinel NIDS · Secure access</p>
        <h1>{setupRequired ? 'Create administrator' : 'Sign in'}</h1>
        <p className="status-note">
          {setupRequired
            ? 'First-run setup. Choose an administrator username and a unique password; no default password is configured.'
            : 'Authenticate with your Sentinel NIDS account.'}
        </p>
        <label className="field-block">
          <span>Username</span>
          <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required maxLength={80} />
        </label>
        <label className="field-block">
          <span>Password {setupRequired ? '(at least 12 characters)' : ''}</span>
          <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete={setupRequired ? 'new-password' : 'current-password'} required minLength={setupRequired ? 12 : 1} />
        </label>
        {error && <div role="alert" className="auth-error">{error}</div>}
        <button type="submit" disabled={busy}>{busy ? 'Please wait…' : setupRequired ? 'Configure administrator' : 'Sign in'}</button>
      </form>
    </main>
  );
}

function BackendUnavailableScreen({ apiUrl, onRetry }) {
  const [retrying, setRetrying] = useState(false);
  const retry = async () => {
    setRetrying(true);
    await onRetry();
    setRetrying(false);
  };
  return (
    <main className="auth-shell">
      <section className="auth-card" role="alert">
        <div className="brand-icon"><WifiOff size={18} /></div>
        <p className="eyebrow">Sentinel NIDS · Connection status</p>
        <h1>Backend unavailable</h1>
        <p className="status-note">Backend not reachable at <code>{apiUrl}</code></p>
        <button type="button" onClick={retry} disabled={retrying}>
          {retrying ? 'Retrying…' : 'Retry connection'}
        </button>
      </section>
    </main>
  );
}

class ErrorBoundary extends React.Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('NIDS application render failed', error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <main className="auth-shell">
        <section className="auth-card" role="alert">
          <div className="brand-icon"><AlertTriangle size={18} /></div>
          <p className="eyebrow">Sentinel NIDS · Application error</p>
          <h1>The dashboard could not render</h1>
          <p className="status-note">{this.state.error.message || 'An unexpected rendering error occurred.'}</p>
          <button type="button" onClick={() => window.location.reload()}>Reload application</button>
        </section>
      </main>
    );
  }
}

function MetricCard({ title, value, subtitle, icon, tone = 'default' }) {
  return (
    <div className={`metric-card ${tone}`}>
      <div className="metric-top">
        <span>{title}</span>
        {icon}
      </div>
      <strong>{value}</strong>
      <small>{subtitle}</small>
    </div>
  );
}

function Panel({ title, children }) {
  return (
    <section className="panel">
      <div className="panel-header"><h2>{title}</h2><ChevronDown size={14} /></div>
      {children}
    </section>
  );
}

function Field({ label, children }) {
  return (
    <div className="field-box">
      <label>{label}</label>
      <span>{children}</span>
    </div>
  );
}

function EmptyState({ text }) {
  return <div className="empty-state">{text}</div>;
}

function StatusCard({ label, state, detail }) {
  return (
    <div className="status-card">
      <div className="status-top"><strong>{label}</strong><span className={`badge ${state === 'Operational' ? 'good' : state === 'Not Configured' ? 'info' : 'warning'}`}>{state}</span></div>
      <small>{detail}</small>
    </div>
  );
}

createRoot(document.getElementById('root')).render(
  <ErrorBoundary>
    <App />
  </ErrorBoundary>,
);
