import os
from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="SENTINELOPS Web Portal")

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")
LOGO_PATH = os.path.join(STATIC_DIR, "soc logo.png")

@app.get("/soc-logo.png")
def soc_logo():
    return FileResponse(LOGO_PATH, media_type="image/png")

# Static assets
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", response_class=HTMLResponse)
def index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINELOPS // Security Operations</title>
    <link rel="icon" type="image/png" href="/static/soc%20logo.png">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        :root {
            --bg-primary: #050706;
            --bg-card: #0b100d;
            --bg-header: #070a08;
            --border-color: #1b2a20;
            --text-main: #e4eee7;
            --text-muted: #91a49a;
            --accent-blue: #39ff14;
            --accent-cyan: #9aff68;
            --sev-critical: #ef4444;
            --sev-high: #f05252;
            --sev-medium: #8eea52;
            --sev-low: #57d68d;
            --status-online: #8eea52;
            --status-offline: #56665c;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        html, body { min-height: 100%; }
        body { background-color: var(--bg-primary); color: var(--text-main); display: flex; min-height: 100vh; overflow: hidden; position: relative; }
        body::before { content: ''; position: fixed; inset: 0; background: url('/static/soc%20logo.png') center / min(86vw, 1080px) auto no-repeat; opacity: 0.30; pointer-events: none; z-index: 0; }
        body::after { content: ''; position: fixed; inset: 0; background: rgba(5, 7, 6, 0.35); pointer-events: none; z-index: 0; }

        /* Sidebar Navigation */
        .sidebar {
            width: 248px;
            background: var(--bg-header);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            flex-shrink: 0;
            transition: width 0.25s ease;
            min-height: 100vh;
            position: relative;
            z-index: 1;
        }
        .sidebar.collapsed { width: 76px; }
        .sidebar.collapsed .brand-name,
        .sidebar.collapsed .brand-badge,
        .sidebar.collapsed .nav-label { display: none; }
        .sidebar.collapsed .brand { justify-content: center; padding-inline: 10px; }
        .sidebar.collapsed .nav-item { justify-content: center; padding-inline: 10px; }
        .sidebar.collapsed .nav-item.active { padding-left: 10px; }
        .sidebar-toggle {
            margin-right: 2px;
            width: 34px;
            height: 34px;
            min-height: 34px;
            padding: 0;
            background: transparent;
            border: 1px solid transparent;
            cursor: pointer;
        }
        .sidebar-toggle:hover { border-color: var(--accent-blue); background: rgba(57, 255, 20, 0.08); }
        .sidebar.collapsed .sidebar-toggle { margin-right: 0; }
        .brand-logo {
            width: 42px;
            height: 42px;
            flex: 0 0 42px;
            object-fit: contain;
            filter: drop-shadow(0 0 8px rgba(0, 212, 255, 0.35));
            border-radius: 8px;
        }
        .nav-label { overflow-wrap: anywhere; }
        .brand {
            padding: 20px;
            font-size: 1.1rem;
            font-weight: 700;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 10px;
            border-bottom: 1px solid var(--border-color);
        }
        .brand-badge {
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .nav-list { list-style: none; padding: 15px 10px; flex: 1; overflow-y: auto; }
        .nav-item {
            padding: 10px 14px;
            border-radius: 6px;
            margin-bottom: 4px;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 0.88rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 10px;
            min-height: 42px;
            line-height: 1.25;
            white-space: normal;
            overflow-wrap: anywhere;
            transition: all 0.2s ease;
        }
        .nav-item:hover, .nav-item.active {
            background: rgba(142, 234, 82, 0.12);
            color: #fff;
        }
        .nav-item.active { border-left: 3px solid var(--accent-blue); padding-left: 11px; }
        .nav-item:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible {
            outline: 2px solid var(--accent-cyan);
            outline-offset: 2px;
        }
        button { min-height: 38px; white-space: normal; line-height: 1.25; }

        /* Main Content Workspace */
        .main-container { flex: 1; min-width: 0; min-height: 0; height: 100vh; display: flex; flex-direction: column; overflow: hidden; position: relative; z-index: 1; }
        .workspace-watermark { position: absolute; top: 50%; left: 58%; width: min(68vw, 900px); max-width: 90%; transform: translate(-50%, -50%); opacity: 0.20; filter: drop-shadow(0 0 18px rgba(0, 212, 255, 0.25)); pointer-events: none; z-index: 0; }
        
        .topbar {
            height: 60px;
            background: var(--bg-header);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 25px;
            position: relative;
            z-index: 1;
        }
        .topbar-title { font-size: 1.1rem; font-weight: 600; color: #fff; }
        .user-status { display: flex; align-items: center; gap: 15px; font-size: 0.85rem; }
        .badge-live {
            background: rgba(16, 185, 129, 0.2);
            color: var(--status-online);
            border: 1px solid var(--status-online);
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .content-area { flex: 1 1 auto; min-width: 0; min-height: 0; padding: 20px; overflow-y: auto; overscroll-behavior: contain; scrollbar-color: var(--accent-blue) var(--bg-primary); scrollbar-width: thin; position: relative; z-index: 1; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* Metric Cards Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 18px;
        }
        .card-title { font-size: 0.8rem; color: var(--text-muted); font-weight: 500; text-transform: uppercase; margin-bottom: 8px; }
        .card-value { font-size: 1.8rem; font-weight: 700; color: #fff; }
        .card-sub { font-size: 0.78rem; color: var(--text-muted); margin-top: 5px; }
        .charts-grid {
            display: grid;
            grid-template-columns: minmax(260px, 0.85fr) minmax(360px, 1.15fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        .chart-card { min-width: 0; }
        .chart-card .table-header { margin: -1px -1px 0; }
        .chart-wrap { height: 230px; padding: 16px; position: relative; }
        .chart-empty { color: var(--text-muted); display: grid; height: 100%; place-items: center; text-align: center; font-size: 0.85rem; }

        /* Custom Tables */
        .table-card { background: rgba(11, 16, 13, 0.58); border: 1px solid rgba(57, 255, 20, 0.22); border-radius: 8px; overflow: hidden; margin-bottom: 20px; backdrop-filter: blur(4px); }
        .table-header { padding: 15px 20px; background: rgba(5, 7, 6, 0.42); border-bottom: 1px solid rgba(57, 255, 20, 0.16); display: flex; justify-content: space-between; align-items: center; }
        .table-header h3 { font-size: 1rem; font-weight: 600; }
        .refresh-controls { display: flex; align-items: center; gap: 12px; }
        .refresh-status { color: var(--text-muted); font-size: 0.72rem; white-space: nowrap; }
        
        table { width: 100%; min-width: 760px; border-collapse: collapse; text-align: left; font-size: 0.85rem; }
        .table-card { overflow-x: auto; scrollbar-color: var(--accent-blue) var(--bg-card); scrollbar-width: thin; }
        th { background: rgba(10, 15, 12, 0.68); padding: 12px 16px; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid rgba(57, 255, 20, 0.14); }
        td { padding: 12px 16px; background: rgba(5, 7, 6, 0.20); border-bottom: 1px solid rgba(27, 42, 32, 0.78); color: var(--text-main); }
        tr:hover td { background: rgba(57, 255, 20, 0.06); }

        .badge-sev { padding: 3px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }
        .sev-critical { background: rgba(239, 68, 68, 0.2); color: var(--sev-critical); border: 1px solid var(--sev-critical); }
        .sev-high { background: rgba(249, 115, 22, 0.2); color: var(--sev-high); border: 1px solid var(--sev-high); }
        .sev-medium { background: rgba(234, 179, 8, 0.2); color: var(--sev-medium); border: 1px solid var(--sev-medium); }
        .sev-low { background: rgba(59, 130, 246, 0.2); color: var(--sev-low); border: 1px solid var(--sev-low); }

        /* Controls & Inputs */
        input, select, button {
            background: #0a0f0c;
            border: 1px solid var(--border-color);
            color: #fff;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
        }
        button { background: var(--accent-blue); font-weight: 600; cursor: pointer; border: none; transition: background 0.2s; }
        button:hover { background: #65b83b; }

        /* Graph Network */
        #network-graph { width: 100%; height: 450px; background: #090d16; border-radius: 8px; border: 1px solid var(--border-color); }

        /* Evidence & Detail Modals */
        .modal-overlay {
            position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
            background: rgba(0, 0, 0, 0.8); display: none; align-items: center; justify-content: center; z-index: 9999;
        }
        .modal-box {
            background: #111827; border: 1px solid #1f293d; border-radius: 10px; width: 750px; max-width: 90vw;
            max-height: 85vh; overflow-y: auto; padding: 25px; box-shadow: 0 20px 40px rgba(0,0,0,0.8);
        }
        .modal-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1f293d; padding-bottom: 12px; margin-bottom: 15px; }
        .modal-header h3 { font-size: 1.1rem; color: #fff; }
        .close-btn { background: transparent; border: none; color: var(--text-muted); font-size: 1.2rem; cursor: pointer; }

        @media (max-width: 900px) {
            body { display: block; overflow: auto; }
            .sidebar { width: 100%; border-right: none; border-bottom: 1px solid var(--border-color); }
            .brand { padding: 14px 16px; }
            .nav-list { display: flex; flex-wrap: wrap; gap: 6px; padding: 10px; overflow: visible; }
            .nav-item { flex: 1 1 220px; margin: 0; min-height: 40px; max-width: none; }
            .nav-item.active { padding-left: 11px; }
            .main-container { min-height: calc(100vh - 116px); overflow: visible; }
            .topbar { height: auto; min-height: 60px; gap: 12px; padding: 12px 16px; flex-wrap: wrap; }
            .user-status { flex-wrap: wrap; gap: 8px 12px; }
            .content-area { padding: 16px; overflow: visible; }
            .table-header { align-items: stretch; flex-wrap: wrap; gap: 10px; }
            .charts-grid { grid-template-columns: 1fr; }
            .refresh-controls { width: 100%; justify-content: space-between; }
        }

        @media (max-width: 560px) {
            .topbar-title { font-size: 1rem; }
            .user-status { font-size: 0.78rem; }
            .badge-live { font-size: 0.68rem; }
            .nav-item { flex-basis: 160px; }
            .metrics-grid { grid-template-columns: 1fr 1fr; gap: 10px; }
            .card { padding: 14px; }
            .card-value { font-size: 1.45rem; }
            .content-area { padding: 12px; }
            .table-header { padding: 12px 14px; }
            .table-header button, .table-header input { width: 100%; }
            .modal-box { max-width: calc(100vw - 24px); padding: 18px; }
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="brand">
            <button class="sidebar-toggle" type="button" aria-label="Collapse sidebar" aria-expanded="true" title="Toggle sidebar" onclick="toggleSidebar()">
                <img class="brand-logo" src="/static/soc%20logo.png" alt="SentinelOps security operations logo">
            </button>
            <span class="brand-name">SENTINELOPS</span>
        </div>
        <ul class="nav-list">
            <li class="nav-item active" role="button" tabindex="0" aria-current="page" onclick="switchTab('dashboard', this)" onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); switchTab('dashboard', this); }"><span class="nav-label">Overview</span></li>
            <li class="nav-item" role="button" tabindex="0" onclick="switchTab('alerts', this)" onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); switchTab('alerts', this); }"><span class="nav-label">Alerts</span></li>
            <li class="nav-item" role="button" tabindex="0" onclick="switchTab('rules', this)" onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); switchTab('rules', this); }"><span class="nav-label">Rules</span></li>
            <li class="nav-item" role="button" tabindex="0" onclick="switchTab('incidents', this)" onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); switchTab('incidents', this); }"><span class="nav-label">Cases</span></li>
            <li class="nav-item" role="button" tabindex="0" onclick="switchTab('investigations', this)" onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); switchTab('investigations', this); }"><span class="nav-label">Investigate</span></li>
            <li class="nav-item" role="button" tabindex="0" onclick="switchTab('hunting', this)" onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); switchTab('hunting', this); }"><span class="nav-label">Hunt</span></li>
            <li class="nav-item" role="button" tabindex="0" onclick="switchTab('assets', this)" onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); switchTab('assets', this); }"><span class="nav-label">Assets</span></li>
            <li class="nav-item" role="button" tabindex="0" onclick="switchTab('mitre', this)" onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); switchTab('mitre', this); }"><span class="nav-label">MITRE</span></li>
            <li class="nav-item" role="button" tabindex="0" onclick="switchTab('health', this)" onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); switchTab('health', this); }"><span class="nav-label">Health</span></li>
            <li class="nav-item" role="button" tabindex="0" onclick="switchTab('playbooks', this)" onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); switchTab('playbooks', this); }"><span class="nav-label">Playbooks</span></li>
            <li class="nav-item" role="button" tabindex="0" onclick="switchTab('reports', this)" onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); switchTab('reports', this); }"><span class="nav-label">Reports</span></li>
        </ul>
    </div>

    <!-- Main Workspace -->
    <div class="main-container">
        <img class="workspace-watermark" src="/static/soc%20logo.png" alt="">
        <div class="topbar">
            <div class="topbar-title" id="tab-title">SentinelOps // Overview</div>
            <div class="user-status">
                <span class="badge-live">● REAL-TIME TELEMETRY</span>
                <span>Analyst: <strong id="display-username">...</strong> (<span id="display-role">...</span>)</span>
                <button onclick="logout()" style="padding: 5px 10px; font-size: 0.75rem; background: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-muted); cursor: pointer;">Logout</button>
            </div>
        </div>

        <div class="content-area">
            
            <!-- Dashboard Tab -->
            <div id="tab-dashboard" class="tab-content active">
                <div class="metrics-grid">
                    <div class="card">
                        <div class="card-title">Total Alerts Ingested</div>
                        <div class="card-value" id="stat-alerts">0</div>
                        <div class="card-sub">Updated live</div>
                    </div>
                    <div class="card">
                        <div class="card-title">Active Unresolved Incidents</div>
                        <div class="card-value" id="stat-incidents">0</div>
                        <div class="card-sub">Requires triage</div>
                    </div>
                    <div class="card">
                        <div class="card-title">Monitored Assets</div>
                        <div class="card-value" id="stat-assets">0</div>
                        <div class="card-sub">Registered Enterprise Hosts</div>
                    </div>
                    <div class="card">
                        <div class="card-title">Events Normalized (EPS)</div>
                        <div class="card-value" id="stat-events">0</div>
                        <div class="card-sub">Continuous Telemetry Stream</div>
                    </div>
                </div>

                <div class="table-card">
                    <div class="table-header">
                        <h3>Critical & High Priority Security Alerts</h3>
                        <div class="refresh-controls">
                            <span id="dashboard-refresh-status" class="refresh-status">Live polling: 15s</span>
                            <button id="dashboard-refresh" type="button" onclick="refreshData()">Refresh Telemetry</button>
                        </div>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Timestamp</th>
                                <th>Alert Title</th>
                                <th>Severity</th>
                                <th>Source IP / Host</th>
                                <th>Risk Score</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="dashboard-alerts-body">
                            <tr><td colspan="7">Loading SOC telemetry...</td></tr>
                        </tbody>
                    </table>
                </div>

                <div class="charts-grid" aria-label="Security telemetry charts">
                    <div class="table-card chart-card">
                        <div class="table-header"><h3>Alerts by Severity</h3></div>
                        <div class="chart-wrap"><canvas id="severity-chart" aria-label="Alerts by severity chart"></canvas><div id="severity-chart-empty" class="chart-empty" hidden>No alert data available.</div></div>
                    </div>
                    <div class="table-card chart-card">
                        <div class="table-header"><h3>Alert Activity, Last 24 Hours</h3></div>
                        <div class="chart-wrap"><canvas id="activity-chart" aria-label="Alert activity over the last 24 hours chart"></canvas><div id="activity-chart-empty" class="chart-empty" hidden>No alert data available.</div></div>
                    </div>
                </div>
            </div>

            <!-- Alerts Tab -->
            <div id="tab-alerts" class="tab-content">
                <div class="table-card">
                    <div class="table-header">
                        <h3>Alert Stream & Triage Center</h3>
                        <input type="text" id="alert-search" placeholder="Search IP, Title, Rule..." onkeyup="filterAlerts()">
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Timestamp</th>
                                <th>Title</th>
                                <th>Severity</th>
                                <th>Source / User</th>
                                <th>MITRE ATT&CK</th>
                                <th>Risk Score</th>
                                <th>Lifecycle Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="all-alerts-body">
                            <tr><td colspan="9">Loading alerts...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Detection Rules Management Tab (Phase 5) -->
            <div id="tab-rules" class="tab-content">
                <div class="table-card">
                    <div class="table-header">
                        <h3>Modular Detection Rules Engine Catalog</h3>
                        <button onclick="refreshRules()">Refresh Catalog</button>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Rule ID</th>
                                <th>Rule Name</th>
                                <th>Severity</th>
                                <th>Confidence</th>
                                <th>Threshold / Window</th>
                                <th>MITRE Tactic & ID</th>
                                <th>Status</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="rules-catalog-body">
                            <tr><td colspan="8">Loading detection rules...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Incidents & Cases Tab -->
            <div id="tab-incidents" class="tab-content">
                <div class="table-card">
                    <div class="table-header">
                        <h3>Active Security Incidents & Cases</h3>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Incident ID</th>
                                <th>Title</th>
                                <th>Severity</th>
                                <th>Priority</th>
                                <th>Status</th>
                                <th>Category</th>
                                <th>Created At</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="incidents-body">
                            <tr><td colspan="8">Loading incidents...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Investigation Tab -->
            <div id="tab-investigations" class="tab-content">
                <div class="table-card" style="padding: 15px;">
                    <h3>Entity Relationship Graph Visualizer (Pivoting Engine)</h3>
                    <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 15px;">
                        Pivoting relationship topology across Users, Endpoints, Network IP Targets, and Malware IOC Signatures.
                    </p>
                    <div id="network-graph"></div>
                </div>
            </div>

            <!-- Threat Hunting Tab -->
            <div id="tab-hunting" class="tab-content">
                <div class="table-card">
                    <div class="table-header">
                        <h3>Normalized Telemetry Event Search Engine</h3>
                        <div style="display: flex; gap: 10px; align-items: center;">
                            <select id="source-mode-filter" onchange="runHuntingQuery()">
                                <option value="all">ALL (Live & Sim)</option>
                                <option value="live">LIVE ONLY</option>
                                <option value="simulation">SIMULATION ONLY</option>
                            </select>
                            <input type="text" id="hunting-query" placeholder="e.g. 192.168.1.100, Failed Login..." style="width: 260px;">
                            <button onclick="runHuntingQuery()">Execute Query</button>
                        </div>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Event ID</th>
                                <th>Timestamp</th>
                                <th>Source Type</th>
                                <th>Hostname</th>
                                <th>Source IP</th>
                                <th>User</th>
                                <th>Event Type</th>
                                <th>Severity</th>
                            </tr>
                        </thead>
                        <tbody id="hunting-results-body">
                            <tr><td colspan="8">Enter query to hunt telemetry events...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Asset Inventory Tab -->
            <div id="tab-assets" class="tab-content">
                <div class="table-card">
                    <div class="table-header">
                        <h3>Enterprise Asset Inventory & Risk Matrix</h3>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Asset ID</th>
                                <th>Hostname</th>
                                <th>IP Address</th>
                                <th>Operating System</th>
                                <th>Role</th>
                                <th>Criticality</th>
                                <th>Agent Status</th>
                                <th>Risk Score</th>
                            </tr>
                        </thead>
                        <tbody id="assets-body">
                            <tr><td colspan="8">Loading enterprise assets...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- MITRE ATT&CK Matrix Tab -->
            <div id="tab-mitre" class="tab-content">
                <div class="table-card" style="padding: 20px;">
                    <h3>MITRE ATT&CK Matrix Coverage Analyzer</h3>
                    <div id="mitre-summary-stats" style="margin: 10px 0; font-size: 0.85rem; color: var(--text-muted);">
                        Loading ATT&CK matrix...
                    </div>
                    <div id="mitre-matrix-container" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-top: 15px;">
                        <!-- Dynamically filled -->
                    </div>
                </div>
            </div>

            <!-- SOC Health Tab -->
            <div id="tab-health" class="tab-content">
                <div class="table-card">
                    <div class="table-header">
                        <h3>SENTINELOPS Infrastructure & Sensor Health Status</h3>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Integration / Service Name</th>
                                <th>Health Status</th>
                                <th>Details / Information</th>
                            </tr>
                        </thead>
                        <tbody id="health-body">
                            <tr><td colspan="3">Checking integration statuses...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- SOAR Playbooks Tab -->
            <div id="tab-playbooks" class="tab-content">
                <div class="safety-banner" style="background: rgba(57, 255, 20, 0.08); border: 1px solid rgba(57, 255, 20, 0.35); padding: 12px 18px; border-radius: 8px; margin-bottom: 20px; color: var(--accent-blue); font-weight: 600; display: flex; align-items: center; justify-content: space-between;">
                    <div>
                        <span style="background: var(--accent-blue); color: #050706; padding: 3px 8px; border-radius: 4px; font-size: 11px; margin-right: 10px; text-transform: uppercase; letter-spacing: 0.5px;">SENTINELOPS — SIMULATION MODE</span>
                        <span>All playbook executions operate in isolated lab simulation mode by default.</span>
                    </div>
                    <div style="font-size: 12px; color: #a855f7;">LIVE RESPONSE — NOT CONFIGURED</div>
                </div>

                <div class="table-card" style="margin-bottom: 25px;">
                    <div class="table-header">
                        <h3>SOAR Controlled Playbook Automation Catalog</h3>
                        <button onclick="loadPlaybooks()">Refresh Catalog</button>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Playbook ID</th>
                                <th>Name & Description</th>
                                <th>Execution Mode</th>
                                <th>Risk Level</th>
                                <th>Approval Requirement</th>
                                <th>Configured Actions</th>
                                <th>Execute Control</th>
                            </tr>
                        </thead>
                        <tbody id="playbooks-body">
                            <tr><td colspan="7">Loading automation playbooks...</td></tr>
                        </tbody>
                    </table>
                </div>

                <div class="table-card">
                    <div class="table-header">
                        <h3>Playbook Executions Log & Analyst Approval Gate</h3>
                        <button onclick="loadPlaybookExecutions()">Refresh Execution History</button>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Execution ID</th>
                                <th>Playbook ID</th>
                                <th>Target Asset</th>
                                <th>Mode</th>
                                <th>Status</th>
                                <th>Requested By</th>
                                <th>Approved By</th>
                                <th>Started At</th>
                                <th>Governance Controls</th>
                            </tr>
                        </thead>
                        <tbody id="playbook-executions-body">
                            <tr><td colspan="9">Loading execution logs...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Reports & Audit Tab -->
            <div id="tab-reports" class="tab-content">
                <div class="card" style="margin-bottom: 20px;">
                    <h3>Export SOC Operations Reports</h3>
                    <p style="font-size: 0.85rem; color: var(--text-muted); margin: 10px 0;">
                        Download compliance audits, executive summaries, and incident response metrics.
                    </p>
                    <div style="display: flex; gap: 15px; margin-top: 15px;">
                        <button onclick="downloadReport('json')">Export Daily JSON Audit Report</button>
                        <button onclick="downloadReport('csv')">Export Alerts CSV Data</button>
                    </div>
                </div>

                <div class="table-card">
                    <div class="table-header">
                        <h3>System Security Audit Log Trail</h3>
                        <button onclick="loadReportsAndAudit()">Refresh Audit Trail</button>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Username</th>
                                <th>Role</th>
                                <th>Action</th>
                                <th>Target Type</th>
                                <th>Target ID</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="audit-log-body">
                            <tr><td colspan="7">Loading security audit logs...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

        </div>
    </div>

    <!-- Alert Evidence & Risk Modal -->
    <div id="evidence-modal" class="modal-overlay">
        <div class="modal-box">
            <div class="modal-header">
                <h3 id="modal-alert-title">Alert Evidence Drill-Down</h3>
                <button class="close-btn" onclick="closeEvidenceModal()">✕</button>
            </div>
            <div id="modal-alert-content">
                Loading evidence...
            </div>
        </div>
    </div>

    <!-- Dark Glassmorphic Login Overlay -->
    <div id="login-overlay" style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(11, 15, 25, 0.96); display: flex; align-items: center; justify-content: center; z-index: 10000; display: none;">
        <style>
            .login-card {
                background: #111827;
                border: 1px solid #1f293d;
                padding: 40px;
                border-radius: 12px;
                width: 420px;
                box-shadow: 0 15px 35px rgba(0, 0, 0, 0.6);
                text-align: center;
            }
            .login-card h2 { margin-bottom: 8px; font-size: 1.6rem; color: #fff; font-weight: 700; }
            .login-card p { color: #94a3b8; font-size: 0.85rem; margin-bottom: 25px; }
            .login-field { text-align: left; margin-bottom: 18px; }
            .login-field label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 6px; font-weight: 500; }
            .login-field input {
                width: 100%;
                padding: 12px;
                background: #0b0f19;
                border: 1px solid #1f293d;
                border-radius: 6px;
                color: #fff;
                font-size: 0.9rem;
                outline: none;
                transition: border-color 0.2s;
            }
            .login-field input:focus { border-color: #3b82f6; }
            .login-btn-submit {
                width: 100%;
                padding: 12px;
                background: var(--accent-blue);
                border: none;
                color: #fff;
                font-weight: 600;
                border-radius: 6px;
                cursor: pointer;
                font-size: 0.95rem;
                transition: filter 0.2s;
            }
            .login-btn-submit:hover { filter: brightness(1.1); }
            .login-error-msg { color: #ef4444; font-size: 0.82rem; margin-top: 15px; display: none; }
        </style>
        <div class="login-card">
            <h2>SENTINELOPS // ACCESS</h2>
            <p>Security operations, response, and threat visibility</p>
            <form onsubmit="loginUser(event)">
                <div class="login-field">
                    <label for="login-username">Username</label>
                    <input type="text" id="login-username" value="admin" placeholder="e.g. admin" required>
                </div>
                <div class="login-field">
                    <label for="login-password">Password</label>
                    <input type="password" id="login-password" value="soc-lab-admin-change-me" placeholder="••••••••" required>
                </div>
                <button type="submit" class="login-btn-submit">Authenticate Securely</button>
                <div id="login-error" class="login-error-msg">Invalid credentials.</div>
            </form>
        </div>
    </div>

    <script>
        const API_BASE = "http://" + (window.location.hostname || "127.0.0.1") + ":8001";
        let currentTab = 'dashboard';
        let severityChart = null;
        let activityChart = null;
        let refreshTimer = null;
        let refreshInFlight = false;

        const originalFetch = window.fetch;
        window.fetch = async function (url, options = {}) {
            if (url.toString().startsWith(API_BASE)) {
                options.headers = options.headers || {};
                const token = localStorage.getItem("soc_token");
                if (token && !options.headers["Authorization"]) {
                    options.headers["Authorization"] = "Bearer " + token;
                }
            }
            const res = await originalFetch(url, options);
            if (res.status === 401 && !url.toString().includes('/api/auth/login')) {
                localStorage.removeItem("soc_token");
                localStorage.removeItem("soc_role");
                localStorage.removeItem("soc_username");
                showLoginOverlay();
            }
            return res;
        };

        function escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        function showLoginOverlay() {
            document.getElementById('login-overlay').style.display = 'flex';
        }

        function toggleSidebar() {
            const sidebar = document.querySelector('.sidebar');
            const toggle = document.querySelector('.sidebar-toggle');
            const collapsed = sidebar.classList.toggle('collapsed');
            sidebar.style.width = collapsed && window.innerWidth > 900 ? '76px' : '';
            toggle.setAttribute('aria-expanded', String(!collapsed));
            toggle.setAttribute('aria-label', collapsed ? 'Expand sidebar' : 'Collapse sidebar');
            toggle.setAttribute('title', collapsed ? 'Expand sidebar' : 'Collapse sidebar');
            localStorage.setItem('sentinelops_sidebar_collapsed', String(collapsed));
        }

        function restoreSidebarState() {
            if (localStorage.getItem('sentinelops_sidebar_collapsed') === 'true' && window.innerWidth > 900) {
                toggleSidebar();
            }
        }

        function hideLoginOverlay() {
            document.getElementById('login-overlay').style.display = 'none';
            document.getElementById('display-username').innerText = localStorage.getItem("soc_username") || "Guest";
            document.getElementById('display-role').innerText = localStorage.getItem("soc_role") || "Read Only";
            switchTab(currentTab);
        }

        async function loginUser(event) {
            if (event) event.preventDefault();
            const usernameInput = document.getElementById('login-username').value;
            const passwordInput = document.getElementById('login-password').value;
            const errDiv = document.getElementById('login-error');
            errDiv.style.display = 'none';

            try {
                const res = await originalFetch(API_BASE + '/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: usernameInput, password: passwordInput })
                });

                if (res.status === 200) {
                    const data = await res.json();
                    localStorage.setItem("soc_token", data.access_token);
                    localStorage.setItem("soc_role", data.role);
                    localStorage.setItem("soc_username", usernameInput);
                    hideLoginOverlay();
                } else {
                    const errData = await res.json();
                    errDiv.innerText = errData.detail || "Invalid username or password";
                    errDiv.style.display = 'block';
                }
            } catch (e) {
                errDiv.innerText = "Error connecting to SOC API";
                errDiv.style.display = 'block';
            }
        }

        async function autoLoginDefault() {
            const usernameInput = (document.getElementById('login-username') ? document.getElementById('login-username').value : '') || "admin";
            const passwordInput = (document.getElementById('login-password') ? document.getElementById('login-password').value : '') || "soc-lab-admin-change-me";
            try {
                const res = await originalFetch(API_BASE + '/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: usernameInput, password: passwordInput })
                });
                if (res.status === 200) {
                    const data = await res.json();
                    localStorage.setItem("soc_token", data.access_token);
                    localStorage.setItem("soc_role", data.role);
                    localStorage.setItem("soc_username", usernameInput);
                    hideLoginOverlay();
                    return true;
                }
            } catch (e) {}
            showLoginOverlay();
            return false;
        }

        async function logout() {
            try {
                await fetch(API_BASE + '/api/auth/logout', { method: 'POST' });
            } catch (e) {}
            localStorage.removeItem("soc_token");
            localStorage.removeItem("soc_role");
            localStorage.removeItem("soc_username");
            showLoginOverlay();
        }

        window.addEventListener('DOMContentLoaded', async () => {
            restoreSidebarState();
            if (!localStorage.getItem("soc_token")) {
                await autoLoginDefault();
            } else {
                hideLoginOverlay();
            }
            startLiveRefresh();
        });

        function startLiveRefresh() {
            if (refreshTimer) clearInterval(refreshTimer);
            refreshTimer = setInterval(() => {
                if (document.hidden || !localStorage.getItem("soc_token")) return;
                if (currentTab === 'dashboard') refreshData();
            }, 15000);
        }

        async function switchTab(tabId, el) {
            currentTab = tabId || 'dashboard';
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(i => {
                i.classList.remove('active');
                i.removeAttribute('aria-current');
            });
            
            const targetTab = document.getElementById('tab-' + currentTab);
            if (targetTab) targetTab.classList.add('active');
            
            let navEl = el;
            if (!navEl) {
                navEl = document.querySelector(`.nav-item[onclick*="'${currentTab}'"]`);
            }
            if (navEl) {
                navEl.classList.add('active');
                navEl.setAttribute('aria-current', 'page');
                const label = navEl.querySelector('.nav-label');
                document.getElementById('tab-title').innerText = `SentinelOps // ${label ? label.innerText : navEl.innerText}`;
            }

            if (!localStorage.getItem("soc_token")) {
                showLoginOverlay();
                if (targetTab) {
                    const container = targetTab.querySelector('.table-card') || targetTab.querySelector('.card') || targetTab;
                    container.innerHTML = `<div style="padding: 30px; text-align: center; color: var(--sev-medium);">Authentication required to access workspace '${currentTab}'. Please log in to view live security telemetry.</div>`;
                }
                return;
            }

            try {
                if (currentTab === 'dashboard') await refreshData();
                else if (currentTab === 'alerts') await loadAlerts();
                else if (currentTab === 'rules') await refreshRules();
                else if (currentTab === 'incidents') await loadIncidents();
                else if (currentTab === 'investigations') await loadGraph();
                else if (currentTab === 'hunting') initHuntingView();
                else if (currentTab === 'assets') await loadAssets();
                else if (currentTab === 'mitre') await loadMitre();
                else if (currentTab === 'health') await loadHealth();
                else if (currentTab === 'playbooks') await loadPlaybooks();
                else if (currentTab === 'reports') await loadReportsAndAudit();
            } catch (err) {
                console.error("Error switching tab to " + currentTab + ":", err);
                if (targetTab) {
                    const container = targetTab.querySelector('.table-card') || targetTab.querySelector('.card') || targetTab;
                    container.innerHTML = `<div style="padding: 30px; text-align: center; color: var(--sev-critical);">Unable to load tab '${currentTab}': ${escapeHtml(err.message || String(err))}</div>`;
                }
            }
        }

        async function fetchAPI(endpoint, options = {}) {
            try {
                const token = localStorage.getItem("soc_token");
                const headers = Object.assign({}, options.headers || {});
                if (token && !headers['Authorization']) {
                    headers['Authorization'] = 'Bearer ' + token;
                }
                const res = await fetch(API_BASE + endpoint, { ...options, headers });
                if (!res.ok) {
                    let detail = res.statusText;
                    try {
                        const errJson = await res.json();
                        detail = errJson.detail || errJson.message || res.statusText;
                    } catch (e) {
                        try {
                            detail = await res.text() || res.statusText;
                        } catch (e2) {}
                    }
                    console.error("API error for " + endpoint + ":", res.status, detail);
                    return { _error: true, status: res.status, statusText: res.statusText, detail: detail };
                }
                return await res.json();
            } catch (e) {
                console.error("API exception for " + endpoint + ":", e);
                return { _error: true, status: 0, statusText: e.message, detail: e.message };
            }
        }

        function renderCharts(alerts) {
            const severityCanvas = document.getElementById('severity-chart');
            const activityCanvas = document.getElementById('activity-chart');
            if (!severityCanvas || !activityCanvas || typeof Chart === 'undefined') return;

            const severityEmpty = document.getElementById('severity-chart-empty');
            const activityEmpty = document.getElementById('activity-chart-empty');
            const hasAlerts = Array.isArray(alerts) && alerts.length > 0;
            severityCanvas.hidden = !hasAlerts;
            activityCanvas.hidden = !hasAlerts;
            severityEmpty.hidden = hasAlerts;
            activityEmpty.hidden = hasAlerts;

            if (!hasAlerts) {
                if (severityChart) severityChart.destroy();
                if (activityChart) activityChart.destroy();
                severityChart = null;
                activityChart = null;
                return;
            }

            const severityOrder = ['critical', 'high', 'medium', 'low'];
            const severityCounts = severityOrder.reduce((counts, severity) => {
                counts[severity] = 0;
                return counts;
            }, {});
            alerts.forEach(alert => {
                const severity = String(alert.severity || 'low').toLowerCase();
                severityCounts[severity] = (severityCounts[severity] || 0) + 1;
            });

            const now = new Date();
            now.setMinutes(0, 0, 0);
            const activityLabels = [];
            const activityCounts = [];
            for (let offset = 23; offset >= 0; offset -= 1) {
                const hour = new Date(now);
                hour.setHours(now.getHours() - offset);
                activityLabels.push(hour.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
                activityCounts.push(0);
            }
            const firstHour = new Date(now);
            firstHour.setHours(now.getHours() - 23);
            alerts.forEach(alert => {
                const timestamp = new Date(alert.timestamp);
                if (Number.isNaN(timestamp.getTime()) || timestamp < firstHour) return;
                const bucket = Math.floor((timestamp - firstHour) / (60 * 60 * 1000));
                if (bucket >= 0 && bucket < activityCounts.length) activityCounts[bucket] += 1;
            });

            const chartOptions = {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: '#cbd5e1', boxWidth: 12 } }
                }
            };
            if (severityChart) severityChart.destroy();
            severityChart = new Chart(severityCanvas, {
                type: 'doughnut',
                data: {
                    labels: severityOrder.map(severity => severity.toUpperCase()),
                    datasets: [{
                        data: severityOrder.map(severity => severityCounts[severity]),
                        backgroundColor: ['#ef4444', '#f05252', '#eab308', '#3b82f6'],
                        borderColor: '#0b100d',
                        borderWidth: 3
                    }]
                },
                options: { ...chartOptions, cutout: '64%' }
            });

            if (activityChart) activityChart.destroy();
            activityChart = new Chart(activityCanvas, {
                type: 'bar',
                data: {
                    labels: activityLabels,
                    datasets: [{
                        label: 'Alerts',
                        data: activityCounts,
                        backgroundColor: 'rgba(0, 212, 255, 0.72)',
                        borderColor: '#00d4ff',
                        borderWidth: 1,
                        borderRadius: 3
                    }]
                },
                options: {
                    ...chartOptions,
                    scales: {
                        x: { ticks: { color: '#91a49a', maxTicksLimit: 8 }, grid: { display: false } },
                        y: { beginAtZero: true, ticks: { color: '#91a49a', precision: 0 }, grid: { color: 'rgba(145, 164, 154, 0.14)' } }
                    }
                }
            });
        }

        async function refreshData() {
            if (!localStorage.getItem("soc_token") || refreshInFlight) return;
            refreshInFlight = true;
            const refreshButton = document.getElementById('dashboard-refresh');
            const refreshStatus = document.getElementById('dashboard-refresh-status');
            if (refreshButton) {
                refreshButton.disabled = true;
                refreshButton.innerText = 'Refreshing...';
            }

            try {
                const [stats, alerts] = await Promise.all([
                    fetchAPI('/api/stats'),
                    fetchAPI('/api/alerts?limit=50')
                ]);

                if (stats && !stats._error) {
                    document.getElementById('stat-alerts').innerText = stats.total_alerts !== undefined ? stats.total_alerts : 0;
                    document.getElementById('stat-incidents').innerText = stats.active_incidents !== undefined ? stats.active_incidents : 0;
                    document.getElementById('stat-assets').innerText = stats.total_assets !== undefined ? stats.total_assets : 0;
                    document.getElementById('stat-events').innerText = stats.total_events !== undefined ? stats.total_events : 0;
                }

                if (alerts && !alerts._error && Array.isArray(alerts)) {
                    renderAlertsTable('dashboard-alerts-body', alerts.slice(0, 10), false);
                    renderCharts(alerts);
                } else if (alerts && alerts._error) {
                    const errMsg = alerts.detail || alerts.statusText || ("HTTP " + alerts.status);
                    document.getElementById('dashboard-alerts-body').innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--sev-critical);">Unable to load telemetry: ${escapeHtml(errMsg)}</td></tr>`;
                    renderCharts([]);
                } else {
                    document.getElementById('dashboard-alerts-body').innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); font-weight: 600;">No alerts available.</td></tr>';
                    renderCharts([]);
                }
                if (refreshStatus) refreshStatus.innerText = `Updated ${new Date().toLocaleTimeString()}`;
            } finally {
                refreshInFlight = false;
                if (refreshButton) {
                    refreshButton.disabled = false;
                    refreshButton.innerText = 'Refresh Telemetry';
                }
            }
        }

        async function loadAlerts() {
            const tbody = document.getElementById('all-alerts-body');
            if (!tbody) return;
            tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 20px; color: var(--text-muted);">Loading alert stream & triage data...</td></tr>';
            
            const alerts = await fetchAPI('/api/alerts?limit=50');
            if (alerts && alerts._error) {
                const errMsg = alerts.detail || alerts.statusText || ("HTTP " + alerts.status);
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 20px; color: var(--sev-critical);">Unable to load alerts: ${escapeHtml(errMsg)}</td></tr>`;
                return;
            }
            if (!Array.isArray(alerts) || alerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 20px; color: var(--text-muted); font-weight: 600;">No alerts available.</td></tr>';
                return;
            }
            renderAlertsTable('all-alerts-body', alerts, true);
        }

        function filterAlerts() {
            const q = (document.getElementById('alert-search') ? document.getElementById('alert-search').value : '').toLowerCase();
            const rows = document.querySelectorAll('#all-alerts-body tr');
            rows.forEach(r => {
                const text = r.innerText.toLowerCase();
                r.style.display = text.includes(q) ? '' : 'none';
            });
        }

        function renderAlertsTable(targetId, alerts, showActions) {
            const tbody = document.getElementById(targetId);
            if (!tbody) return;
            const cols = showActions ? 9 : 7;
            if (!Array.isArray(alerts) || alerts.length === 0) {
                tbody.innerHTML = `<tr><td colspan="${cols}" style="text-align: center; padding: 20px; color: var(--text-muted); font-weight: 600;">No alerts available.</td></tr>`;
                return;
            }
            tbody.innerHTML = alerts.map(a => `
                <tr>
                    <td><code>${escapeHtml(a.id || '-')}</code></td>
                    <td>${a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '-'}</td>
                    <td><strong style="color: var(--accent-blue); cursor: pointer;" onclick="openEvidenceModal('${a.id}')">${escapeHtml(a.title || 'Untitled Alert')}</strong></td>
                    <td><span class="badge-sev sev-${(a.severity||'low').toLowerCase()}">${escapeHtml(a.severity || 'LOW')}</span></td>
                    <td>${escapeHtml(a.affected_asset || a.source_ip || a.source || '0.0.0.0')} (${escapeHtml(a.affected_user || a.username || 'system')})</td>
                    ${showActions ? `<td>${escapeHtml(a.mitre_technique || a.mitre_technique_id || 'T1059')}</td>` : ''}
                    <td><strong>${a.risk_score !== undefined ? a.risk_score : 50}</strong> / 100</td>
                    <td>
                        <select onchange="updateAlertLifecycle('${a.id}', this.value)" style="padding: 2px 6px; font-size: 0.75rem;">
                            <option value="NEW" ${a.status==='NEW'?'selected':''}>NEW</option>
                            <option value="ACKNOWLEDGED" ${a.status==='ACKNOWLEDGED'?'selected':''}>ACKNOWLEDGED</option>
                            <option value="INVESTIGATING" ${a.status==='INVESTIGATING'?'selected':''}>INVESTIGATING</option>
                            <option value="CONFIRMED" ${a.status==='CONFIRMED'?'selected':''}>CONFIRMED</option>
                            <option value="RESOLVED" ${a.status==='RESOLVED'?'selected':''}>RESOLVED</option>
                            <option value="FALSE_POSITIVE" ${a.status==='FALSE_POSITIVE'?'selected':''}>FALSE_POSITIVE</option>
                        </select>
                    </td>
                    ${showActions ? `
                    <td>
                        <button onclick="openEvidenceModal('${a.id}')" style="padding: 3px 6px; font-size: 0.72rem;">Evidence</button>
                    </td>` : ''}
                </tr>
            `).join('');
        }

        async function updateAlertLifecycle(alertId, newStatus) {
            let fp_reason = "";
            if (newStatus === "FALSE_POSITIVE") {
                fp_reason = prompt("Please provide justification / guidance for marking this alert as FALSE_POSITIVE:") || "Analyst false positive tuning";
            }
            const res = await fetch(API_BASE + '/api/v1/alerts/' + alertId + '/status', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus, fp_reason: fp_reason })
            });
            if (res.ok) {
                refreshData();
                loadAlerts();
            } else {
                alert("Failed to update alert status.");
            }
        }

        async function openEvidenceModal(alertId) {
            document.getElementById('evidence-modal').style.display = 'flex';
            document.getElementById('modal-alert-content').innerHTML = 'Loading alert evidence...';
            
            const data = await fetchAPI('/api/v1/alerts/' + alertId + '/evidence');
            if (!data || data._error || !data.alert) {
                document.getElementById('modal-alert-content').innerHTML = '<div style="color: var(--sev-critical); padding: 15px;">Failed to load evidence details.</div>';
                return;
            }

            const a = data.alert;
            const bd = a.risk_breakdown || {};
            
            let html = `
                <div style="margin-bottom: 15px;">
                    <span class="badge-sev sev-${(a.severity||'low').toLowerCase()}">${escapeHtml(a.severity)}</span>
                    <span style="font-weight: 700; margin-left: 10px;">Risk Score: ${a.risk_score}/100</span>
                    <p style="margin-top: 8px; color: var(--text-muted); font-size: 0.88rem;">${escapeHtml(a.description || '')}</p>
                </div>

                    <div style="background: #0a0f0c; padding: 12px; border-radius: 6px; margin-bottom: 15px; border-left: 3px solid var(--accent-cyan);">
                    <h4 style="font-size: 0.85rem; color: var(--accent-cyan); margin-bottom: 6px;">WHY DID THIS ALERT FIRE?</h4>
                    <p style="font-size: 0.83rem; font-family: 'JetBrains Mono', monospace; color: #fff;">${escapeHtml(a.reason || 'Signature match condition triggered.')}</p>
                </div>

                <div style="background: #0f172a; padding: 12px; border-radius: 6px; margin-bottom: 15px;">
                    <h4 style="font-size: 0.85rem; color: #fff; margin-bottom: 8px;">TRANSPARENT RISK SCORE BREAKDOWN</h4>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; font-size: 0.8rem;">
                        <div>Base Severity: +${bd.base_severity || 0}</div>
                        <div>Event Frequency: +${bd.event_frequency || 0}</div>
                        <div>Confidence: +${bd.confidence || 0}</div>
                        <div>Asset Criticality: +${bd.asset_criticality || 0}</div>
                        <div>Account Sensitivity: +${bd.account_sensitivity || 0}</div>
                        <div>Correlation Strength: +${bd.correlation_strength || 0}</div>
                    </div>
                </div>

                <div style="margin-bottom: 15px;">
                    <h4 style="font-size: 0.85rem; color: #fff; margin-bottom: 8px;">TRIGGERING EVIDENCE & TELEMETRY PAYLOADS (${(data.triggering_events||[]).length})</h4>
                    <div style="max-height: 200px; overflow-y: auto; background: #080b12; padding: 10px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;">
                        ${(data.triggering_events||[]).length > 0 ? escapeHtml(JSON.stringify(data.triggering_events, null, 2)) : 'No raw events attached.'}
                    </div>
                </div>

                <div>
                    <h4 style="font-size: 0.85rem; color: #fff; margin-bottom: 6px;">MITRE ATT&CK REFERENCE</h4>
                    <p style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(a.mitre_tactic || 'Execution')} — ${escapeHtml(a.mitre_technique || 'T1059')}</p>
                </div>
            `;

            document.getElementById('modal-alert-title').innerText = `Alert Evidence: ${a.title} (${a.id})`;
            document.getElementById('modal-alert-content').innerHTML = html;
        }

        function closeEvidenceModal() {
            document.getElementById('evidence-modal').style.display = 'none';
        }

        async function refreshRules() {
            const tbody = document.getElementById('rules-catalog-body');
            if (!tbody) return;
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--text-muted);">Loading detection rules...</td></tr>';
            
            const data = await fetchAPI('/api/v1/detections/rules');
            if (data && data._error) {
                const errMsg = data.detail || data.statusText || ("HTTP " + data.status);
                tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--sev-critical);">Unable to load detection rules: ${escapeHtml(errMsg)}</td></tr>`;
                return;
            }
            const rules = (data && Array.isArray(data.rules)) ? data.rules : (Array.isArray(data) ? data : []);
            if (rules.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--text-muted); font-weight: 600;">No detection rules available.</td></tr>';
                return;
            }

            tbody.innerHTML = rules.map(r => `
                <tr>
                    <td><code>${escapeHtml(r.rule_id || r.id)}</code></td>
                    <td><strong>${escapeHtml(r.name || r.rule_name)}</strong></td>
                    <td><span class="badge-sev sev-${(r.severity||'low').toLowerCase()}">${escapeHtml(r.severity || 'LOW')}</span></td>
                    <td>${r.confidence || 80}%</td>
                    <td>Threshold: ${r.threshold || 1} / ${r.time_window || 60}s</td>
                    <td>${escapeHtml(r.mitre_tactic || 'Execution')} (${escapeHtml(r.mitre_technique_id || 'T1059')})</td>
                    <td><span class="badge-sev ${r.enabled ? 'sev-low' : 'sev-critical'}">${r.enabled ? 'ENABLED' : 'DISABLED'}</span></td>
                    <td>
                        <button onclick="toggleRule('${r.rule_id || r.id}', ${!r.enabled})" style="padding: 3px 8px; font-size: 0.72rem; background: ${r.enabled ? 'var(--sev-critical)' : 'var(--accent-blue)'};">
                            ${r.enabled ? 'Disable' : 'Enable'}
                        </button>
                    </td>
                </tr>
            `).join('');
        }

        async function toggleRule(ruleId, enableState) {
            const res = await fetch(API_BASE + '/api/v1/detections/rules/' + ruleId + '/enable', {
                method: 'PATCH',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ enabled: enableState })
            });
            if (res.ok) {
                refreshRules();
            } else {
                alert("Failed to toggle rule state.");
            }
        }

        async function loadIncidents() {
            const tbody = document.getElementById('incidents-body');
            if (!tbody) return;
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--text-muted);">Loading incidents & cases...</td></tr>';

            const data = await fetchAPI('/api/incidents');
            if (data && data._error) {
                const errMsg = data.detail || data.statusText || ("HTTP " + data.status);
                tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--sev-critical);">Unable to load incidents: ${escapeHtml(errMsg)}</td></tr>`;
                return;
            }
            const incidents = Array.isArray(data) ? data : (Array.isArray(data?.incidents) ? data.incidents : []);
            if (incidents.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--text-muted); font-weight: 600;">No active incidents.</td></tr>';
                return;
            }
            tbody.innerHTML = incidents.map(i => `
                <tr>
                    <td><code>${escapeHtml(i.id || '-')}</code></td>
                    <td><strong>${escapeHtml(i.title || 'Untitled Incident')}</strong></td>
                    <td><span class="badge-sev sev-${(i.severity||'high').toLowerCase()}">${escapeHtml(i.severity || 'HIGH')}</span></td>
                    <td>${escapeHtml(i.priority || 'P2')}</td>
                    <td><span class="badge-live">${escapeHtml(i.status || 'open')}</span></td>
                    <td>${escapeHtml(i.category || 'Security Breach')}</td>
                    <td>${i.created_at ? new Date(i.created_at).toLocaleString() : '-'}</td>
                    <td><button onclick="resolveIncident('${i.id}')" style="padding: 4px 8px; font-size: 0.75rem;">Resolve Incident</button></td>
                </tr>
            `).join('');
        }

        async function resolveIncident(incId) {
            await fetch(API_BASE + '/api/incidents/' + incId + '/resolve', { method: 'POST' });
            loadIncidents();
            refreshData();
        }

        async function loadAssets() {
            const tbody = document.getElementById('assets-body');
            if (!tbody) return;
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--text-muted);">Loading enterprise assets...</td></tr>';

            const data = await fetchAPI('/api/assets');
            if (data && data._error) {
                const errMsg = data.detail || data.statusText || ("HTTP " + data.status);
                tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--sev-critical);">Unable to load assets: ${escapeHtml(errMsg)}</td></tr>`;
                return;
            }
            const assets = Array.isArray(data) ? data : (Array.isArray(data?.assets) ? data.assets : []);
            if (assets.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--text-muted); font-weight: 600;">No assets available.</td></tr>';
                return;
            }
            tbody.innerHTML = assets.map(a => `
                <tr>
                    <td><code>${escapeHtml(a.id || '-')}</code></td>
                    <td><strong>${escapeHtml(a.hostname || '-')}</strong></td>
                    <td>${escapeHtml(a.ip || '-')}</td>
                    <td>${escapeHtml(a.os || '-')}</td>
                    <td>${escapeHtml(a.role || '-')}</td>
                    <td><span class="badge-sev sev-${(a.criticality||'medium').toLowerCase() === 'critical' ? 'critical' : 'medium'}">${escapeHtml(a.criticality || 'medium')}</span></td>
                    <td><span class="badge-live">${escapeHtml(a.agent_status || 'OFFLINE')}</span></td>
                    <td><strong>${a.risk_score !== undefined ? a.risk_score : 0}</strong> / 100</td>
                </tr>
            `).join('');
        }

        async function loadHealth() {
            const tbody = document.getElementById('health-body');
            if (!tbody) return;
            tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 20px; color: var(--text-muted);">Checking platform & sensor health statuses...</td></tr>';

            const health = await fetchAPI('/api/soc/health');
            if (health && health._error) {
                const errMsg = health.detail || health.statusText || ("HTTP " + health.status);
                tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; padding: 20px; color: var(--sev-critical);">Unable to check health status: ${escapeHtml(errMsg)}</td></tr>`;
                return;
            }
            
            let html = '';
            if (health && Array.isArray(health.services)) {
                html = health.services.map(s => {
                    const st = s.status || 'UNKNOWN';
                    const badgeClass = st === 'ONLINE' ? 'sev-low' : (st === 'SIMULATION' ? 'sev-medium' : (st === 'NOT_CONFIGURED' ? 'sev-low' : 'sev-critical'));
                    return `
                        <tr>
                            <td><strong>${escapeHtml(s.name || 'Service')}</strong></td>
                            <td><span class="badge-sev ${badgeClass}">${escapeHtml(st)}</span></td>
                            <td>${escapeHtml(s.details || s.description || '-')}</td>
                        </tr>
                    `;
                }).join('');
            }

            const integRes = await fetchAPI('/api/v1/integrations/health');
            if (integRes && !integRes._error && Array.isArray(integRes.integrations)) {
                html += '<tr><td colspan="3" style="background: rgba(59, 130, 246, 0.1); font-weight: 600; text-align: center; color: var(--accent-cyan);">Phase 4 Vendor Integration Matrix</td></tr>';
                html += integRes.integrations.map(i => {
                    const st = i.status || 'NOT_CONFIGURED';
                    const badgeClass = st === 'ONLINE' ? 'sev-low' : (st === 'SIMULATION' ? 'sev-medium' : (st === 'NOT_CONFIGURED' ? 'sev-low' : 'sev-critical'));
                    return `
                        <tr>
                            <td><strong>${escapeHtml(i.name || 'Integration')} (${escapeHtml((i.type||'').toUpperCase())})</strong></td>
                            <td><span class="badge-sev ${badgeClass}">${escapeHtml(st)}</span></td>
                            <td>Received: ${i.events_received || 0} | Processed: ${i.events_processed || 0} | Failed: ${i.events_failed || 0} | Latency: ${i.processing_latency_ms || 0}ms</td>
                        </tr>
                    `;
                }).join('');
            }

            tbody.innerHTML = html || '<tr><td colspan="3" style="text-align: center; padding: 20px; color: var(--text-muted); font-weight: 600;">No health metrics available.</td></tr>';
        }

        async function loadPlaybooks() {
            const tbody = document.getElementById('playbooks-body');
            if (!tbody) return;
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 20px; color: var(--text-muted);">Loading playbook catalog...</td></tr>';

            const data = await fetchAPI('/api/v1/playbooks');
            if (data && data._error) {
                const errMsg = data.detail || data.statusText || ("HTTP " + data.status);
                tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 20px; color: var(--sev-critical);">Unable to load playbooks: ${escapeHtml(errMsg)}</td></tr>`;
                await loadPlaybookExecutions();
                return;
            }
            const playbooks = Array.isArray(data) ? data : (Array.isArray(data?.playbooks) ? data.playbooks : []);
            if (playbooks.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 20px; color: var(--text-muted); font-weight: 600;">No playbooks available.</td></tr>';
                await loadPlaybookExecutions();
                return;
            }

            tbody.innerHTML = playbooks.map(p => {
                const modeClass = p.execution_mode === 'LIVE' ? 'sev-critical' : (p.execution_mode === 'LAB' ? 'sev-high' : 'sev-medium');
                const riskClass = p.risk_level === 'HIGH' || p.risk_level === 'CRITICAL' ? 'sev-critical' : (p.risk_level === 'MEDIUM' ? 'sev-high' : 'sev-low');
                const actionsStr = Array.isArray(p.actions) ? p.actions.map(a => typeof a === 'object' ? a.action_type : a).join(', ') : (p.action_type || 'SIMULATION_ACTION');
                
                return `
                    <tr>
                        <td><code>${escapeHtml(p.id || p.playbook_id || '-')}</code></td>
                        <td><strong>${escapeHtml(p.name || 'Playbook')}</strong><br><span style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(p.description || '')}</span></td>
                        <td><span class="badge-sev ${modeClass}">${escapeHtml(p.execution_mode || 'SIMULATION')}</span></td>
                        <td><span class="badge-sev ${riskClass}">${escapeHtml(p.risk_level || 'LOW')}</span></td>
                        <td>${p.requires_approval ? '<span class="badge-sev sev-high">Approval Required</span>' : '<span class="badge-sev sev-low">Auto</span>'}</td>
                        <td><code style="font-size: 0.72rem;">${escapeHtml(actionsStr)}</code></td>
                        <td>
                            <button onclick="previewPlaybook('${p.id || p.playbook_id}')" style="padding: 4px 8px; font-size: 0.75rem; background: #6366f1;">Preview</button>
                            <button onclick="runPlaybook('${p.id || p.playbook_id}')" style="padding: 4px 8px; font-size: 0.75rem;">Run (Simulation)</button>
                        </td>
                    </tr>
                `;
            }).join('');

            await loadPlaybookExecutions();
        }

        async function previewPlaybook(pbId) {
            const target = prompt("Enter target IP or Hostname for dry-run preview:", "10.0.0.15") || "10.0.0.15";
            const res = await fetch(API_BASE + '/api/v1/playbooks/' + pbId + '/preview', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ target: target })
            });
            const data = await res.json();
            alert("SOAR Dry-Run Preview (No State Changes):\\n" + JSON.stringify(data, null, 2));
        }

        async function loadPlaybookExecutions() {
            const tbody = document.getElementById('playbook-executions-body');
            if (!tbody) return;
            tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 20px; color: var(--text-muted);">Loading execution history...</td></tr>';

            const data = await fetchAPI('/api/v1/playbook-executions');
            if (data && data._error) {
                const errMsg = data.detail || data.statusText || ("HTTP " + data.status);
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 20px; color: var(--sev-critical);">Unable to load execution history: ${escapeHtml(errMsg)}</td></tr>`;
                return;
            }
            const executions = (data && Array.isArray(data.executions)) ? data.executions : (Array.isArray(data) ? data : []);
            if (executions.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 20px; color: var(--text-muted); font-weight: 600;">No playbook executions available.</td></tr>';
                return;
            }

            tbody.innerHTML = executions.map(e => {
                const statusClass = e.status === 'COMPLETED' ? 'sev-low' : (e.status === 'PENDING_APPROVAL' ? 'sev-medium' : 'sev-critical');
                const modeClass = e.execution_mode === 'LIVE' ? 'sev-critical' : 'sev-medium';
                
                let ctrlBtns = '';
                if (e.status === 'PENDING_APPROVAL') {
                    ctrlBtns = `
                        <button onclick="approveExec('${e.execution_id}')" style="padding: 3px 6px; font-size: 0.72rem; background: var(--status-online);">Approve</button>
                        <button onclick="rejectExec('${e.execution_id}')" style="padding: 3px 6px; font-size: 0.72rem; background: var(--sev-critical);">Reject</button>
                    `;
                } else if (e.status === 'COMPLETED' && e.rollback_status !== 'COMPLETED') {
                    ctrlBtns = `<button onclick="rollbackExec('${e.execution_id}')" style="padding: 3px 6px; font-size: 0.72rem; background: var(--accent-cyan);">Rollback</button>`;
                } else {
                    ctrlBtns = `<span style="font-size: 0.75rem; color: var(--text-muted);">${e.rollback_status === 'COMPLETED' ? 'Rolled Back' : 'Done'}</span>`;
                }

                return `
                    <tr>
                        <td><code>${escapeHtml(e.execution_id || '-')}</code></td>
                        <td><strong>${escapeHtml(e.playbook_id || '-')}</strong></td>
                        <td>${escapeHtml(e.target || '127.0.0.1')}</td>
                        <td><span class="badge-sev ${modeClass}">${escapeHtml(e.execution_mode || 'SIMULATION')}</span></td>
                        <td><span class="badge-sev ${statusClass}">${escapeHtml(e.status || 'UNKNOWN')}</span></td>
                        <td>${escapeHtml(e.requested_by || 'system')}</td>
                        <td>${escapeHtml(e.approved_by || '-')}</td>
                        <td>${e.started_at ? new Date(e.started_at).toLocaleTimeString() : '-'}</td>
                        <td>${ctrlBtns}</td>
                    </tr>
                `;
            }).join('');
        }

        async function runPlaybook(pbId) {
            const target = prompt("Enter target IP or Hostname for playbook execution:", "10.0.0.15") || "10.0.0.15";
            const res = await fetch(API_BASE + '/api/v1/playbooks/' + pbId + '/execute', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ playbook_id: pbId, target: target, approved: false })
            });
            const data = await res.json();
            alert("SOAR Engine Response:\\n" + JSON.stringify(data, null, 2));
            loadPlaybookExecutions();
        }

        async function approveExec(execId) {
            const reason = prompt("Enter justification for approving high-risk execution:", "Verified security alert by L2 Analyst") || "Analyst Approval";
            const res = await fetch(API_BASE + '/api/v1/playbook-executions/' + execId + '/approve', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ reason: reason })
            });
            const data = await res.json();
            alert("Approval Result:\\n" + JSON.stringify(data, null, 2));
            loadPlaybookExecutions();
        }

        async function rejectExec(execId) {
            const reason = prompt("Enter reason for rejecting execution:", "False positive alert") || "Rejected by Analyst";
            const res = await fetch(API_BASE + '/api/v1/playbook-executions/' + execId + '/reject', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ reason: reason })
            });
            const data = await res.json();
            alert("Rejection Result:\\n" + JSON.stringify(data, null, 2));
            loadPlaybookExecutions();
        }

        async function rollbackExec(execId) {
            if (!confirm("Are you sure you want to rollback actions for execution " + execId + "?")) return;
            const res = await fetch(API_BASE + '/api/v1/playbook-executions/' + execId + '/rollback', {
                method: 'POST'
            });
            const data = await res.json();
            alert("Rollback Result:\\n" + JSON.stringify(data, null, 2));
            loadPlaybookExecutions();
        }

        async function loadGraph() {
            const container = document.getElementById('network-graph');
            if (!container) return;
            container.innerHTML = '<div style="padding: 30px; text-align: center; color: var(--text-muted);">Loading entity relationship topology...</div>';

            const graphData = await fetchAPI('/api/investigation/graph');
            if (graphData && graphData._error) {
                const errMsg = graphData.detail || graphData.statusText || ("HTTP " + graphData.status);
                container.innerHTML = `<div style="padding: 30px; text-align: center; color: var(--sev-critical);">Unable to load investigation graph: ${escapeHtml(errMsg)}</div>`;
                return;
            }
            if (!graphData || !Array.isArray(graphData.nodes) || graphData.nodes.length === 0) {
                container.innerHTML = '<div style="padding: 30px; text-align: center; color: var(--text-muted); font-weight: 600;">No investigation graph data available.</div>';
                return;
            }

            if (typeof vis === 'undefined') {
                container.innerHTML = '<div style="padding: 30px; text-align: center; color: var(--text-muted); font-weight: 600;">Vis.js network visualizer library is loading or unavailable.</div>';
                return;
            }

            container.innerHTML = '';
            const nodes = new vis.DataSet(graphData.nodes.map(n => ({
                id: n.id,
                label: n.label || n.name || n.id,
                shape: n.type === 'alert' ? 'diamond' : (n.type === 'user' ? 'icon' : 'box'),
                color: n.type === 'alert' ? '#ef4444' : (n.type === 'host' ? '#3b82f6' : '#06b6d4')
            })));
            const edges = new vis.DataSet((Array.isArray(graphData.edges) ? graphData.edges : []).map(e => ({ from: e.source, to: e.target, label: e.relationship || '' })));
            
            new vis.Network(container, { nodes, edges }, {
                nodes: { font: { color: '#fff' } },
                edges: { font: { color: '#94a3b8', size: 10 }, color: '#1f293d' }
            });
        }

        async function loadMitre() {
            const stats = document.getElementById('mitre-summary-stats');
            const container = document.getElementById('mitre-matrix-container');
            if (stats) stats.innerText = 'Loading ATT&CK matrix...';
            if (container) container.innerHTML = '';

            const data = await fetchAPI('/api/mitre/coverage');
            if (data && data._error) {
                const errMsg = data.detail || data.statusText || ("HTTP " + data.status);
                if (stats) stats.innerHTML = `<span style="color: var(--sev-critical);">Unable to load MITRE ATT&CK matrix: ${escapeHtml(errMsg)}</span>`;
                return;
            }
            if (!data || !data.matrix || typeof data.matrix !== 'object' || Object.keys(data.matrix).length === 0) {
                if (stats) stats.innerText = 'No MITRE ATT&CK coverage data available.';
                return;
            }

            if (stats) {
                stats.innerHTML = `
                    Active Detection Rules: <strong>${data.total_active_rules || 0}</strong> | 
                    Tactic Coverage: <strong>${data.covered_tactics || 0}/${data.total_tactics || 0} (${data.coverage_percentage || 0}%)</strong> | 
                    Total Detections Triggered: <strong>${data.total_detections_triggered || 0}</strong>
                `;
            }

            if (container) {
                container.innerHTML = Object.entries(data.matrix).map(([tactic, rules]) => `
                    <div style="background: #0f172a; padding: 12px; border-radius: 6px; border: 1px solid var(--border-color);">
                        <div style="font-weight: 600; font-size: 0.8rem; margin-bottom: 8px; color: var(--accent-cyan);">${escapeHtml(tactic)}</div>
                        ${Array.isArray(rules) && rules.length > 0 ? rules.map(r => `
                            <div style="background: var(--bg-card); padding: 8px; border-radius: 4px; font-size: 0.72rem; margin-bottom: 6px; border-left: 3px solid ${r.coverage_status === 'ALERTED' ? 'var(--sev-critical)' : 'var(--accent-blue)'};">
                                <strong>${escapeHtml(r.technique_id || 'T1059')}</strong> - ${escapeHtml(r.technique_name || r.name || '')}<br>
                                <span style="color: var(--text-muted);">${escapeHtml(r.rule_name || r.rule_id || '')}</span><br>
                                <span class="badge-sev ${r.coverage_status === 'ALERTED' ? 'sev-critical' : 'sev-low'}" style="font-size: 0.65rem;">${escapeHtml(r.coverage_status || 'ACTIVE')} (${r.alert_count || 0} alerts)</span>
                            </div>
                        `).join('') : '<div style="font-size: 0.72rem; color: var(--text-muted);">No rules active</div>'}
                    </div>
                `).join('');
            }
        }

        function initHuntingView() {
            const qInput = document.getElementById('hunting-query');
            const tbody = document.getElementById('hunting-results-body');
            if (!tbody) return;
            const q = qInput ? qInput.value.trim() : '';
            if (!q) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--text-muted);">Enter a search query (e.g., IP address, hostname, username, event type) above to hunt telemetry events.</td></tr>';
            } else {
                runHuntingQuery();
            }
        }

        async function runHuntingQuery() {
            const tbody = document.getElementById('hunting-results-body');
            if (!tbody) return;
            
            const q = (document.getElementById('hunting-query') ? document.getElementById('hunting-query').value : '').trim();
            const modeSelect = document.getElementById('source-mode-filter');
            const sourceMode = modeSelect ? modeSelect.value : 'all';

            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--text-muted);">Searching telemetry events...</td></tr>';

            let endpoint = '/api/v1/telemetry/events?limit=50';
            if (q) endpoint += '&search_query=' + encodeURIComponent(q);
            if (sourceMode && sourceMode !== 'all') endpoint += '&source_mode=' + encodeURIComponent(sourceMode);

            const data = await fetchAPI(endpoint);
            if (data && data._error) {
                const errMsg = data.detail || data.statusText || ("HTTP " + data.status);
                tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--sev-critical);">Unable to search telemetry events: ${escapeHtml(errMsg)}</td></tr>`;
                return;
            }
            const events = data ? (Array.isArray(data.events) ? data.events : (Array.isArray(data) ? data : [])) : [];
            if (events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--text-muted); font-weight: 600;">No matching telemetry events found.</td></tr>';
                return;
            }
            tbody.innerHTML = events.map(e => `
                <tr>
                    <td><code>${escapeHtml(e.event_id || e.id || '-')}</code></td>
                    <td>${e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '-'}</td>
                    <td>${escapeHtml(e.source_type || 'system')} (${escapeHtml(e.source_mode || 'live')})</td>
                    <td>${escapeHtml(e.hostname || '-')}</td>
                    <td>${escapeHtml(e.source_ip || '-')}</td>
                    <td>${escapeHtml(e.username || '-')}</td>
                    <td><strong>${escapeHtml(e.event_type || e.message || 'Telemetry Event')}</strong></td>
                    <td><span class="badge-sev sev-${(e.severity || 'low').toLowerCase()}">${escapeHtml(e.severity || 'low')}</span></td>
                </tr>
            `).join('');
        }

        async function loadReportsAndAudit() {
            const tbody = document.getElementById('audit-log-body');
            if (!tbody) return;
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 20px; color: var(--text-muted);">Loading security audit logs...</td></tr>';

            const data = await fetchAPI('/api/v1/audit/logs?limit=50');
            if (data && data._error) {
                if (data.status === 403) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 20px; color: var(--text-muted);">Access Restricted: Audit logs require audit.read permission (Administrator or SOC Manager).</td></tr>';
                } else {
                    const errMsg = data.detail || data.statusText || ("HTTP " + data.status);
                    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 20px; color: var(--sev-critical);">Unable to load audit logs: ${escapeHtml(errMsg)}</td></tr>`;
                }
                return;
            }
            const logs = (data && Array.isArray(data.logs)) ? data.logs : (Array.isArray(data) ? data : []);
            if (logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 20px; color: var(--text-muted); font-weight: 600;">No audit records available.</td></tr>';
                return;
            }

            tbody.innerHTML = logs.map(l => `
                <tr>
                    <td>${l.timestamp ? new Date(l.timestamp).toLocaleString() : '-'}</td>
                    <td><strong>${escapeHtml(l.username || '-')}</strong></td>
                    <td>${escapeHtml(l.role || '-')}</td>
                    <td><code>${escapeHtml(l.action || '-')}</code></td>
                    <td>${escapeHtml(l.target_type || '-')}</td>
                    <td><code>${escapeHtml(l.target_id || '-')}</code></td>
                    <td><span class="badge-sev ${l.status === 'SUCCESS' ? 'sev-low' : 'sev-critical'}">${escapeHtml(l.status || 'SUCCESS')}</span></td>
                </tr>
            `).join('');
        }

        async function downloadReport(fmt) {
            const token = localStorage.getItem("soc_token");
            if (!token) {
                alert("Authentication required to download report.");
                showLoginOverlay();
                return;
            }
            try {
                const res = await fetch(API_BASE + '/api/reports/download?fmt=' + encodeURIComponent(fmt), {
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                });
                if (!res.ok) {
                    let errText = res.statusText;
                    try {
                        const errData = await res.json();
                        errText = errData.detail || errData.message || res.statusText;
                    } catch (e) {}
                    alert("Failed to download report (HTTP " + res.status + "): " + errText);
                    return;
                }
                const blob = await res.blob();
                const filename = fmt === 'csv' ? 'soc_alerts_report.csv' : 'soc_daily_report.json';
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            } catch (e) {
                console.error("Error downloading report:", e);
                alert("Error downloading report: " + e.message);
            }
        }

        refreshData();
        setInterval(refreshData, 5000);
    </script>
</body>
</html>"""
