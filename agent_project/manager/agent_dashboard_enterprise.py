#!/usr/bin/env python3
"""
SecretSnipe Enterprise Agent Dashboard
=====================================
Full-featured management dashboard with:
- Agent overview and real-time status
- Log viewer with filtering
- Schedule management (CRUD)
- Watch paths configuration
- Findings viewer with actions
- Configuration management
"""

import os
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict

import dash
from dash import dcc, html, dash_table, callback_context
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
import requests
import plotly.graph_objects as go
import plotly.express as px

# Configuration
MANAGER_URL = os.getenv("MANAGER_URL", "http://localhost:8443")
API_KEY = os.getenv("API_KEY", "")

# Dashboard App
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.DARKLY, dbc.icons.FONT_AWESOME],
    suppress_callback_exceptions=True,
    title="SecretSnipe Agent Manager"
)

# ==================== API Helpers ====================

def api_request(method: str, endpoint: str, data: dict = None) -> Optional[dict]:
    """Make API request"""
    url = f"{MANAGER_URL}/api/v1{endpoint}"
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    
    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            resp = requests.post(url, headers=headers, json=data, timeout=10)
        elif method == "PUT":
            resp = requests.put(url, headers=headers, json=data, timeout=10)
        elif method == "DELETE":
            resp = requests.delete(url, headers=headers, timeout=10)
        else:
            return None
        
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception as e:
        print(f"API error: {e}")
        return None


def get_agents() -> List[Dict]:
    """Get all agents"""
    result = api_request("GET", "/agents")
    if result and result.get("success"):
        return result.get("data", [])
    return []


def get_agent_logs(agent_id: str, lines: int = 100, level: str = None) -> List[Dict]:
    """Get agent logs"""
    endpoint = f"/agents/{agent_id}/logs?lines={lines}"
    if level:
        endpoint += f"&level={level}"
    result = api_request("GET", endpoint)
    if result and result.get("success"):
        return result.get("data", [])
    return []


def get_schedules(agent_id: str = None) -> List[Dict]:
    """Get schedules"""
    endpoint = f"/agents/{agent_id}/schedules" if agent_id else "/schedules"
    result = api_request("GET", endpoint)
    if result and result.get("success"):
        return result.get("data", [])
    return []


def get_findings(agent_id: str = None, severity: str = None, resolved: bool = None) -> List[Dict]:
    """Get findings"""
    params = []
    if agent_id:
        params.append(f"agent_id={agent_id}")
    if severity:
        params.append(f"severity={severity}")
    if resolved is not None:
        params.append(f"resolved={str(resolved).lower()}")
    
    endpoint = "/findings"
    if params:
        endpoint += "?" + "&".join(params)
    
    result = api_request("GET", endpoint)
    if result and result.get("success"):
        return result.get("data", [])
    return []


def get_watch_paths(agent_id: str) -> List[Dict]:
    """Get watch paths for agent"""
    result = api_request("GET", f"/agents/{agent_id}/watch-paths")
    if result and result.get("success"):
        return result.get("data", [])
    return []


def get_stats() -> Dict:
    """Get overall statistics"""
    result = api_request("GET", "/stats")
    if result and result.get("success"):
        return result.get("data", {})
    return {}


# ==================== Layout Components ====================

def create_navbar():
    """Create navigation bar"""
    return dbc.Navbar(
        dbc.Container([
            dbc.Row([
                dbc.Col(html.I(className="fas fa-shield-alt fa-2x text-success")),
                dbc.Col(dbc.NavbarBrand("SecretSnipe Agent Manager", className="ms-2 fs-4")),
            ], align="center", className="g-0"),
            dbc.NavbarToggler(id="navbar-toggler"),
            dbc.Collapse(
                dbc.Nav([
                    dbc.NavItem(dbc.NavLink("Agents", href="#", id="nav-agents", active=True)),
                    dbc.NavItem(dbc.NavLink("Logs", href="#", id="nav-logs")),
                    dbc.NavItem(dbc.NavLink("Schedules", href="#", id="nav-schedules")),
                    dbc.NavItem(dbc.NavLink("Findings", href="#", id="nav-findings")),
                    dbc.NavItem(dbc.NavLink("Settings", href="#", id="nav-settings")),
                ], className="ms-auto", navbar=True),
                id="navbar-collapse",
                navbar=True,
            ),
        ], fluid=True),
        color="dark",
        dark=True,
        className="mb-4"
    )


def create_stats_cards():
    """Create stats cards row"""
    return dbc.Row([
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4(id="stat-total-agents", className="card-title text-success"),
                html.P("Total Agents", className="card-text text-muted")
            ])
        ], color="dark", outline=True), width=3),
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4(id="stat-online-agents", className="card-title text-info"),
                html.P("Online Agents", className="card-text text-muted")
            ])
        ], color="dark", outline=True), width=3),
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4(id="stat-total-findings", className="card-title text-warning"),
                html.P("Total Findings", className="card-text text-muted")
            ])
        ], color="dark", outline=True), width=3),
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4(id="stat-jobs-24h", className="card-title text-primary"),
                html.P("Jobs (24h)", className="card-text text-muted")
            ])
        ], color="dark", outline=True), width=3),
    ], className="mb-4")


def create_agents_tab():
    """Create agents tab content"""
    return html.Div([
        dbc.Row([
            dbc.Col([
                html.H4("Agent Fleet", className="mb-3"),
                dbc.Button(
                    [html.I(className="fas fa-sync me-2"), "Refresh"],
                    id="btn-refresh-agents",
                    color="primary",
                    size="sm",
                    className="mb-3"
                ),
            ]),
        ]),
        dbc.Row([
            dbc.Col([
                dash_table.DataTable(
                    id="agents-table",
                    columns=[
                        {"name": "Hostname", "id": "hostname"},
                        {"name": "IP", "id": "ip_address"},
                        {"name": "OS", "id": "os_type"},
                        {"name": "Version", "id": "agent_version"},
                        {"name": "Status", "id": "status"},
                        {"name": "Last Heartbeat", "id": "last_heartbeat"},
                        {"name": "CPU %", "id": "cpu_percent"},
                        {"name": "Mem %", "id": "memory_percent"},
                        {"name": "Actions", "id": "actions", "presentation": "markdown"},
                    ],
                    data=[],
                    style_table={"overflowX": "auto"},
                    style_cell={
                        "backgroundColor": "#303030",
                        "color": "white",
                        "textAlign": "left",
                        "padding": "10px",
                    },
                    style_header={
                        "backgroundColor": "#1a1a1a",
                        "fontWeight": "bold",
                    },
                    style_data_conditional=[
                        {"if": {"filter_query": "{status} = 'online'"}, "backgroundColor": "#1a3d1a"},
                        {"if": {"filter_query": "{status} = 'offline'"}, "backgroundColor": "#3d1a1a"},
                    ],
                    row_selectable="single",
                    page_size=10,
                )
            ])
        ]),
        
        # Agent Details Modal
        dbc.Modal([
            dbc.ModalHeader(dbc.ModalTitle("Agent Details")),
            dbc.ModalBody(id="agent-details-body"),
            dbc.ModalFooter([
                dbc.Button("Create Job", id="btn-create-job", color="success", className="me-2"),
                dbc.Button("View Logs", id="btn-view-logs", color="info", className="me-2"),
                dbc.Button("Delete", id="btn-delete-agent", color="danger"),
            ]),
        ], id="agent-details-modal", size="lg"),
        
        # Create Job Modal
        dbc.Modal([
            dbc.ModalHeader(dbc.ModalTitle("Create Scan Job")),
            dbc.ModalBody([
                dbc.Form([
                    dbc.Row([
                        dbc.Label("Scan Paths (one per line)", width=12),
                        dbc.Col(
                            dbc.Textarea(id="job-scan-paths", rows=3, placeholder="C:\\Projects\nD:\\Code"),
                            width=12
                        ),
                    ], className="mb-3"),
                    dbc.Row([
                        dbc.Label("Scanners", width=12),
                        dbc.Col([
                            dbc.Checklist(
                                id="job-scanners",
                                options=[
                                    {"label": " Gitleaks", "value": "gitleaks"},
                                    {"label": " Trufflehog", "value": "trufflehog"},
                                    {"label": " Custom", "value": "custom"},
                                ],
                                value=["gitleaks", "trufflehog", "custom"],
                                inline=True,
                            )
                        ], width=12),
                    ], className="mb-3"),
                    dbc.Row([
                        dbc.Label("Priority", width=4),
                        dbc.Col(
                            dbc.Select(
                                id="job-priority",
                                options=[
                                    {"label": "High (1)", "value": "1"},
                                    {"label": "Normal (5)", "value": "5"},
                                    {"label": "Low (10)", "value": "10"},
                                ],
                                value="5",
                            ),
                            width=8
                        ),
                    ], className="mb-3"),
                ])
            ]),
            dbc.ModalFooter([
                dbc.Button("Create Job", id="btn-submit-job", color="success"),
                dbc.Button("Cancel", id="btn-cancel-job", color="secondary"),
            ]),
        ], id="create-job-modal", size="lg"),
    ])


def create_logs_tab():
    """Create logs tab content"""
    return html.Div([
        dbc.Row([
            dbc.Col([
                html.H4("Agent Logs", className="mb-3"),
            ], width=6),
            dbc.Col([
                dbc.InputGroup([
                    dbc.Select(
                        id="logs-agent-select",
                        options=[],
                        placeholder="Select Agent..."
                    ),
                    dbc.Select(
                        id="logs-level-select",
                        options=[
                            {"label": "All Levels", "value": ""},
                            {"label": "DEBUG", "value": "DEBUG"},
                            {"label": "INFO", "value": "INFO"},
                            {"label": "WARNING", "value": "WARNING"},
                            {"label": "ERROR", "value": "ERROR"},
                        ],
                        value=""
                    ),
                    dbc.Button(
                        [html.I(className="fas fa-sync")],
                        id="btn-refresh-logs",
                        color="primary"
                    ),
                ], size="sm"),
            ], width=6),
        ], className="mb-3"),
        dbc.Row([
            dbc.Col([
                html.Div(
                    id="logs-container",
                    style={
                        "backgroundColor": "#1a1a1a",
                        "padding": "15px",
                        "borderRadius": "5px",
                        "height": "500px",
                        "overflowY": "auto",
                        "fontFamily": "monospace",
                        "fontSize": "12px",
                    }
                )
            ])
        ])
    ])


def create_schedules_tab():
    """Create schedules tab content"""
    return html.Div([
        dbc.Row([
            dbc.Col([
                html.H4("Scan Schedules", className="mb-3"),
            ], width=6),
            dbc.Col([
                dbc.Button(
                    [html.I(className="fas fa-plus me-2"), "New Schedule"],
                    id="btn-new-schedule",
                    color="success",
                    size="sm",
                    className="float-end"
                ),
            ], width=6),
        ], className="mb-3"),
        dbc.Row([
            dbc.Col([
                dash_table.DataTable(
                    id="schedules-table",
                    columns=[
                        {"name": "Name", "id": "name"},
                        {"name": "Agent", "id": "agent_hostname"},
                        {"name": "Cron", "id": "cron_expression"},
                        {"name": "Paths", "id": "scan_paths_display"},
                        {"name": "Enabled", "id": "enabled"},
                        {"name": "Last Run", "id": "last_run"},
                        {"name": "Actions", "id": "actions", "presentation": "markdown"},
                    ],
                    data=[],
                    style_table={"overflowX": "auto"},
                    style_cell={
                        "backgroundColor": "#303030",
                        "color": "white",
                        "textAlign": "left",
                        "padding": "10px",
                    },
                    style_header={
                        "backgroundColor": "#1a1a1a",
                        "fontWeight": "bold",
                    },
                    page_size=10,
                )
            ])
        ]),
        
        # Create Schedule Modal
        dbc.Modal([
            dbc.ModalHeader(dbc.ModalTitle("Create Schedule")),
            dbc.ModalBody([
                dbc.Form([
                    dbc.Row([
                        dbc.Label("Name", width=3),
                        dbc.Col(dbc.Input(id="schedule-name", type="text", placeholder="Daily Scan"), width=9),
                    ], className="mb-3"),
                    dbc.Row([
                        dbc.Label("Agent", width=3),
                        dbc.Col(dbc.Select(id="schedule-agent", options=[]), width=9),
                    ], className="mb-3"),
                    dbc.Row([
                        dbc.Label("Cron Expression", width=3),
                        dbc.Col([
                            dbc.Input(id="schedule-cron", type="text", placeholder="0 2 * * *"),
                            dbc.FormText("Format: minute hour day month weekday (e.g., '0 2 * * *' = 2 AM daily)"),
                        ], width=9),
                    ], className="mb-3"),
                    dbc.Row([
                        dbc.Label("Scan Paths", width=3),
                        dbc.Col(dbc.Textarea(id="schedule-paths", rows=3, placeholder="C:\\Projects"), width=9),
                    ], className="mb-3"),
                    dbc.Row([
                        dbc.Label("Scanners", width=3),
                        dbc.Col([
                            dbc.Checklist(
                                id="schedule-scanners",
                                options=[
                                    {"label": " Gitleaks", "value": "gitleaks"},
                                    {"label": " Trufflehog", "value": "trufflehog"},
                                    {"label": " Custom", "value": "custom"},
                                ],
                                value=["gitleaks", "trufflehog", "custom"],
                            )
                        ], width=9),
                    ], className="mb-3"),
                ])
            ]),
            dbc.ModalFooter([
                dbc.Button("Create", id="btn-submit-schedule", color="success"),
                dbc.Button("Cancel", id="btn-cancel-schedule", color="secondary"),
            ]),
        ], id="create-schedule-modal", size="lg"),
    ])


def create_findings_tab():
    """Create findings tab content"""
    return html.Div([
        dbc.Row([
            dbc.Col([
                html.H4("Security Findings", className="mb-3"),
            ], width=3),
            dbc.Col([
                dbc.InputGroup([
                    dbc.Select(
                        id="findings-agent-select",
                        options=[{"label": "All Agents", "value": ""}],
                        value=""
                    ),
                    dbc.Select(
                        id="findings-severity-select",
                        options=[
                            {"label": "All Severities", "value": ""},
                            {"label": "Critical", "value": "critical"},
                            {"label": "High", "value": "high"},
                            {"label": "Medium", "value": "medium"},
                            {"label": "Low", "value": "low"},
                        ],
                        value=""
                    ),
                    dbc.Select(
                        id="findings-resolved-select",
                        options=[
                            {"label": "All", "value": ""},
                            {"label": "Unresolved", "value": "false"},
                            {"label": "Resolved", "value": "true"},
                        ],
                        value="false"
                    ),
                    dbc.Button([html.I(className="fas fa-sync")], id="btn-refresh-findings", color="primary"),
                ], size="sm"),
            ], width=9),
        ], className="mb-3"),
        dbc.Row([
            dbc.Col([
                dash_table.DataTable(
                    id="findings-table",
                    columns=[
                        {"name": "Type", "id": "secret_type"},
                        {"name": "Severity", "id": "severity"},
                        {"name": "File", "id": "file_path"},
                        {"name": "Line", "id": "line_number"},
                        {"name": "Scanner", "id": "scanner"},
                        {"name": "Verified", "id": "verified"},
                        {"name": "Actions", "id": "actions", "presentation": "markdown"},
                    ],
                    data=[],
                    style_table={"overflowX": "auto"},
                    style_cell={
                        "backgroundColor": "#303030",
                        "color": "white",
                        "textAlign": "left",
                        "padding": "10px",
                        "maxWidth": "200px",
                        "overflow": "hidden",
                        "textOverflow": "ellipsis",
                    },
                    style_header={
                        "backgroundColor": "#1a1a1a",
                        "fontWeight": "bold",
                    },
                    style_data_conditional=[
                        {"if": {"filter_query": "{severity} = 'critical'"}, "backgroundColor": "#4a1a1a"},
                        {"if": {"filter_query": "{severity} = 'high'"}, "backgroundColor": "#4a3a1a"},
                        {"if": {"filter_query": "{severity} = 'medium'"}, "backgroundColor": "#3a3a1a"},
                    ],
                    page_size=15,
                    row_selectable="multi",
                )
            ])
        ]),
        dbc.Row([
            dbc.Col([
                dbc.ButtonGroup([
                    dbc.Button([html.I(className="fas fa-check me-2"), "Mark Resolved"], id="btn-resolve-findings", color="success", size="sm"),
                    dbc.Button([html.I(className="fas fa-certificate me-2"), "Mark Verified"], id="btn-verify-findings", color="info", size="sm"),
                ], className="mt-3")
            ])
        ]),
        
        # Finding Details Modal
        dbc.Modal([
            dbc.ModalHeader(dbc.ModalTitle("Finding Details")),
            dbc.ModalBody(id="finding-details-body"),
        ], id="finding-details-modal", size="lg"),
    ])


def create_settings_tab():
    """Create settings tab content"""
    return html.Div([
        dbc.Row([
            dbc.Col([
                html.H4("Settings", className="mb-3"),
            ]),
        ]),
        dbc.Tabs([
            dbc.Tab([
                html.Div([
                    html.H5("Watch Paths", className="mt-3 mb-3"),
                    dbc.Row([
                        dbc.Col([
                            dbc.Select(id="watch-agent-select", options=[], placeholder="Select Agent..."),
                        ], width=4),
                        dbc.Col([
                            dbc.Button([html.I(className="fas fa-plus me-2"), "Add Path"], id="btn-add-watch-path", color="success", size="sm"),
                        ], width=2),
                    ], className="mb-3"),
                    html.Div(id="watch-paths-list"),
                ])
            ], label="Watch Paths"),
            dbc.Tab([
                html.Div([
                    html.H5("Agent Configuration", className="mt-3 mb-3"),
                    dbc.Row([
                        dbc.Col([
                            dbc.Select(id="config-agent-select", options=[], placeholder="Select Agent..."),
                        ], width=4),
                        dbc.Col([
                            dbc.Button([html.I(className="fas fa-save me-2"), "Save Config"], id="btn-save-config", color="success", size="sm"),
                        ], width=2),
                    ], className="mb-3"),
                    dbc.Textarea(
                        id="agent-config-editor",
                        rows=15,
                        style={"fontFamily": "monospace", "backgroundColor": "#1a1a1a", "color": "#fff"}
                    ),
                ])
            ], label="Configuration"),
        ])
    ])


# ==================== Main Layout ====================

app.layout = html.Div([
    create_navbar(),
    dbc.Container([
        create_stats_cards(),
        html.Div(id="tab-content"),
        dcc.Store(id="current-tab", data="agents"),
        dcc.Store(id="selected-agent-id", data=None),
        dcc.Interval(id="refresh-interval", interval=30000, n_intervals=0),  # 30s refresh
    ], fluid=True),
    
    # Toast notifications
    dbc.Toast(
        id="notification-toast",
        header="Notification",
        is_open=False,
        dismissable=True,
        duration=4000,
        style={"position": "fixed", "top": 66, "right": 10, "width": 350},
    ),
])


# ==================== Callbacks ====================

@app.callback(
    Output("current-tab", "data"),
    [Input("nav-agents", "n_clicks"),
     Input("nav-logs", "n_clicks"),
     Input("nav-schedules", "n_clicks"),
     Input("nav-findings", "n_clicks"),
     Input("nav-settings", "n_clicks")],
    prevent_initial_call=True
)
def switch_tab(agents, logs, schedules, findings, settings):
    """Switch between tabs"""
    ctx = callback_context
    if not ctx.triggered:
        return "agents"
    
    button_id = ctx.triggered[0]["prop_id"].split(".")[0]
    tab_map = {
        "nav-agents": "agents",
        "nav-logs": "logs",
        "nav-schedules": "schedules",
        "nav-findings": "findings",
        "nav-settings": "settings",
    }
    return tab_map.get(button_id, "agents")


@app.callback(
    Output("tab-content", "children"),
    [Input("current-tab", "data")]
)
def render_tab(tab):
    """Render the current tab content"""
    if tab == "agents":
        return create_agents_tab()
    elif tab == "logs":
        return create_logs_tab()
    elif tab == "schedules":
        return create_schedules_tab()
    elif tab == "findings":
        return create_findings_tab()
    elif tab == "settings":
        return create_settings_tab()
    return create_agents_tab()


@app.callback(
    [Output("stat-total-agents", "children"),
     Output("stat-online-agents", "children"),
     Output("stat-total-findings", "children"),
     Output("stat-jobs-24h", "children")],
    [Input("refresh-interval", "n_intervals")]
)
def update_stats(n):
    """Update statistics cards"""
    stats = get_stats()
    agents_by_status = stats.get("agents_by_status", {})
    
    total_agents = stats.get("total_agents", 0)
    online_agents = agents_by_status.get("online", 0)
    total_findings = stats.get("total_findings", 0)
    jobs_24h = stats.get("jobs_last_24h", 0)
    
    return str(total_agents), str(online_agents), str(total_findings), str(jobs_24h)


@app.callback(
    Output("agents-table", "data"),
    [Input("btn-refresh-agents", "n_clicks"),
     Input("refresh-interval", "n_intervals")]
)
def update_agents_table(n_clicks, n_intervals):
    """Update agents table"""
    agents = get_agents()
    
    rows = []
    for agent in agents:
        # Format last heartbeat
        last_hb = agent.get("last_heartbeat", "")
        if last_hb:
            try:
                dt = datetime.fromisoformat(last_hb.replace('Z', '+00:00'))
                last_hb = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
        
        rows.append({
            "hostname": agent.get("hostname", ""),
            "ip_address": agent.get("ip_address", ""),
            "os_type": agent.get("os_type", ""),
            "agent_version": agent.get("agent_version", ""),
            "status": agent.get("status", "unknown"),
            "last_heartbeat": last_hb,
            "cpu_percent": f"{agent.get('cpu_percent', 0):.1f}%",
            "memory_percent": f"{agent.get('memory_percent', 0):.1f}%",
            "agent_id": agent.get("agent_id", ""),
            "actions": f"[Scan]() | [Logs]() | [Delete]()",
        })
    
    return rows


@app.callback(
    Output("logs-container", "children"),
    [Input("btn-refresh-logs", "n_clicks"),
     Input("logs-agent-select", "value"),
     Input("logs-level-select", "value")]
)
def update_logs(n_clicks, agent_id, level):
    """Update logs display"""
    if not agent_id:
        return html.P("Select an agent to view logs", className="text-muted")
    
    logs = get_agent_logs(agent_id, 200, level if level else None)
    
    if not logs:
        return html.P("No logs available", className="text-muted")
    
    log_elements = []
    for log in logs:
        level_color = {
            "DEBUG": "#6c757d",
            "INFO": "#17a2b8",
            "WARNING": "#ffc107",
            "ERROR": "#dc3545",
        }.get(log.get("level", "INFO"), "#fff")
        
        timestamp = log.get("timestamp", "")[:19]
        message = log.get("message", "")
        
        log_elements.append(html.Div([
            html.Span(f"[{timestamp}] ", style={"color": "#6c757d"}),
            html.Span(f"[{log.get('level', 'INFO')}] ", style={"color": level_color, "fontWeight": "bold"}),
            html.Span(message),
        ], className="mb-1"))
    
    return log_elements


@app.callback(
    Output("logs-agent-select", "options"),
    [Input("current-tab", "data")]
)
def update_logs_agent_options(tab):
    """Update agent options for logs dropdown"""
    if tab != "logs":
        return []
    
    agents = get_agents()
    return [{"label": a.get("hostname", ""), "value": a.get("agent_id", "")} for a in agents]


@app.callback(
    Output("schedules-table", "data"),
    [Input("current-tab", "data"),
     Input("refresh-interval", "n_intervals")]
)
def update_schedules_table(tab, n):
    """Update schedules table"""
    if tab != "schedules":
        return []
    
    schedules = get_schedules()
    
    rows = []
    for sched in schedules:
        paths = sched.get("scan_paths", [])
        paths_display = ", ".join(paths[:2]) + ("..." if len(paths) > 2 else "")
        
        last_run = sched.get("last_run", "")
        if last_run:
            try:
                dt = datetime.fromisoformat(last_run.replace('Z', '+00:00'))
                last_run = dt.strftime("%Y-%m-%d %H:%M")
            except:
                pass
        
        rows.append({
            "name": sched.get("name", ""),
            "agent_hostname": sched.get("agent_hostname", ""),
            "cron_expression": sched.get("cron_expression", ""),
            "scan_paths_display": paths_display,
            "enabled": "✓" if sched.get("enabled", False) else "✗",
            "last_run": last_run or "Never",
            "schedule_id": sched.get("schedule_id", ""),
            "actions": "[Edit]() | [Delete]()",
        })
    
    return rows


@app.callback(
    Output("findings-table", "data"),
    [Input("btn-refresh-findings", "n_clicks"),
     Input("findings-agent-select", "value"),
     Input("findings-severity-select", "value"),
     Input("findings-resolved-select", "value"),
     Input("refresh-interval", "n_intervals")]
)
def update_findings_table(n_clicks, agent_id, severity, resolved, n_intervals):
    """Update findings table"""
    resolved_bool = None
    if resolved == "true":
        resolved_bool = True
    elif resolved == "false":
        resolved_bool = False
    
    findings = get_findings(
        agent_id if agent_id else None,
        severity if severity else None,
        resolved_bool
    )
    
    rows = []
    for finding in findings:
        rows.append({
            "secret_type": finding.get("secret_type", ""),
            "severity": finding.get("severity", ""),
            "file_path": finding.get("file_path", ""),
            "line_number": finding.get("line_number", ""),
            "scanner": finding.get("scanner", ""),
            "verified": "✓" if finding.get("verified", False) else "",
            "finding_id": finding.get("id", ""),
            "actions": "[View]() | [Resolve]()",
        })
    
    return rows


@app.callback(
    [Output("findings-agent-select", "options"),
     Output("schedule-agent", "options"),
     Output("watch-agent-select", "options"),
     Output("config-agent-select", "options")],
    [Input("current-tab", "data")]
)
def update_all_agent_dropdowns(tab):
    """Update all agent dropdown options"""
    agents = get_agents()
    options = [{"label": a.get("hostname", ""), "value": a.get("agent_id", "")} for a in agents]
    options_with_all = [{"label": "All Agents", "value": ""}] + options
    return options_with_all, options, options, options


# ==================== Main ====================

if __name__ == "__main__":
    # Get API key from environment or prompt
    if not API_KEY:
        API_KEY = os.getenv("SECRETSNIPE_API_KEY", "")
        if not API_KEY:
            print("Warning: No API_KEY set. Set SECRETSNIPE_API_KEY environment variable.")
    
    print("\n" + "=" * 60)
    print("  SecretSnipe Enterprise Agent Dashboard")
    print("=" * 60)
    print(f"  Manager URL: {MANAGER_URL}")
    print(f"  Dashboard:   http://0.0.0.0:8051")
    print("=" * 60 + "\n")
    
    app.run(
        host="0.0.0.0",
        port=8051,
        debug=os.getenv("DEBUG", "false").lower() == "true"
    )
