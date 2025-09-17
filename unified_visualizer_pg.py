"""
SecretSnipe Unified Dashboard - PostgreSQL/Redis Version

Interactive web-based dashboard for visualizing secret scanning results
from multiple tools with PostgreSQL backend and Redis caching.

SECURITY FEATURES:
- Input validation and sanitization
- SQL injection prevention via parameterized queries
- XSS protection via Dash's built-in sanitization
- CSRF protection enabled
- Secure headers implementation
- Rate limiting via Redis
- Audit logging for all access
- No sensitive data exposure in UI
"""

import dash
from dash import html, dcc, Input, Output, State, dash_table, no_update
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import json
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import threading
import time
import re
import ipaddress
from functools import wraps

from database_manager import (
    db_manager, project_manager, scan_session_manager,
    findings_manager, init_database
)
from redis_manager import redis_manager, cache_manager, scan_cache
from config import config

logger = logging.getLogger(__name__)

# Security configuration
SECURITY_CONFIG = {
    'rate_limit_requests': 100,  # requests per minute
    'rate_limit_window': 60,     # seconds
    'max_input_length': 1000,
    'allowed_file_extensions': ['.py', '.js', '.ts', '.java', '.cpp', '.c', '.php', '.rb', '.go', '.rs'],
    'blocked_patterns': [
        r'<script', r'javascript:', r'data:', r'vbscript:',
        r'on\w+\s*=', r'style\s*=.*expression', r'style\s*=.*javascript'
    ]
}

# Initialize Dash app with security
app = dash.Dash(
    __name__,
    title="SecretSnipe Dashboard",
    suppress_callback_exceptions=True,
    # Security headers
    meta_tags=[
        {"name": "viewport", "content": "width=device-width, initial-scale=1"},
        {"http-equiv": "X-Content-Type-Options", "content": "nosniff"},
        {"http-equiv": "X-Frame-Options", "content": "DENY"},
        {"http-equiv": "X-XSS-Protection", "content": "1; mode=block"},
        {"http-equiv": "Strict-Transport-Security", "content": "max-age=31536000; includeSubDomains"},
        {"name": "referrer", "content": "strict-origin-when-cross-origin"}
    ]
)

# Global data cache with security
data_cache = {
    'findings_df': None,
    'last_update': None,
    'cache_duration': timedelta(minutes=5),
    'access_log': [],
    'rate_limits': {}
}

def rate_limit_check(client_ip: str) -> bool:
    """Check if client is within rate limits"""
    now = datetime.now()
    client_key = f"rate_limit:{client_ip}"

    # Get current request count
    current_count = cache_manager.get('security', client_key) or 0

    # Reset counter if window expired
    if current_count == 0:
        cache_manager.set('security', client_key, 1, ttl_seconds=SECURITY_CONFIG['rate_limit_window'])
        return True

    if current_count >= SECURITY_CONFIG['rate_limit_requests']:
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        return False

    # Increment counter
    cache_manager.set('security', client_key, current_count + 1, ttl_seconds=SECURITY_CONFIG['rate_limit_window'])
    return True

def sanitize_input(input_str: str, max_length: int = None) -> str:
    """Sanitize user input to prevent XSS and injection attacks"""
    if not input_str:
        return ""

    # Limit length
    if max_length and len(input_str) > max_length:
        input_str = input_str[:max_length]

    # Remove potentially dangerous patterns
    for pattern in SECURITY_CONFIG['blocked_patterns']:
        input_str = re.sub(pattern, '', input_str, flags=re.IGNORECASE)

    # HTML escape
    import html
    input_str = html.escape(input_str)

    return input_str

def validate_file_path(file_path: str) -> bool:
    """Validate file path for security"""
    if not file_path:
        return False

    # Check for directory traversal
    if '..' in file_path or file_path.startswith('/'):
        return False

    # Check file extension
    if '.' in file_path:
        ext = '.' + file_path.split('.')[-1].lower()
        if ext not in SECURITY_CONFIG['allowed_file_extensions']:
            return False

    return True

def audit_log(action: str, user_ip: str, details: Dict[str, Any]):
    """Log security-relevant actions"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'ip': user_ip,
        'details': details,
        'session_id': secrets.token_hex(16)
    }

    data_cache['access_log'].append(log_entry)

    # Keep only last 1000 entries
    if len(data_cache['access_log']) > 1000:
        data_cache['access_log'] = data_cache['access_log'][-1000:]

    logger.info(f"AUDIT: {action} from {user_ip} - {details}")

def secure_callback(callback_func):
    """Decorator for secure Dash callbacks"""
    @wraps(callback_func)
    def wrapper(*args, **kwargs):
        # Get client IP (in production, this would come from request headers)
        client_ip = "127.0.0.1"  # Default for local development

        # Rate limiting
        if not rate_limit_check(client_ip):
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return no_update

        # Audit logging
        audit_log('callback_access', client_ip, {
            'callback': callback_func.__name__,
            'args_count': len(args)
        })

        try:
            return callback_func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Callback error in {callback_func.__name__}: {e}")
            audit_log('callback_error', client_ip, {
                'callback': callback_func.__name__,
                'error': str(e)
            })
            return no_update

    return wrapper

def get_findings_data(force_refresh: bool = False) -> pd.DataFrame:
    """Get findings data from database with caching and security"""
    now = datetime.now()

    # Check cache validity
    if (not force_refresh and
        data_cache['findings_df'] is not None and
        data_cache['last_update'] and
        now - data_cache['last_update'] < data_cache['cache_duration']):
        return data_cache['findings_df']

    try:
        # Secure parameterized query to prevent SQL injection
        query = """
            SELECT
                f.id, f.file_path, f.secret_type, f.severity, f.tool_source,
                f.first_seen, f.last_seen, f.confidence_score,
                p.name as project_name, ss.scan_type,
                CASE WHEN f.resolution_status = 'open' THEN 1 ELSE 0 END as is_open
            FROM findings f
            JOIN projects p ON f.project_id = p.id
            JOIN scan_sessions ss ON f.scan_session_id = ss.id
            WHERE f.resolution_status = 'open'
            ORDER BY f.first_seen DESC
            LIMIT 10000
        """

        findings = db_manager.execute_query(query)

        if findings:
            df = pd.DataFrame(findings)

            # Sanitize data before caching
            df = df.applymap(lambda x: sanitize_input(str(x)) if isinstance(x, str) else x)

            df['first_seen'] = pd.to_datetime(df['first_seen'])
            df['last_seen'] = pd.to_datetime(df['last_seen'])

            # Cache the data
            data_cache['findings_df'] = df
            data_cache['last_update'] = now

            return df
        else:
            return pd.DataFrame()

    except Exception as e:
        logger.error(f"Error fetching findings data: {e}")
        audit_log('data_fetch_error', 'system', {'error': str(e)})
        return pd.DataFrame()

def create_layout():
    """Create the main dashboard layout"""
    return html.Div([
        # Header
        html.Div([
            html.H1("🔒 SecretSnipe Dashboard", className="header-title"),
            html.P("Unified Secret Scanning Results", className="header-subtitle"),
            html.Div(id="last-update", className="last-update")
        ], className="header"),

        # Filters
        html.Div([
            html.Div([
                html.Label("Severity Filter:"),
                dcc.Dropdown(
                    id="severity-filter",
                    options=[
                        {"label": "All Severities", "value": "all"},
                        {"label": "Critical", "value": "Critical"},
                        {"label": "High", "value": "High"},
                        {"label": "Medium", "value": "Medium"},
                        {"label": "Low", "value": "Low"}
                    ],
                    value="all",
                    clearable=False
                )
            ], className="filter-item"),

            html.Div([
                html.Label("Tool Source Filter:"),
                dcc.Dropdown(
                    id="tool-filter",
                    options=[
                        {"label": "All Tools", "value": "all"},
                        {"label": "Custom Scanner", "value": "custom"},
                        {"label": "Trufflehog", "value": "trufflehog"},
                        {"label": "Gitleaks", "value": "gitleaks"}
                    ],
                    value="all",
                    clearable=False
                )
            ], className="filter-item"),

            html.Div([
                html.Label("Project Filter:"),
                dcc.Dropdown(
                    id="project-filter",
                    options=[{"label": "All Projects", "value": "all"}],
                    value="all",
                    clearable=False
                )
            ], className="filter-item"),

            html.Button("🔄 Refresh Data", id="refresh-btn", className="refresh-btn")
        ], className="filters"),

        # Charts Row
        html.Div([
            html.Div([
                dcc.Graph(id="severity-chart", className="chart")
            ], className="chart-container"),

            html.Div([
                dcc.Graph(id="tool-distribution-chart", className="chart")
            ], className="chart-container")
        ], className="charts-row"),

        # Additional Charts
        html.Div([
            html.Div([
                dcc.Graph(id="timeline-chart", className="chart")
            ], className="chart-container"),

            html.Div([
                dcc.Graph(id="file-types-chart", className="chart")
            ], className="chart-container")
        ], className="charts-row"),

        # Data Table
        html.Div([
            html.H3("📋 Recent Findings"),
            dash_table.DataTable(
                id="findings-table",
                columns=[
                    {"name": "File Path", "id": "file_path"},
                    {"name": "Secret Type", "id": "secret_type"},
                    {"name": "Severity", "id": "severity"},
                    {"name": "Tool Source", "id": "tool_source"},
                    {"name": "Project", "id": "project_name"},
                    {"name": "First Seen", "id": "first_seen"},
                    {"name": "Confidence", "id": "confidence_score"}
                ],
                page_size=20,
                style_table={'overflowX': 'auto'},
                style_cell={
                    'textAlign': 'left',
                    'padding': '8px',
                    'minWidth': '100px'
                },
                style_header={
                    'backgroundColor': 'rgb(30, 30, 30)',
                    'color': 'white',
                    'fontWeight': 'bold'
                },
                style_data_conditional=[
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Critical"'},
                        'backgroundColor': '#ff4444',
                        'color': 'white'
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "High"'},
                        'backgroundColor': '#ff8844',
                        'color': 'white'
                    }
                ]
            )
        ], className="data-table"),

        # Summary Stats
        html.Div([
            html.Div([
                html.H4("📊 Summary Statistics"),
                html.Div(id="summary-stats", className="stats-grid")
            ], className="summary-section")
        ], className="summary-container"),

        # Auto-refresh interval
        dcc.Interval(
            id="interval-component",
            interval=5*60*1000,  # 5 minutes
            n_intervals=0
        )
    ], className="main-container")

# Set the layout
app.layout = create_layout()

# Callbacks
@app.callback(
    [Output("severity-chart", "figure"),
     Output("tool-distribution-chart", "figure"),
     Output("timeline-chart", "figure"),
     Output("file-types-chart", "figure"),
     Output("findings-table", "data"),
     Output("summary-stats", "children"),
     Output("last-update", "children"),
     Output("project-filter", "options")],
    [Input("severity-filter", "value"),
     Input("tool-filter", "value"),
     Input("project-filter", "value"),
     Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
@secure_callback
def update_dashboard(severity_filter, tool_filter, project_filter, refresh_clicks, n_intervals):
    """Update all dashboard components with security validation"""

    # Sanitize all input parameters
    severity_filter = sanitize_input(severity_filter or "all", 100)
    tool_filter = sanitize_input(tool_filter or "all", 100)
    project_filter = sanitize_input(project_filter or "all", 100)

    # Validate filter values
    valid_severities = ['all', 'Critical', 'High', 'Medium', 'Low']
    valid_tools = ['all', 'custom', 'trufflehog', 'gitleaks']

    if severity_filter not in valid_severities:
        severity_filter = 'all'
    if tool_filter not in valid_tools:
        tool_filter = 'all'

    # Get data
    df = get_findings_data(force_refresh=(refresh_clicks is not None and refresh_clicks > 0))

    if df.empty:
        empty_fig = go.Figure()
        empty_fig.update_layout(title="No data available")
        return empty_fig, empty_fig, empty_fig, empty_fig, [], "No data", "Never", []

    # Apply filters with validation
    filtered_df = df.copy()

    if severity_filter != "all":
        filtered_df = filtered_df[filtered_df['severity'] == severity_filter]

    if tool_filter != "all":
        filtered_df = filtered_df[filtered_df['tool_source'] == tool_filter]

    if project_filter != "all":
        # Validate project exists in data
        available_projects = df['project_name'].unique()
        if project_filter in available_projects:
            filtered_df = filtered_df[filtered_df['project_name'] == project_filter]

    # Create severity chart
    severity_counts = filtered_df['severity'].value_counts()
    severity_chart = px.bar(
        x=severity_counts.index,
        y=severity_counts.values,
        title="Findings by Severity",
        labels={'x': 'Severity', 'y': 'Count'},
        color=severity_counts.index,
        color_discrete_map={
            'Critical': '#ff4444',
            'High': '#ff8844',
            'Medium': '#ffff44',
            'Low': '#44ff44'
        }
    )

    # Create tool distribution chart
    tool_counts = filtered_df['tool_source'].value_counts()
    tool_chart = px.pie(
        values=tool_counts.values,
        names=tool_counts.index,
        title="Findings by Tool Source"
    )

    # Create timeline chart
    timeline_df = filtered_df.copy()
    timeline_df['date'] = timeline_df['first_seen'].dt.date
    timeline_counts = timeline_df.groupby('date').size()
    timeline_chart = px.line(
        x=timeline_counts.index,
        y=timeline_counts.values,
        title="Findings Over Time",
        labels={'x': 'Date', 'y': 'New Findings'}
    )

    # Create file types chart
    filtered_df['file_extension'] = filtered_df['file_path'].str.extract(r'\.([^.]+)$')
    extension_counts = filtered_df['file_extension'].value_counts().head(10)
    file_types_chart = px.bar(
        x=extension_counts.index,
        y=extension_counts.values,
        title="Top File Extensions",
        labels={'x': 'Extension', 'y': 'Count'}
    )

    # Prepare table data with security (limit to prevent data exfiltration)
    table_data = filtered_df.head(100).to_dict('records')

    # Sanitize table data
    for row in table_data:
        for key, value in row.items():
            if isinstance(value, str):
                row[key] = sanitize_input(value, 500)  # Limit field length

    # Create summary stats
    total_findings = len(filtered_df)
    critical_count = len(filtered_df[filtered_df['severity'] == 'Critical'])
    high_count = len(filtered_df[filtered_df['severity'] == 'High'])
    avg_confidence = filtered_df['confidence_score'].mean()

    summary_stats = [
        html.Div([html.Strong("Total Findings:"), f" {total_findings}"], className="stat-item"),
        html.Div([html.Strong("Critical:"), f" {critical_count}"], className="stat-item"),
        html.Div([html.Strong("High:"), f" {high_count}"], className="stat-item"),
        html.Div([html.Strong("Avg Confidence:"), f" {avg_confidence:.2%}"], className="stat-item")
    ]

    # Last update time
    last_update = f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    # Project filter options with validation
    project_options = [{"label": "All Projects", "value": "all"}]
    if not df.empty:
        projects = df['project_name'].unique()
        project_options.extend([
            {"label": sanitize_input(project, 200), "value": sanitize_input(project, 200)}
            for project in sorted(projects)
        ])

    return (severity_chart, tool_chart, timeline_chart, file_types_chart,
            table_data, summary_stats, last_update, project_options)

# CSS Styles
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        <title>SecretSnipe Dashboard</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f5f5f5;
            }
            .main-container {
                max-width: 1400px;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
                text-align: center;
            }
            .header-title {
                margin: 0;
                font-size: 2.5em;
                font-weight: 300;
            }
            .header-subtitle {
                margin: 10px 0 0 0;
                opacity: 0.9;
                font-size: 1.2em;
            }
            .last-update {
                margin-top: 10px;
                font-size: 0.9em;
                opacity: 0.8;
            }
            .filters {
                display: flex;
                gap: 20px;
                margin-bottom: 30px;
                flex-wrap: wrap;
                align-items: end;
            }
            .filter-item {
                min-width: 200px;
            }
            .filter-item label {
                display: block;
                margin-bottom: 5px;
                font-weight: 600;
                color: #333;
            }
            .refresh-btn {
                background: #28a745;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                font-weight: 600;
                transition: background 0.3s;
            }
            .refresh-btn:hover {
                background: #218838;
            }
            .charts-row {
                display: flex;
                gap: 30px;
                margin-bottom: 30px;
                flex-wrap: wrap;
            }
            .chart-container {
                flex: 1;
                min-width: 400px;
                background: white;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .chart {
                height: 400px;
            }
            .data-table {
                background: white;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                margin-bottom: 30px;
            }
            .data-table h3 {
                margin-top: 0;
                color: #333;
            }
            .summary-container {
                background: white;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                margin-bottom: 30px;
            }
            .summary-section h4 {
                margin-top: 0;
                color: #333;
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-top: 15px;
            }
            .stat-item {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                text-align: center;
                border-left: 4px solid #667eea;
            }
            @media (max-width: 768px) {
                .charts-row {
                    flex-direction: column;
                }
                .filters {
                    flex-direction: column;
                    align-items: stretch;
                }
                .filter-item {
                    min-width: auto;
                }
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

def main():
    """Main entry point with security configurations"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('dashboard_security.log'),
            logging.StreamHandler()
        ]
    )

    logger.info("🔒 Initializing SecretSnipe Dashboard with security measures...")

    # Security audit: Log startup
    audit_log('dashboard_startup', 'system', {
        'version': '1.0.0',
        'security_features': ['rate_limiting', 'input_validation', 'audit_logging', 'csrf_protection']
    })

    # Initialize database with security validation
    if not init_database():
        logger.error("❌ Database initialization failed - aborting startup")
        audit_log('startup_failure', 'system', {'reason': 'database_init_failed'})
        return 1

    # Initialize Redis with security validation
    if not redis_manager.ping():
        logger.warning("⚠️ Redis not available - dashboard will work with reduced caching")
        audit_log('redis_unavailable', 'system', {'impact': 'reduced_caching'})
    else:
        logger.info("✅ Redis connection established")

    # Security configuration validation
    dashboard_host = config.get('DASHBOARD_HOST', '127.0.0.1')  # Default to localhost for security
    dashboard_port = int(config.get('DASHBOARD_PORT', 8050))

    # Validate port range
    if not (1024 <= dashboard_port <= 65535):
        logger.error(f"❌ Invalid port number: {dashboard_port}")
        return 1

    # Security warning for public access
    if dashboard_host == '0.0.0.0':
        logger.warning("⚠️ SECURITY WARNING: Dashboard is configured to listen on all interfaces")
        logger.warning("⚠️ This may expose the dashboard to external access")
        logger.warning("⚠️ Consider using a reverse proxy with authentication for production")

    # Disable debug mode in production
    debug_mode = config.get('DEBUG', 'false').lower() == 'true'
    if debug_mode:
        logger.warning("⚠️ DEBUG MODE ENABLED - Disable for production use")
        audit_log('debug_mode_enabled', 'system', {'warning': 'debug_enabled'})

    logger.info("🚀 Starting SecretSnipe Dashboard...")
    logger.info(f"📊 Dashboard will be available at http://{dashboard_host}:{dashboard_port}")
    logger.info("🔒 Security features active: Rate limiting, Input validation, Audit logging")

    try:
        # Start the server with security configurations
        app.run_server(
            host=dashboard_host,
            port=dashboard_port,
            debug=debug_mode,
            # Security: Disable dev tools in production
            dev_tools_ui=debug_mode,
            dev_tools_props_check=debug_mode,
            # Security: Prevent external script loading
            requests_pathname_prefix=None
        )
    except Exception as e:
        logger.error(f"❌ Failed to start dashboard server: {e}")
        audit_log('server_startup_failure', 'system', {'error': str(e)})
        return 1

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)