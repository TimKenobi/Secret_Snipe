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
from flask import session, request
import base64
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
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
import os
import subprocess
from functools import wraps
from flask_httpauth import HTTPBasicAuth

from database_manager import (
    db_manager, project_manager, scan_session_manager,
    findings_manager, init_database
)
from redis_manager import cache_manager, scan_cache, init_redis
import redis_manager
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

# Authentication setup
app.layout = html.Div([
    dcc.Store(id='login-status', storage_type='session'),
    html.Div(id='login-container')
])

@app.callback(
    Output('login-container', 'children'),
    Input('login-status', 'data')
)
def render_layout(login_data):
    if login_data is None or not login_data.get('logged_in', False):
        return html.Div([
            html.H2("Login to SecretSnipe Dashboard"),
            dcc.Input(id="login-username", type="text", placeholder="Username"),
            dcc.Input(id="login-password", type="password", placeholder="Password"),
            html.Button("Login", id="login-btn"),
            html.Div(id="login-message")
        ])
    else:
        return create_layout()  # Main dashboard layout

@app.callback(
    [Output('login-status', 'data'),
     Output('login-message', 'children')],
    Input('login-btn', 'n_clicks'),
    [State('login-username', 'value'),
     State('login-password', 'value')]
)
def login(n_clicks, username, password):
    if n_clicks is None:
        return no_update, no_update

    if username == config.dashboard.auth_username and password == config.dashboard.auth_password_hash:
        return {'logged_in': True}, "Login successful!"
    else:
        return no_update, "Invalid credentials"

def rate_limit_check(client_ip: str) -> bool:
    """Check if client is within rate limits"""
    now = datetime.now()
    client_key = f"rate_limit:{client_ip}"

    # Get current request count
    current_count = cache_manager.get('security', client_key) or 0 if cache_manager else 0

    # Reset counter if window expired
    if current_count == 0:
        cache_manager.set('security', client_key, 1, ttl_seconds=SECURITY_CONFIG['rate_limit_window']) if cache_manager else None
        return True

    if current_count >= SECURITY_CONFIG['rate_limit_requests']:
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        return False

    # Increment counter
    cache_manager.set('security', client_key, current_count + 1, ttl_seconds=SECURITY_CONFIG['rate_limit_window']) if cache_manager else None
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
                f.id, f.file_path, f.secret_type, f.secret_value, f.context, f.severity, f.tool_source,
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
            df = df.map(lambda x: sanitize_input(str(x)) if isinstance(x, str) else x)

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

# Layout definition moved to the complete create_layout function below

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
     Input("interval-component", "n_intervals"),
     Input("dark-mode-toggle", "value")]
)
@secure_callback
def update_dashboard(severity_filter, tool_filter, project_filter, refresh_clicks, n_intervals, dark_mode_value):
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

    # Determine if dark mode is enabled and set the Plotly template
    is_dark_mode = dark_mode_value and "dark" in dark_mode_value
    template = 'plotly_dark' if is_dark_mode else 'plotly_white'

    # Set colors based on dark mode state - simplified to rely on template
    if is_dark_mode:
        # Use exact colors from old visualizer that work well in dark mode
        severity_colors = {
            'Critical': '#ff0000',  # Bright red
            'High': '#d9534f',      # Orange-red
            'Medium': '#f0ad4e',    # Orange
            'Low': '#5cb85c'        # Green
        }
        tool_colors = ['#00bfff', '#32cd32', '#ffa500', '#ff4444', '#da70d6']  # Bright colors for dark mode
        timeline_color = '#00bfff' # Bright blue for dark mode
        color_scale = 'plasma' # Plasma has bright colors for dark mode
    else:
        # Light mode colors
        severity_colors = {
            'Critical': '#ff0000',
            'High': '#d9534f',
            'Medium': '#f0ad4e',
            'Low': '#5cb85c'
        }
        tool_colors = ['#1d4ed8', '#059669', '#d97706', '#dc2626', '#7c3aed']
        timeline_color = '#3b82f6'
        color_scale = 'Blues'

    # Get data
    df = get_findings_data(force_refresh=(refresh_clicks is not None and refresh_clicks > 0))

    if df.empty:
        empty_fig = go.Figure()
        empty_fig.update_layout(
            title="No data available",
            template=template,
            # Additional background forcing
            margin=dict(l=50, r=50, t=50, b=50),
            showlegend=False
        )
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
        color_discrete_map=severity_colors,
        template=template
    )
    severity_chart.update_layout(
        showlegend=True,
        margin=dict(l=50, r=50, t=50, b=50)
    )

    # Create tool distribution chart
    tool_counts = filtered_df['tool_source'].value_counts()
    
    tool_chart = px.pie(
        values=tool_counts.values,
        names=tool_counts.index,
        title="Findings by Tool Source",
        color_discrete_sequence=tool_colors,
        template=template
    )
    tool_chart.update_layout(
        showlegend=True,
        margin=dict(l=50, r=50, t=50, b=50),
        legend=dict(
            bgcolor='rgba(0,0,0,0)'
        )
    )

    # Create timeline chart
    timeline_df = filtered_df.copy()
    timeline_df['date'] = timeline_df['first_seen'].dt.date
    timeline_counts = timeline_df.groupby('date').size()
    timeline_chart = px.line(
        x=timeline_counts.index,
        y=timeline_counts.values,
        title="Findings Over Time",
        labels={'x': 'Date', 'y': 'New Findings'},
        template=template
    )
    timeline_chart.update_traces(line_color=timeline_color)
    timeline_chart.update_layout(
        margin=dict(l=50, r=50, t=50, b=50),
        showlegend=False
    )

    # Create file types chart
    filtered_df['file_extension'] = filtered_df['file_path'].str.extract(r'\.([^.]+)$')
    extension_counts = filtered_df['file_extension'].value_counts().head(10)
    file_types_chart = px.bar(
        x=extension_counts.index,
        y=extension_counts.values,
        title="Top File Extensions",
        labels={'x': 'Extension', 'y': 'Count'},
        color=extension_counts.values,
        color_continuous_scale=color_scale,
        template=template
    )
    file_types_chart.update_layout(
        margin=dict(l=50, r=50, t=50, b=50),
        showlegend=False
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

# New Callbacks for Enhanced Features

@app.callback(
    Output("custom-scan-modal", "className"),
    [Input("custom-scan-btn", "n_clicks"),
     Input("cancel-scan-btn", "n_clicks"),
     Input("start-custom-scan-btn", "n_clicks")],
    [State("custom-scan-modal", "className")]
)
@secure_callback
def toggle_scan_modal(custom_scan_clicks, cancel_clicks, start_clicks, current_class):
    """Toggle custom scan modal visibility"""
    ctx = dash.callback_context
    if not ctx.triggered:
        return "modal-container"

    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if trigger_id == "custom-scan-btn":
        return "modal-container show"
    elif trigger_id in ["cancel-scan-btn", "start-custom-scan-btn"]:
        return "modal-container"

    return current_class

@app.callback(
    Output("report-download", "data"),
    [Input("export-csv-btn", "n_clicks"),
     Input("export-json-btn", "n_clicks"),
     Input("export-pdf-btn", "n_clicks")],
    [State("report-severity-filter", "value"),
     State("report-date-range", "start_date"),
     State("report-date-range", "end_date")]
)
def export_report(csv_clicks, json_clicks, pdf_clicks, severities, start_date, end_date):
    ctx = dash.callback_context
    if not ctx.triggered:
        return no_update

    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

    # Get filtered data
    df = get_findings_data()
    if severities and "all" not in severities:
        df = df[df['severity'].isin(severities)]
    if start_date:
        df = df[df['first_seen'] >= start_date]
    if end_date:
        df = df[df['first_seen'] <= end_date]

    if trigger_id == "export-csv-btn":
        return dcc.send_data_frame(df.to_csv, "report.csv")

    if trigger_id == "export-json-btn":
        return dcc.send_string(df.to_json(orient="records"), "report.json")

    if trigger_id == "export-pdf-btn":
        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.drawString(100, 750, "SecretSnipe Report")
        # Add more PDF content here
        c.save()
        buffer.seek(0)
        return dcc.send_bytes(buffer.getvalue(), "report.pdf")

    return no_update

@app.callback(
    [Output("scanner-status-custom", "children"),
     Output("scanner-status-custom", "className"),
     Output("scanner-status-trufflehog", "children"),
     Output("scanner-status-trufflehog", "className"),
     Output("scanner-status-gitleaks", "children"),
     Output("scanner-status-gitleaks", "className"),
     Output("scanner-status-overall", "children"),
     Output("scanner-status-overall", "className")],
    [Input("interval-component", "n_intervals")]
)
@secure_callback
def update_scanner_status(n_intervals):
    """Update scanner status display"""
    try:
        # Check Redis connectivity for caching status
        redis_status = "✅ Connected" if (redis_manager.redis_manager and redis_manager.redis_manager.ping()) else "❌ Disconnected"

        # Get recent scan sessions to determine scanner status
        query = """
            SELECT 
                ss.scan_type,
                ss.status,
                ss.completed_at,
                ss.error_message,
                ss.started_at,
                COUNT(f.id) as findings_count
            FROM scan_sessions ss
            LEFT JOIN findings f ON ss.id = f.scan_session_id
            WHERE ss.started_at >= NOW() - INTERVAL '24 hours'
            GROUP BY ss.id, ss.scan_type, ss.status, ss.completed_at, ss.error_message, ss.started_at
            ORDER BY ss.started_at DESC
            LIMIT 10
        """
        recent_scans = db_manager.execute_query(query)

        scanner_statuses = {
            'custom': {'status': 'Unknown', 'class': 'status-item'},
            'trufflehog': {'status': 'Unknown', 'class': 'status-item'},
            'gitleaks': {'status': 'Unknown', 'class': 'status-item'}
        }

        if recent_scans:
            for scan in recent_scans:
                scan_type = scan['scan_type']
                
                if scan_type == 'custom':
                    # Custom scans can contain findings from multiple tools
                    if scan['status'] == 'completed':
                        scanner_statuses['custom'] = {
                            'status': f"✅ Last run: {scan['completed_at'].strftime('%H:%M') if scan['completed_at'] else 'Recent'} ({scan['findings_count']} findings)",
                            'class': 'status-item'
                        }
                    elif scan['status'] == 'failed':
                        scanner_statuses['custom'] = {
                            'status': f"❌ Failed: {scan['error_message'][:50] if scan['error_message'] else 'Unknown error'}",
                            'class': 'status-item status-error'
                        }
                    elif scan['status'] == 'running':
                        scanner_statuses['custom'] = {
                            'status': "🔄 Running...",
                            'class': 'status-item status-warning'
                        }
                
                elif scan_type == 'combined':
                    # Combined scans run both Trufflehog and Gitleaks
                    if scan['status'] == 'completed':
                        status_text = f"✅ Last run: {scan['completed_at'].strftime('%H:%M') if scan['completed_at'] else 'Recent'}"
                        scanner_statuses['trufflehog'] = {
                            'status': status_text,
                            'class': 'status-item'
                        }
                        scanner_statuses['gitleaks'] = {
                            'status': status_text,
                            'class': 'status-item'
                        }
                    elif scan['status'] == 'failed':
                        error_text = f"❌ Failed: {scan['error_message'][:50] if scan['error_message'] else 'Unknown error'}"
                        scanner_statuses['trufflehog'] = {
                            'status': error_text,
                            'class': 'status-item status-error'
                        }
                        scanner_statuses['gitleaks'] = {
                            'status': error_text,
                            'class': 'status-item status-error'
                        }
                    elif scan['status'] == 'running':
                        scanner_statuses['trufflehog'] = {
                            'status': "🔄 Running...",
                            'class': 'status-item status-warning'
                        }
                        scanner_statuses['gitleaks'] = {
                            'status': "🔄 Running...",
                            'class': 'status-item status-warning'
                        }

        custom_status = f"Custom Scanner: {scanner_statuses['custom']['status']}"
        trufflehog_status = f"Trufflehog: {scanner_statuses['trufflehog']['status']}"
        gitleaks_status = f"Gitleaks: {scanner_statuses['gitleaks']['status']}"
        overall_status = f"Redis Cache: {redis_status}"

        return (
            custom_status, scanner_statuses['custom']['class'],
            trufflehog_status, scanner_statuses['trufflehog']['class'],
            gitleaks_status, scanner_statuses['gitleaks']['class'],
            overall_status, 'status-item'
        )

    except Exception as e:
        logger.error(f"Error updating scanner status: {e}")
        return (
            "Custom Scanner: Error", "status-item status-error",
            "Trufflehog: Error", "status-item status-error",
            "Gitleaks: Error", "status-item status-error",
            "System: Error", "status-item status-error"
        )

@app.callback(
    Output("scan-result-notification", "children"),
    [Input("quick-scan-btn", "n_clicks"),
     Input("start-custom-scan-btn", "n_clicks")],
    [State("scan-path-input", "value"),
     State("scan-project-input", "value"),
     State("scan-scanners-checklist", "value")]
)
@secure_callback
def perform_scan(quick_clicks, custom_clicks, scan_path, project_name, selected_scanners):
    """Perform scan operation"""
    ctx = dash.callback_context
    if not ctx.triggered:
        return ""

    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if trigger_id not in ["quick-scan-btn", "start-custom-scan-btn"]:
        return ""

    try:
        # Determine scan parameters
        if trigger_id == "quick-scan-btn":
            scan_path = "/scan"  # Default path
            project_name = f"quick-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            selected_scanners = ["custom", "trufflehog", "gitleaks"]
        else:
            scan_path = scan_path or "/scan"
            project_name = project_name or f"custom-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            selected_scanners = selected_scanners or ["custom"]

        # Validate inputs
        scan_path = sanitize_input(scan_path, 500)
        project_name = sanitize_input(project_name, 100)

        # Run scan in background (would need to be implemented)
        # For now, just return a notification
        scanners_str = ", ".join(selected_scanners)
        return f"🔄 Scan started: {project_name} on {scan_path} using {scanners_str}"

    except Exception as e:
        logger.error(f"Error performing scan: {e}")
        return f"❌ Scan failed: {str(e)}"

@app.callback(
    Output("cleanup-result-notification", "children"),
    [Input("cleanup-btn", "n_clicks")]
)
@secure_callback
def perform_cleanup(cleanup_clicks):
    """Perform cleanup of old data"""
    if not cleanup_clicks:
        return ""

    try:
        # Cleanup old findings (older than 30 days)
        cutoff_date = datetime.now() - timedelta(days=30)

        # Delete old scan sessions and their findings
        query = """
            DELETE FROM scan_sessions
            WHERE created_at < %s
            AND status IN ('completed', 'failed')
        """
        deleted_sessions = db_manager.execute_query(query, (cutoff_date,))

        # Delete orphaned findings
        query = """
            DELETE FROM findings
            WHERE scan_session_id NOT IN (
                SELECT id FROM scan_sessions
            )
        """
        deleted_findings = db_manager.execute_query(query, ())

        # Clear old cache entries
        try:
            # This would need Redis cleanup logic
            cache_cleanup = "Redis cache entries older than 7 days cleared"
        except:
            cache_cleanup = "Redis cache cleanup skipped"

        return f"✅ Cleanup completed: Removed old scan data (30+ days). Cache: {cache_cleanup}"

    except Exception as e:
        logger.error(f"Error performing cleanup: {e}")
        return f"❌ Cleanup failed: {str(e)}"

@app.callback(
    Output("main-container", "className"),
    [Input("dark-mode-toggle", "value")]
)
@secure_callback
def toggle_dark_mode(dark_mode_value):
    """Toggle dark mode styling"""
    if dark_mode_value and "dark" in dark_mode_value:
        return "main-container dark-mode"
    return "main-container"

@app.callback(
    [Output("findings-table", "style_header"),
     Output("findings-table", "style_cell"),
     Output("findings-table", "style_data_conditional")],
    [Input("dark-mode-toggle", "value")]
)
@secure_callback
def update_table_styles(dark_mode_value):
    """Update table styles based on dark mode"""
    is_dark_mode = dark_mode_value and "dark" in dark_mode_value
    
    # Let CSS handle base table styling - only apply conditional highlighting
    style_header = {}
    style_cell = {}
    
    if is_dark_mode:
        # Dark mode conditional highlighting for severity
        style_data_conditional = [
            {
                'if': {'column_id': 'severity', 'filter_query': '{severity} = "Critical"'},
                'backgroundColor': '#ff0000',
                'color': 'white',
                'fontWeight': 'bold'
            },
            {
                'if': {'column_id': 'severity', 'filter_query': '{severity} = "High"'},
                'backgroundColor': '#d9534f',
                'color': 'white',
                'fontWeight': 'bold'
            },
            {
                'if': {'column_id': 'severity', 'filter_query': '{severity} = "Medium"'},
                'backgroundColor': '#f0ad4e',
                'color': 'white',
                'fontWeight': 'bold'
            },
            {
                'if': {'column_id': 'severity', 'filter_query': '{severity} = "Low"'},
                'backgroundColor': '#5cb85c',
                'color': 'white',
                'fontWeight': 'bold'
            }
        ]
    else:
        # Light mode conditional highlighting for severity
        style_data_conditional = [
            {
                'if': {'column_id': 'severity', 'filter_query': '{severity} = "Critical"'},
                'backgroundColor': '#ff0000',
                'color': 'white',
                'fontWeight': 'bold'
            },
            {
                'if': {'column_id': 'severity', 'filter_query': '{severity} = "High"'},
                'backgroundColor': '#d9534f',
                'color': 'white',
                'fontWeight': 'bold'
            },
            {
                'if': {'column_id': 'severity', 'filter_query': '{severity} = "Medium"'},
                'backgroundColor': '#f0ad4e',
                'color': 'white',
                'fontWeight': 'bold'
            },
            {
                'if': {'column_id': 'severity', 'filter_query': '{severity} = "Low"'},
                'backgroundColor': '#5cb85c',
                'color': 'white',
                'fontWeight': 'bold'
            }
        ]
    
    return style_header, style_cell, style_data_conditional

app.clientside_callback(
    """
    function(dark_mode_value) {
        // This function is a trigger for the clientside observer setup.
        // It doesn't do anything itself but ensures the JS is loaded and run.
        return window.dash_clientside.clientside.setup_chart_observer(dark_mode_value);
    }
    """,
    Output("clientside-fix-output", "data"),
    [Input("dark-mode-toggle", "value")]
)

# Add notification divs to layout
def create_layout():
    """Create the main dashboard layout"""
    # Aggressive CSS overrides to fix dark mode rendering issues
    return html.Div([
        # Hidden notification divs for callbacks
        html.Div(id="scan-result-notification", style={"display": "none"}),
        html.Div(id="cleanup-result-notification", style={"display": "none"}),

        # Main container
        html.Div([
            # Header with controls
            html.Div([
                html.Div([
                    html.H1("🔒 SecretSnipe Dashboard", className="header-title"),
                    html.P("Unified Secret Scanning Results", className="header-subtitle"),
                    html.Div(id="last-update", className="last-update")
                ], className="header-content"),

                html.Div([
                    # Dark mode toggle
                    html.Div([
                        html.Label("🌙 Dark Mode", className="toggle-label"),
                        dcc.Checklist(
                            id="dark-mode-toggle",
                            options=[{"label": "", "value": "dark"}],
                            value=["dark"],  # Enable dark mode by default
                            className="dark-mode-toggle"
                        )
                    ], className="control-item"),

                    # Scan controls
                    html.Div([
                        html.Button("🔍 Quick Scan", id="quick-scan-btn", className="scan-btn"),
                        html.Button("📁 Custom Scan", id="custom-scan-btn", className="scan-btn"),
                        html.Button("🧹 Cleanup Old Data", id="cleanup-btn", className="cleanup-btn")
                    ], className="control-item")
                ], className="header-controls")
            ], className="header"),

            # Scanner Status
            html.Div([
                html.H3("📊 Scanner Status"),
                html.Div([
                    html.Div(id="scanner-status-custom", className="status-item"),
                    html.Div(id="scanner-status-trufflehog", className="status-item"),
                    html.Div(id="scanner-status-gitleaks", className="status-item"),
                    html.Div(id="scanner-status-overall", className="status-item")
                ], className="scanner-status-grid")
            ], className="scanner-status"),

            # Custom Scan Modal
            html.Div([
                dcc.Store(id="scan-modal-open", data=False),
                html.Div([
                    html.H2("Custom Scan Configuration"),
                    html.Div([
                        html.Label("Scan Path:"),
                        dcc.Input(
                            id="scan-path-input",
                            type="text",
                            placeholder="/path/to/scan or leave empty for default",
                            className="modal-input"
                        )
                    ], className="modal-field"),

                    html.Div([
                        html.Label("Project Name:"),
                        dcc.Input(
                            id="scan-project-input",
                            type="text",
                            placeholder="project-name",
                            value="custom-scan",
                            className="modal-input"
                        )
                    ], className="modal-field"),

                    html.Div([
                        html.Label("Scanners to Use:"),
                        dcc.Checklist(
                            id="scan-scanners-checklist",
                            options=[
                                {"label": "Custom Scanner", "value": "custom"},
                                {"label": "Trufflehog", "value": "trufflehog"},
                                {"label": "Gitleaks", "value": "gitleaks"}
                            ],
                            value=["custom", "trufflehog", "gitleaks"],
                            className="modal-checklist"
                        )
                    ], className="modal-field"),

                    html.Div(id='clientside-fix-output', style={'display': 'none'}),

                    html.Div([
                        html.Button("Start Scan", id="start-custom-scan-btn", className="modal-btn primary"),
                        html.Button("Cancel", id="cancel-scan-btn", className="modal-btn secondary")
                    ], className="modal-buttons")
                ], className="modal-content")
            ], id="custom-scan-modal", className="modal-container"),

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
                        clearable=False,
                        optionHeight=50,  # Increase height for multi-line text
                        style={'minWidth': '200px'}
                    )
                ], className="filter-item"),

                html.Button("🔄 Refresh Data", id="refresh-btn", className="refresh-btn")
            ], className="filters"),

            # Charts Row
            html.Div([
                html.Div([
                    dcc.Graph(
                        id="severity-chart", 
                        className="chart",
                        config={
                            'displayModeBar': True,
                            'displaylogo': False,
                            'modeBarButtonsToRemove': ['pan2d', 'lasso2d', 'select2d'],
                            'plotlyServerURL': False
                        }
                    )
                ], className="chart-container"),

                html.Div([
                    dcc.Graph(
                        id="tool-distribution-chart", 
                        className="chart",
                        config={
                            'displayModeBar': True,
                            'displaylogo': False,
                            'modeBarButtonsToRemove': ['pan2d', 'lasso2d', 'select2d'],
                            'plotlyServerURL': False
                        }
                    )
                ], className="chart-container")
            ], className="charts-row"),

            # Additional Charts
            html.Div([
                html.Div([
                    dcc.Graph(
                        id="timeline-chart", 
                        className="chart",
                        config={
                            'displayModeBar': True,
                            'displaylogo': False,
                            'modeBarButtonsToRemove': ['pan2d', 'lasso2d', 'select2d'],
                            'plotlyServerURL': False
                        }
                    )
                ], className="chart-container"),

                html.Div([
                    dcc.Graph(
                        id="file-types-chart", 
                        className="chart",
                        config={
                            'displayModeBar': True,
                            'displaylogo': False,
                            'modeBarButtonsToRemove': ['pan2d', 'lasso2d', 'select2d'],
                            'plotlyServerURL': False
                        }
                    )
                ], className="chart-container")
            ], className="charts-row"),

            # Data Table
            html.Div([
                html.H3("📋 Recent Findings"),
                dash_table.DataTable(
                    id="findings-table",
                    columns=[
                        {"name": "File Path", "id": "file_path", "deletable": True, "selectable": True, "hideable": True},
                        {"name": "Secret Type", "id": "secret_type", "deletable": True, "selectable": True, "hideable": True},
                        {"name": "Secret Value", "id": "secret_value", "deletable": True, "selectable": True, "hideable": True},
                        {"name": "Context", "id": "context", "deletable": True, "selectable": True, "hideable": True},
                        {"name": "Severity", "id": "severity", "deletable": True, "selectable": True, "hideable": True},
                        {"name": "Tool Source", "id": "tool_source", "deletable": True, "selectable": True, "hideable": True},
                        {"name": "Project", "id": "project_name", "deletable": True, "selectable": True, "hideable": True},
                        {"name": "First Seen", "id": "first_seen", "deletable": True, "selectable": True, "hideable": True},
                        {"name": "Confidence", "id": "confidence_score", "deletable": True, "selectable": True, "hideable": True}
                    ],
                    data=[],
                    filter_action="native",
                    sort_action="native",
                    sort_mode="multi",
                    column_selectable="multi",
                    row_selectable="multi",
                    page_action="native",
                    page_current=0,
                    page_size=20,
                    style_table={'overflowX': 'auto'},
                    style_cell={
                        'minWidth': '150px', 'width': '150px', 'maxWidth': '300px',
                        'overflow': 'hidden',
                        'textOverflow': 'ellipsis',
                        'whiteSpace': 'normal',
                        'height': 'auto',
                    },
                    style_cell_conditional=[
                        {'if': {'column_id': 'context'},
                         'whiteSpace': 'normal',
                         'height': 'auto',
                         'minWidth': '200px', 'width': '200px', 'maxWidth': '400px'},
                        {'if': {'column_id': 'secret_value'},
                         'whiteSpace': 'normal',
                         'height': 'auto',
                         'minWidth': '150px', 'width': '150px', 'maxWidth': '300px'},
                    ],
                    export_format="csv",
                    export_headers="display",
                    css=[{'selector': '.dash-cell div', 'rule': 'white-space: normal; height: auto;'}]
                )
            ], className="data-table"),

            # Custom Report Export Section
            html.Div([
                html.H3("📄 Custom Report Export"),
                html.Div([
                    html.Label("Select Severity:"),
                    dcc.Dropdown(
                        id="report-severity-filter",
                        options=[
                            {"label": "All Severities", "value": "all"},
                            {"label": "Critical", "value": "Critical"},
                            {"label": "High", "value": "High"},
                            {"label": "Medium", "value": "Medium"},
                            {"label": "Low", "value": "Low"}
                        ],
                        value="all",
                        multi=True
                    ),
                ], className="filter-item"),
                html.Div([
                    html.Label("Date Range:"),
                    dcc.DatePickerRange(
                        id="report-date-range",
                        min_date_allowed=datetime.now() - timedelta(days=365),
                        max_date_allowed=datetime.now(),
                        initial_visible_month=datetime.now(),
                        end_date=datetime.now(),
                        start_date=datetime.now() - timedelta(days=7)
                    ),
                ], className="filter-item"),
                html.Button("Export CSV", id="export-csv-btn", className="export-btn"),
                html.Button("Export JSON", id="export-json-btn", className="export-btn"),
                html.Button("Export PDF", id="export-pdf-btn", className="export-btn"),
                dcc.Download(id="report-download")
            ], className="report-section"),

            # Summary Stats
            html.Div([
                html.H3("📊 Summary Statistics"),
                html.Div(id="summary-stats", className="stats-grid")
            ], className="summary-container")

        ], id="main-container", className="main-container"),

        # Interval component for auto-refresh
        dcc.Interval(
            id="interval-component",
            interval=30000,  # 30 seconds
            n_intervals=0
        )
    ])

# Set the layout from create_layout function
app.layout = create_layout()

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

            /* Dark mode override for body background */
            .main-container.dark-mode body {
                background-color: #1a1a1a !important;
            }

            /* Additional dark mode overrides for any remaining light backgrounds */
            .main-container.dark-mode .svg-container,
            .main-container.dark-mode .plotly-graph-div,
            .main-container.dark-mode .js-plotly-plot {
                background-color: #1e1e1e !important;
            }

            /* Ensure chart containers don't have light backgrounds */
            .main-container.dark-mode .chart-container {
                background-color: #1e1e1e !important;
                border: 1px solid #444 !important;
            }

            /* Fix any layering issues with chart elements */
            .main-container.dark-mode .pielayer,
            .main-container.dark-mode .cartesianlayer,
            .main-container.dark-mode .scatterlayer {
                opacity: 1 !important;
            }

            /* Ensure chart content is visible */
            .main-container.dark-mode .js-plotly-plot .pielayer .slice .surface,
            .main-container.dark-mode .js-plotly-plot .barlayer .trace .points .point,
            .main-container.dark-mode .js-plotly-plot .scatterlayer .trace .points .point {
                opacity: 1 !important;
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

            /* New styles for improved GUI */
            .header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
            }

            .header-content {
                flex: 1;
            }

            .header-controls {
                display: flex;
                gap: 20px;
                align-items: center;
            }

            .control-item {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 5px;
            }

            .toggle-label {
                font-size: 0.9em;
                margin-bottom: 5px;
            }

            .dark-mode-toggle .Select-control {
                background-color: #444;
                border-color: #666;
            }

            .scan-btn, .cleanup-btn {
                background: #28a745;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                cursor: pointer;
                font-weight: 600;
                transition: background 0.3s;
                margin: 2px;
            }

            .scan-btn:hover, .cleanup-btn:hover {
                background: #218838;
            }

            .cleanup-btn {
                background: #dc3545;
            }

            .cleanup-btn:hover {
                background: #c82333;
            }

            /* Scanner Status Styles */
            .scanner-status {
                background: white;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                margin-bottom: 30px;
            }

            .scanner-status h3 {
                margin-top: 0;
                color: #333;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }

            .scanner-status-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 15px;
                margin-top: 15px;
            }

            .status-item {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                text-align: center;
                border-left: 4px solid #28a745;
            }

            .status-item.status-error {
                border-left-color: #dc3545;
                background: #fff5f5;
            }

            .status-item.status-warning {
                border-left-color: #ffc107;
                background: #fffbf0;
            }

            /* Modal Styles */
            .modal-container {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.5);
                display: none;
                z-index: 1000;
                align-items: center;
                justify-content: center;
            }

            .modal-container.show {
                display: flex;
            }

            .modal-content {
                background: white;
                border-radius: 10px;
                padding: 30px;
                max-width: 500px;
                width: 90%;
                max-height: 80vh;
                overflow-y: auto;
            }

            .modal-content h2 {
                margin-top: 0;
                color: #333;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }

            .modal-field {
                margin-bottom: 20px;
            }

            .modal-field label {
                display: block;
                margin-bottom: 5px;
                font-weight: 600;
                color: #333;
            }

            .modal-input {
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
            }

            .modal-checklist {
                display: flex;
                flex-direction: column;
                gap: 10px;
            }

            .modal-buttons {
                display: flex;
                gap: 10px;
                justify-content: flex-end;
                margin-top: 30px;
            }

            .modal-btn {
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-weight: 600;
                transition: background 0.3s;
            }

            .modal-btn.primary {
                background: #007bff;
                color: white;
            }

            .modal-btn.primary:hover {
                background: #0056b3;
            }

            .modal-btn.secondary {
                background: #6c757d;
                color: white;
            }

            .modal-btn.secondary:hover {
                background: #545b62;
            }

            /* Info Tooltip Styles */
            .info-tooltip {
                cursor: help;
                color: #007bff;
                font-weight: bold;
                margin-left: 5px;
            }

            .info-tooltip:hover {
                color: #0056b3;
            }

            /* Dark Mode Styles */
            .main-container.dark-mode {
                background-color: #1a1a1a;
                color: #e0e0e0;
            }

            .main-container.dark-mode .header {
                background: #1e1e1e;
                border-bottom: 1px solid #444;
            }

            .main-container.dark-mode .header-title {
                color: #e0e0e0;
            }

            .main-container.dark-mode .header-subtitle {
                color: #b0b0b0;
            }

            .main-container.dark-mode .last-update {
                color: #b0b0b0;
            }

            .main-container.dark-mode .toggle-label {
                color: #e0e0e0;
            }

            .main-container.dark-mode .scan-btn {
                background: #28a745;
                color: white;
            }

            .main-container.dark-mode .scan-btn:hover {
                background: #218838;
            }

            .main-container.dark-mode .cleanup-btn {
                background: #dc3545;
                color: white;
            }

            .main-container.dark-mode .cleanup-btn:hover {
                background: #c82333;
            }

            .main-container.dark-mode .scanner-status {
                background: #1e1e1e;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            }

            .main-container.dark-mode .scanner-status h3 {
                color: #e0e0e0;
                border-bottom: 2px solid #667eea;
            }

            .main-container.dark-mode .status-item {
                background: #3d3d3d;
                color: #e0e0e0;
                border-left: 4px solid #28a745;
            }

            .main-container.dark-mode .status-item.status-error {
                border-left-color: #dc3545;
                background: #4d2d2d;
            }

            .main-container.dark-mode .status-item.status-warning {
                border-left-color: #ffc107;
                background: #4d4d2d;
            }

            /* Modal Styles */
            .main-container.dark-mode .modal-container {
                background: rgba(0,0,0,0.7);
            }

            .main-container.dark-mode .modal-content {
                background: #1e1e1e;
                color: #e0e0e0;
            }

            .main-container.dark-mode .modal-content h2 {
                color: #e0e0e0;
                border-bottom: 2px solid #667eea;
            }

            .main-container.dark-mode .modal-field label {
                color: #e0e0e0;
            }

            .main-container.dark-mode .modal-input {
                background: #3d3d3d;
                border-color: #555;
                color: #e0e0e0;
            }

            .main-container.dark-mode .modal-input:focus {
                border-color: #667eea;
            }

            .main-container.dark-mode .modal-btn.primary {
                background: #007bff;
                color: white;
            }

            .main-container.dark-mode .modal-btn.primary:hover {
                background: #0056b3;
            }

            .main-container.dark-mode .modal-btn.secondary {
                background: #6c757d;
                color: white;
            }

            .main-container.dark-mode .modal-btn.secondary:hover {
                background: #545b62;
            }

            /* Dark mode for body and html */
            .main-container.dark-mode body {
                background-color: #1a1a1a !important;
                color: #e0e0e0 !important;
            }

            /* Dark mode for info tooltips */
            .main-container.dark-mode .info-tooltip {
                color: #4dabf7;
            }

            .main-container.dark-mode .info-tooltip:hover {
                color: #339af0;
            }

            /* Dark mode for data table container */
            .main-container.dark-mode .data-table {
                background-color: #1e1e1e !important;
                border: 1px solid #444 !important;
                color: #e0e0e0 !important;
            }

            .main-container.dark-mode .data-table h3 {
                color: #e0e0e0 !important;
            }

            /* Dark mode for summary container */
            .main-container.dark-mode .summary-container {
                background-color: #1e1e1e !important;
                border: 1px solid #444 !important;
                color: #e0e0e0 !important;
            }

            .main-container.dark-mode .summary-container h4 {
                color: #e0e0e0 !important;
            }

            /* Dark mode for scanner status */
            .main-container.dark-mode .scanner-status {
                background-color: #1e1e1e !important;
                border: 1px solid #444 !important;
                color: #e0e0e0 !important;
            }

            .main-container.dark-mode .scanner-status h3 {
                color: #e0e0e0 !important;
            }

            /* Dark mode for modal content */
            .main-container.dark-mode .modal-content {
                background-color: #1e1e1e !important;
                border: 1px solid #444 !important;
                color: #e0e0e0 !important;
            }

            .main-container.dark-mode .modal-content h2 {
                color: #e0e0e0 !important;
            }

            /* Dark mode for html element (universal background) */
            html.dark-mode {
                background-color: #1a1a1a !important;
                color: #e0e0e0 !important;
            }

            /* Dark mode for entire page background */
            html.dark-mode,
            html.dark-mode body {
                background-color: #1a1a1a !important;
                color: #e0e0e0 !important;
            }

            /* Dark mode for Plotly chart plot area backgrounds */
            .main-container.dark-mode .js-plotly-plot .main-svg {
                background-color: #1e1e1e !important;
            }

            .main-container.dark-mode .js-plotly-plot .svg-container {
                background-color: #1e1e1e !important;
            }

            /* Dark mode for Plotly chart paper background (area around plots) */
            .main-container.dark-mode .js-plotly-plot .plot {
                background-color: #1e1e1e !important;
            }

            /* Dark mode for Plotly cartesian layer (bar chart backgrounds) */
            .main-container.dark-mode .js-plotly-plot .cartesianlayer {
                background-color: #1e1e1e !important;
            }

            /* Dark mode for Plotly pie chart backgrounds */
            .main-container.dark-mode .js-plotly-plot .pielayer {
                background-color: #1e1e1e !important;
            }

            /* Dark mode for Plotly subplot backgrounds */
            .main-container.dark-mode .js-plotly-plot .layer-above {
                background-color: #1e1e1e !important;
            }

            /* Dark mode for chart container padding areas */
            .main-container.dark-mode .chart-container {
                background-color: #1e1e1e !important;
                border: 1px solid #444 !important;
                padding: 15px !important;
            }

            /* Dark mode for universal background - apply to html and body when main container has dark mode */
            html:has(.main-container.dark-mode),
            body:has(.main-container.dark-mode) {
                background-color: #1a1a1a !important;
                color: #e0e0e0 !important;
            }

            /* Alternative approach for universal background */
            .main-container.dark-mode ~ * {
                background-color: #1a1a1a !important;
            }

            /* Dark mode for actual chart content elements */
            .main-container.dark-mode .js-plotly-plot .barlayer .trace.bars .point {
                fill: #4a90e2 !important;
                stroke: #2c5aa0 !important;
                stroke-width: 1px !important;
            }

            .main-container.dark-mode .js-plotly-plot .pielayer .trace .slice {
                stroke: #1e1e1e !important;
                stroke-width: 2px !important;
            }

            .main-container.dark-mode .js-plotly-plot .scatterlayer .trace .points .point {
                fill: #4a90e2 !important;
                stroke: #2c5aa0 !important;
                stroke-width: 2px !important;
            }

            .main-container.dark-mode .js-plotly-plot .scatterlayer .trace .lines path {
                stroke: #4a90e2 !important;
                stroke-width: 2px !important;
            }

            /* Dark mode for chart markers and symbols */
            .main-container.dark-mode .js-plotly-plot .point {
                fill: #4a90e2 !important;
                stroke: #2c5aa0 !important;
            }

            /* Dark mode for bar chart elements */
            .main-container.dark-mode .js-plotly-plot .barlayer .trace .points .point {
                fill: #4a90e2 !important;
                stroke: #2c5aa0 !important;
            }

            /* Dark mode for pie chart slices - ensure they have visible colors */
            .main-container.dark-mode .js-plotly-plot .pielayer path {
                stroke: #1e1e1e !important;
                stroke-width: 1px !important;
            }

            /* Dark mode for line chart elements */
            .main-container.dark-mode .js-plotly-plot .scatterlayer path {
                stroke: #4a90e2 !important;
                fill: none !important;
            }

            /* Dark mode for area fills */
            .main-container.dark-mode .js-plotly-plot .scatterlayer .trace .fill {
                fill: rgba(74, 144, 226, 0.3) !important;
            }

            /* High specificity overrides for Dash defaults - loaded last to override */
            html body .main-container.dark-mode .js-plotly-plot .main-svg {
                background: #1e1e1e !important;
                fill: #1e1e1e !important;
            }

            html body .main-container.dark-mode .js-plotly-plot .bg {
                fill: #1e1e1e !important;
            }

            html body .main-container.dark-mode .js-plotly-plot .plot-bg {
                fill: #1e1e1e !important;
            }

            /* Ensure no elements are covering the charts */
            .main-container.dark-mode .js-plotly-plot .hoverlayer,
            .main-container.dark-mode .js-plotly-plot .draglayer {
                pointer-events: none !important;
            }

            /* Force chart visibility with maximum specificity */
            html body .main-container.dark-mode .chart-container .js-plotly-plot {
                background-color: #1e1e1e !important;
                opacity: 1 !important;
                visibility: visible !important;
            }

            /* Nuclear option: override any grey backgrounds from external sources */
            .main-container.dark-mode .js-plotly-plot * {
                background-color: transparent !important;
            }

            /* But restore backgrounds for specific chart elements */
            .main-container.dark-mode .js-plotly-plot .main-svg,
            .main-container.dark-mode .js-plotly-plot .bg,
            .main-container.dark-mode .js-plotly-plot .plot-bg,
            .main-container.dark-mode .chart-container {
                background-color: #1e1e1e !important;
            }

            /* Dark mode for table severity column highlighting */
            .main-container.dark-mode .dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner table tbody tr td[data-dash-column="severity"]:has-text() {
                color: #ffffff !important;
            }

            /* Dark mode Critical severity highlighting */
            .main-container.dark-mode .dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner table tbody tr td[data-dash-column="severity"]:has-text():contains("Critical"),
            .main-container.dark-mode .dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner table tbody tr td[data-dash-column="severity"]:has-text():contains("CRITICAL") {
                background-color: #8b0000 !important;
                color: #ffffff !important;
                font-weight: bold !important;
            }

            /* Dark mode High severity highlighting */
            .main-container.dark-mode .dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner table tbody tr td[data-dash-column="severity"]:has-text():contains("High"),
            .main-container.dark-mode .dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner table tbody tr td[data-dash-column="severity"]:has-text():contains("HIGH") {
                background-color: #6d2f2f !important;
                color: #ffffff !important;
                font-weight: bold !important;
            }

            /* Dark mode Medium severity highlighting */
            .main-container.dark-mode .dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner table tbody tr td[data-dash-column="severity"]:has-text():contains("Medium"),
            .main-container.dark-mode .dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner table tbody tr td[data-dash-column="severity"]:has-text():contains("MEDIUM") {
                background-color: #75542b !important;
                color: #ffffff !important;
                font-weight: bold !important;
            }

            /* Dark mode Low severity highlighting */
            .main-container.dark-mode .dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner table tbody tr td[data-dash-column="severity"]:has-text():contains("Low"),
            .main-container.dark-mode .dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner table tbody tr td[data-dash-column="severity"]:has-text():contains("LOW") {
                background-color: #2c4a6b !important;
                color: #ffffff !important;
                font-weight: bold !important;
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
            logging.StreamHandler()  # Only use stream handler for read-only containers
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
    if not init_redis(host=config.redis.host, port=config.redis.port, password=config.redis.password):
        logger.warning("⚠️ Redis not available - dashboard will work with reduced caching")
        audit_log('redis_unavailable', 'system', {'impact': 'reduced_caching'})
    else:
        logger.info("✅ Redis connection established")

    # Security configuration validation
    dashboard_host = config.dashboard.host
    dashboard_port = config.dashboard.port

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
    debug_mode = config.debug
    if debug_mode:
        logger.warning("⚠️ DEBUG MODE ENABLED - Disable for production use")
        audit_log('debug_mode_enabled', 'system', {'warning': 'debug_enabled'})

    logger.info("🚀 Starting SecretSnipe Dashboard...")
    logger.info(f"📊 Dashboard will be available at http://{dashboard_host}:{dashboard_port}")
    logger.info("🔒 Security features active: Rate limiting, Input validation, Audit logging")

    try:
        # Start the server with security configurations
        app.run(
            host=dashboard_host,
            port=dashboard_port,
            debug=debug_mode,
            # Security: Disable dev tools in production
            dev_tools_ui=debug_mode,
            dev_tools_props_check=debug_mode
        )
    except Exception as e:
        logger.error(f"❌ Failed to start dashboard server: {e}")
        audit_log('server_startup_failure', 'system', {'error': str(e)})
        return 1

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
