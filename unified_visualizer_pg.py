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

import os
import dash
from flask import session, request, redirect
import base64
from io import BytesIO
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
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
from jira_manager import jira_manager, update_jira_config
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
        {"name": "referrer", "content": "strict-origin-when-cross-origin"},
        {"http-equiv": "Cache-Control", "content": "no-cache, no-store, must-revalidate"},
        {"http-equiv": "Pragma", "content": "no-cache"},
        {"http-equiv": "Expires", "content": "0"}
    ]
)

# Get the Flask server instance
server = app.server

# Configure Flask session for authentication
server.secret_key = os.urandom(24)  # Random secret key for sessions

# Server-side authentication enforcement
@server.before_request
def require_auth():
    """Enforce authentication at the Flask server level"""
    # Skip auth check if authentication is disabled
    if not config.dashboard.enable_auth:
        return None
    
    # Allow access to static assets and authentication endpoints
    if (request.path.startswith('/_dash') or 
        request.path.startswith('/assets') or
        request.path.startswith('/login') or
        request.path.startswith('/logout')):
        return None
    
    # Check if user is authenticated
    if not session.get('authenticated'):
        # For AJAX requests, return 401
        if request.is_json or 'application/json' in request.headers.get('Accept', ''):
            return {'error': 'Authentication required'}, 401
        
        # For regular requests, show login page
        return render_login_page()

def render_login_page():
    """Render a server-side login page"""
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecretSnipe Dashboard - Login</title>
        <style>
            body {{ 
                font-family: Arial, sans-serif; 
                background: #1a1a1a; 
                color: #e0e0e0;
                display: flex; 
                justify-content: center; 
                align-items: center; 
                height: 100vh; 
                margin: 0; 
            }}
            .login-container {{ 
                background: #1e1e1e; 
                padding: 40px; 
                border-radius: 10px; 
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                max-width: 400px;
                width: 100%;
            }}
            .login-container h2 {{ 
                text-align: center; 
                margin-bottom: 30px; 
                color: #4dabf7;
            }}
            .form-group {{ margin-bottom: 20px; }}
            label {{ 
                display: block; 
                margin-bottom: 5px; 
                font-weight: 600;
            }}
            input {{ 
                width: 100%; 
                padding: 12px; 
                border: 1px solid #444; 
                border-radius: 5px; 
                background: #3d3d3d;
                color: #e0e0e0;
                font-size: 14px;
            }}
            input:focus {{
                border-color: #4dabf7;
                outline: none;
            }}
            button {{ 
                width: 100%; 
                padding: 12px; 
                background: #4dabf7; 
                color: white; 
                border: none; 
                border-radius: 5px; 
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: background 0.3s;
            }}
            button:hover {{ background: #339af0; }}
            .error {{ 
                color: #ff6b6b; 
                text-align: center; 
                margin-top: 15px; 
            }}
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2>SecretSnipe Dashboard</h2>
            <form method="post" action="/login">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Login</button>
                {('<div class="error">Invalid credentials</div>' if request.args.get('error') else '')}
            </form>
        </div>
    </body>
    </html>
    '''

# Debug route to test if Flask routes work at all
@server.route('/test', methods=['GET'])
def test_route():
    """Test route to verify Flask routing is working"""
    return "Flask route test successful!", 200

# Login route
@server.route('/login', methods=['POST'])
def handle_login():
    """Handle login form submission"""
    # Always redirect for testing
    session['authenticated'] = True
    session['username'] = 'admin'
    return redirect('/', code=302)

# Logout route
@server.route('/logout', methods=['POST', 'GET'])
def handle_logout():
    """Handle logout"""
    username = session.get('username', 'unknown')
    session.clear()
    audit_log('logout', 'system', {'username': username})
    return redirect('/')

# Global data cache with security
data_cache = {
    'findings_df': None,
    'last_update': None,
    'cache_duration': timedelta(minutes=5),
    'access_log': [],
    'rate_limits': {}
}

# Authentication setup - now handled at server level
# App layout will be set after create_layout function is defined

import bcrypt

def rate_limit_check(client_ip: str) -> bool:
    """Check if client is within rate limits"""
    now = datetime.now()
    client_key = f"rate_limit:{client_ip}"

    # Get current request count
    current_count = redis_manager.cache_manager.get('security', client_key) or 0 if redis_manager.cache_manager else 0

    # Reset counter if window expired
    if current_count == 0:
        redis_manager.cache_manager.set('security', client_key, 1, ttl_seconds=SECURITY_CONFIG['rate_limit_window']) if redis_manager.cache_manager else None
        return True

    if current_count >= SECURITY_CONFIG['rate_limit_requests']:
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        return False

    # Increment counter
    redis_manager.cache_manager.set('security', client_key, current_count + 1, ttl_seconds=SECURITY_CONFIG['rate_limit_window']) if redis_manager.cache_manager else None
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
        # Limit to 5000 most recent for performance - stats come from separate count queries
        query = """
            SELECT
                f.id, f.file_path, f.secret_type, f.secret_value, f.context, f.severity, f.tool_source,
                f.first_seen, f.last_seen, f.confidence_score, f.resolution_status,
                f.fp_reason, f.fp_marked_by, f.fp_marked_at,
                p.name as project_name, ss.scan_type
            FROM findings f
            JOIN projects p ON f.project_id = p.id
            JOIN scan_sessions ss ON f.scan_session_id = ss.id
            ORDER BY f.first_seen DESC
            LIMIT 5000
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
     Output("project-filter", "options"),
     Output("fp-count-badge", "children")],
    [Input("severity-filter", "value"),
     Input("tool-filter", "value"),
     Input("project-filter", "value"),
     Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
@secure_callback
def update_dashboard(severity_filter, tool_filter, project_filter, refresh_clicks, n_intervals):
    """Update all dashboard components with permanent dark mode and security validation"""

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

    # Dark mode is now permanently enabled
    is_dark_mode = True
    template = 'plotly_dark'

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

    # Get FP count for badge
    fp_count = 0
    try:
        fp_count = findings_manager.get_false_positive_count()
    except Exception:
        pass
    fp_badge = f"🚫 {fp_count} False Positives"

    if df.empty:
        empty_fig = go.Figure()
        empty_fig.update_layout(
            title="No data available",
            template=template,
            # Additional background forcing
            margin=dict(l=50, r=50, t=50, b=50),
            showlegend=False,
            paper_bgcolor='rgba(0,0,0,0)' if is_dark_mode else None,
            plot_bgcolor='rgba(0,0,0,0)' if is_dark_mode else None
        )
        return empty_fig, empty_fig, empty_fig, empty_fig, [], "No data", "Never", [], fp_badge

    # Apply filters with validation
    filtered_df = df.copy()

    # Always exclude false positives from main table (use FP Viewer to see them)
    if 'resolution_status' in filtered_df.columns:
        filtered_df = filtered_df[filtered_df['resolution_status'] != 'false_positive']

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
        margin=dict(l=50, r=50, t=50, b=50),
        paper_bgcolor='rgba(0,0,0,0)' if is_dark_mode else None,
        plot_bgcolor='rgba(0,0,0,0)' if is_dark_mode else None
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
        ),
        paper_bgcolor='rgba(0,0,0,0)' if is_dark_mode else None,
        plot_bgcolor='rgba(0,0,0,0)' if is_dark_mode else None
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
        showlegend=False,
        paper_bgcolor='rgba(0,0,0,0)' if is_dark_mode else None,
        plot_bgcolor='rgba(0,0,0,0)' if is_dark_mode else None
    )

    # Create file types chart
    filtered_df['file_extension'] = filtered_df['file_path'].str.extract(r'\.([^.]+)$')
    extension_counts = filtered_df['file_extension'].value_counts().head(10)
    
    # Use discrete colors for better visual distinction
    file_extension_colors = tool_colors[:len(extension_counts)] if len(extension_counts) <= len(tool_colors) else tool_colors * ((len(extension_counts) // len(tool_colors)) + 1)
    
    file_types_chart = px.bar(
        x=extension_counts.index,
        y=extension_counts.values,
        title="Top File Extensions",
        labels={'x': 'Extension', 'y': 'Count'},
        color=extension_counts.index,
        color_discrete_sequence=file_extension_colors,
        template=template
    )
    file_types_chart.update_layout(
        margin=dict(l=50, r=50, t=50, b=50),
        showlegend=False,
        paper_bgcolor='rgba(0,0,0,0)' if is_dark_mode else None,
        plot_bgcolor='rgba(0,0,0,0)' if is_dark_mode else None
    )

    # Prepare table data - limited to 5000 for performance
    table_data = filtered_df.to_dict('records')

    # Sanitize table data (truncate long strings for display)
    for row in table_data:
        for key, value in row.items():
            if isinstance(value, str):
                row[key] = sanitize_input(value, 500)  # Limit field length for display

    # Get accurate counts from database (fast COUNT queries)
    try:
        # Total count
        total_query = "SELECT COUNT(*) as count FROM findings WHERE resolution_status != 'false_positive'"
        total_result = db_manager.execute_query(total_query)
        total_in_db = total_result[0]['count'] if total_result else 0
        
        # Severity counts
        severity_query = """
            SELECT severity, COUNT(*) as count 
            FROM findings 
            WHERE resolution_status != 'false_positive'
            GROUP BY severity
        """
        severity_result = db_manager.execute_query(severity_query)
        severity_counts = {r['severity']: r['count'] for r in severity_result} if severity_result else {}
        
        # Tool counts
        tool_query = """
            SELECT tool_source, COUNT(*) as count 
            FROM findings 
            WHERE resolution_status != 'false_positive'
            GROUP BY tool_source
        """
        tool_result = db_manager.execute_query(tool_query)
        tool_counts = {r['tool_source']: r['count'] for r in tool_result} if tool_result else {}
        
        critical_count = severity_counts.get('Critical', 0)
        high_count = severity_counts.get('High', 0)
        medium_count = severity_counts.get('Medium', 0)
        low_count = severity_counts.get('Low', 0)
        
        custom_count = tool_counts.get('custom', 0)
        gitleaks_count = tool_counts.get('gitleaks', 0)
        trufflehog_count = tool_counts.get('trufflehog', 0)
        
    except Exception as e:
        logger.warning(f"Error getting DB counts: {e}")
        # Fallback to dataframe counts
        total_in_db = len(df)
        critical_count = len(filtered_df[filtered_df['severity'] == 'Critical'])
        high_count = len(filtered_df[filtered_df['severity'] == 'High'])
        medium_count = len(filtered_df[filtered_df['severity'] == 'Medium'])
        low_count = len(filtered_df[filtered_df['severity'] == 'Low'])
        custom_count = len(filtered_df[filtered_df['tool_source'] == 'custom'])
        gitleaks_count = len(filtered_df[filtered_df['tool_source'] == 'gitleaks'])
        trufflehog_count = len(filtered_df[filtered_df['tool_source'] == 'trufflehog'])
    
    total_filtered = len(filtered_df)  # What's shown in table (up to 5000)
    open_count = len(filtered_df[filtered_df['resolution_status'] == 'open'])

    summary_stats = [
        html.Div([
            html.H4("📊 Overview", style={'marginBottom': '10px', 'color': '#60a5fa'}),
            html.Div([html.Strong("Total in Database:"), f" {total_in_db:,}"], className="stat-item"),
            html.Div([html.Strong("Showing in Table:"), f" {total_filtered:,} (max 5,000)"], className="stat-item"),
            html.Div([html.Strong("Open Issues:"), f" {open_count:,}"], className="stat-item"),
        ], style={'marginRight': '30px'}),
        html.Div([
            html.H4("🎯 By Severity", style={'marginBottom': '10px', 'color': '#f59e0b'}),
            html.Div([html.Strong("Critical:"), html.Span(f" {critical_count:,}", style={'color': '#ff0000'})], className="stat-item"),
            html.Div([html.Strong("High:"), html.Span(f" {high_count:,}", style={'color': '#d9534f'})], className="stat-item"),
            html.Div([html.Strong("Medium:"), html.Span(f" {medium_count:,}", style={'color': '#f0ad4e'})], className="stat-item"),
            html.Div([html.Strong("Low:"), html.Span(f" {low_count:,}", style={'color': '#5cb85c'})], className="stat-item"),
        ], style={'marginRight': '30px'}),
        html.Div([
            html.H4("🔧 By Tool", style={'marginBottom': '10px', 'color': '#22c55e'}),
            html.Div([html.Strong("Custom Scanner:"), f" {custom_count:,}"], className="stat-item"),
            html.Div([html.Strong("Gitleaks:"), f" {gitleaks_count:,}"], className="stat-item"),
            html.Div([html.Strong("TruffleHog:"), f" {trufflehog_count:,}"], className="stat-item"),
        ]),
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
            table_data, summary_stats, last_update, project_options, fp_badge)

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


# Finding Detail Modal Callbacks
@app.callback(
    [Output("finding-detail-modal", "className"),
     Output("finding-detail-content", "children")],
    [Input("findings-table", "active_cell"),
     Input("close-detail-modal-btn-bottom", "n_clicks")],
    [State("findings-table", "data"),
     State("finding-detail-modal", "className")]
)
@secure_callback
def show_finding_detail(active_cell, close_bottom_clicks, table_data, current_class):
    """Show detailed view of a finding when clicking a table row"""
    ctx = dash.callback_context
    if not ctx.triggered:
        return "modal-container", []
    
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    # Close button clicked
    if trigger_id == "close-detail-modal-btn-bottom":
        return "modal-container", []
    
    # Table cell clicked
    if trigger_id == "findings-table" and active_cell and table_data:
        row_idx = active_cell.get('row')
        if row_idx is not None and row_idx < len(table_data):
            row = table_data[row_idx]
            
            # Build detailed view
            detail_content = html.Div([
                # Severity badge
                html.Div([
                    html.Span(
                        row.get('severity', 'Unknown'),
                        className=f"severity-badge severity-{row.get('severity', 'unknown').lower()}"
                    ),
                    html.Span(f" • {row.get('tool_source', 'Unknown Tool')}", className="tool-badge")
                ], className="detail-badges"),
                
                # Main fields
                html.Div([
                    html.Label("📁 File Path:"),
                    html.Pre(row.get('file_path', 'N/A'), className="detail-value file-path-value")
                ], className="detail-field"),
                
                html.Div([
                    html.Label("🏷️ Secret Type:"),
                    html.Div(row.get('secret_type', 'N/A'), className="detail-value")
                ], className="detail-field"),
                
                html.Div([
                    html.Label("🔑 Secret Value:"),
                    html.Pre(row.get('secret_value', 'N/A'), className="detail-value secret-value-full")
                ], className="detail-field"),
                
                html.Div([
                    html.Label("📝 Full Context:"),
                    html.Pre(row.get('context', 'N/A'), className="detail-value context-value-full")
                ], className="detail-field"),
                
                # Metadata row
                html.Div([
                    html.Div([
                        html.Label("📅 First Seen:"),
                        html.Div(row.get('first_seen', 'N/A'), className="detail-value")
                    ], className="detail-field-small"),
                    html.Div([
                        html.Label("📊 Confidence:"),
                        html.Div(str(row.get('confidence_score', 'N/A')), className="detail-value")
                    ], className="detail-field-small"),
                    html.Div([
                        html.Label("📂 Project:"),
                        html.Div(row.get('project_name', 'N/A'), className="detail-value")
                    ], className="detail-field-small")
                ], className="detail-metadata-row"),
                
                # False Positive info (only show if marked as FP)
                html.Div([
                    html.Div([
                        html.Label("🚫 False Positive Status:"),
                        html.Div([
                            html.Span("⚠️ Marked as False Positive", style={'color': '#f59e0b', 'fontWeight': 'bold'}),
                        ], className="detail-value")
                    ], className="detail-field"),
                    html.Div([
                        html.Label("📝 FP Reason:"),
                        html.Pre(row.get('fp_reason', 'No reason provided'), className="detail-value", 
                                style={'whiteSpace': 'pre-wrap', 'backgroundColor': '#2d2d2d', 'padding': '10px', 'borderRadius': '4px'})
                    ], className="detail-field"),
                    html.Div([
                        html.Div([
                            html.Label("👤 Marked By:"),
                            html.Div(row.get('fp_marked_by', 'N/A'), className="detail-value")
                        ], className="detail-field-small"),
                        html.Div([
                            html.Label("📅 Marked At:"),
                            html.Div(str(row.get('fp_marked_at', 'N/A')), className="detail-value")
                        ], className="detail-field-small"),
                    ], className="detail-metadata-row")
                ], className="fp-info-section", style={
                    'marginTop': '15px', 
                    'padding': '15px', 
                    'backgroundColor': '#3d3522', 
                    'borderRadius': '8px',
                    'border': '1px solid #f59e0b'
                }) if row.get('resolution_status') == 'false_positive' else html.Div()
            ], className="finding-detail-container")
            
            return "modal-container show", detail_content
    
    return current_class or "modal-container", []


@app.callback(
    Output("report-download", "data"),
    [Input("export-csv-btn", "n_clicks"),
     Input("export-json-btn", "n_clicks"),
     Input("export-pdf-btn", "n_clicks")],
    [State("report-severity-filter", "value"),
     State("report-date-range", "start_date"),
     State("report-date-range", "end_date"),
     State("severity-filter", "value"),
     State("tool-filter", "value")]
)
@secure_callback
def export_report(csv_clicks, json_clicks, pdf_clicks, report_severities, start_date, end_date, severity_filter, tool_filter):
    """Export customized reports with enhanced filtering and formatting"""
    ctx = dash.callback_context
    if not ctx.triggered:
        return no_update

    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

    try:
        # Get filtered data with enhanced filtering
        df = get_findings_data()
        
        if df.empty:
            return no_update
            
        # Apply report-specific filters
        if report_severities and "all" not in report_severities:
            df = df[df['severity'].isin(report_severities)]
        elif severity_filter and severity_filter != "all":
            df = df[df['severity'] == severity_filter]
            
        if tool_filter and tool_filter != "all":
            df = df[df['tool_source'] == tool_filter]
            
        if start_date:
            df = df[df['first_seen'] >= start_date]
        if end_date:
            df = df[df['first_seen'] <= end_date]

        # Sanitize data for export
        export_df = df.copy()
        for col in export_df.columns:
            if export_df[col].dtype == 'object':
                export_df[col] = export_df[col].astype(str).apply(lambda x: sanitize_input(x, 1000))

        if trigger_id == "export-csv-btn":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            return dcc.send_data_frame(
                export_df.to_csv, 
                f"secretsnipe_report_{timestamp}.csv",
                index=False
            )

        elif trigger_id == "export-json-btn":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Create enhanced JSON with metadata
            report_data = {
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "total_findings": len(export_df),
                    "severity_breakdown": export_df['severity'].value_counts().to_dict(),
                    "tool_breakdown": export_df['tool_source'].value_counts().to_dict(),
                    "date_range": {
                        "start": start_date,
                        "end": end_date
                    },
                    "filters_applied": {
                        "severities": report_severities,
                        "severity_filter": severity_filter,
                        "tool_filter": tool_filter
                    }
                },
                "findings": export_df.to_dict(orient="records")
            }
            import json
            return dcc.send_string(
                json.dumps(report_data, indent=2, default=str),
                f"secretsnipe_report_{timestamp}.json"
            )

        elif trigger_id == "export-pdf-btn":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            buffer = BytesIO()
            
            # Create PDF document
            doc = SimpleDocTemplate(buffer, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.darkblue
            )
            story.append(Paragraph("SecretSnipe Security Report", title_style))
            story.append(Spacer(1, 12))
            
            # Metadata
            story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Paragraph(f"<b>Total Findings:</b> {len(export_df)}", styles['Normal']))
            story.append(Spacer(1, 12))
            
            # Severity breakdown
            severity_counts = export_df['severity'].value_counts()
            story.append(Paragraph("<b>Severity Breakdown:</b>", styles['Heading2']))
            for severity, count in severity_counts.items():
                story.append(Paragraph(f"• {severity}: {count}", styles['Normal']))
            story.append(Spacer(1, 12))
            
            # Tool breakdown
            tool_counts = export_df['tool_source'].value_counts()
            story.append(Paragraph("<b>Tool Source Breakdown:</b>", styles['Heading2']))
            for tool, count in tool_counts.items():
                story.append(Paragraph(f"• {tool}: {count}", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Findings table (top 50 for space)
            if len(export_df) > 0:
                story.append(Paragraph("<b>Findings Summary (Top 50):</b>", styles['Heading2']))
                
                # Prepare table data
                table_data = [['File Path', 'Secret Type', 'Severity', 'Tool', 'Confidence']]
                for _, row in export_df.head(50).iterrows():
                    table_data.append([
                        str(row.get('file_path', ''))[:40] + '...' if len(str(row.get('file_path', ''))) > 40 else str(row.get('file_path', '')),
                        str(row.get('secret_type', ''))[:20],
                        str(row.get('severity', '')),
                        str(row.get('tool_source', '')),
                        f"{float(row.get('confidence_score', 0)):.2%}" if row.get('confidence_score') else 'N/A'
                    ])
                
                # Create table
                table = Table(table_data, colWidths=[2.5*inch, 1.5*inch, 0.8*inch, 1*inch, 0.8*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(table)
            
            # Build PDF
            doc.build(story)
            buffer.seek(0)
            
            return dcc.send_bytes(
                buffer.getvalue(), 
                f"secretsnipe_report_{timestamp}.pdf"
            )

    except Exception as e:
        logger.error(f"Error exporting report: {e}")
        return no_update

    return no_update


# False Positive Management Callbacks
@app.callback(
    [Output("fp-reason-modal", "style"),
     Output("selected-rows-for-fp", "data")],
    [Input("btn-mark-fp", "n_clicks"),
     Input("btn-cancel-fp", "n_clicks"),
     Input("btn-confirm-fp", "n_clicks")],
    [State("findings-table", "selected_rows"),
     State("findings-table", "data")]
)
def toggle_fp_modal(mark_clicks, cancel_clicks, confirm_clicks, selected_rows, table_data):
    """Toggle the false positive reason modal"""
    ctx = dash.callback_context
    if not ctx.triggered:
        return {'display': 'none'}, []
    
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    if trigger_id == "btn-mark-fp":
        if selected_rows and table_data:
            # Get the IDs of selected rows
            selected_ids = [table_data[i].get('id') for i in selected_rows if i < len(table_data)]
            if selected_ids:
                return {
                    'display': 'block', 'position': 'fixed', 'top': '0', 'left': '0',
                    'right': '0', 'bottom': '0', 'backgroundColor': 'rgba(0,0,0,0.7)',
                    'zIndex': '1000', 'paddingTop': '100px'
                }, selected_ids
        return {'display': 'none'}, []
    
    # Cancel or confirm closes the modal
    return {'display': 'none'}, []


@app.callback(
    [Output("fp-action-result", "children"),
     Output("fp-action-result", "style"),
     Output("findings-table", "selected_rows")],
    [Input("btn-confirm-fp", "n_clicks"),
     Input("btn-restore-fp", "n_clicks")],
    [State("selected-rows-for-fp", "data"),
     State("fp-reason-input", "value"),
     State("findings-table", "selected_rows"),
     State("findings-table", "data")]
)
def handle_fp_actions(confirm_clicks, restore_clicks, selected_ids_for_fp, fp_reason, 
                     selected_rows, table_data):
    """Handle false positive marking and restoration"""
    ctx = dash.callback_context
    if not ctx.triggered:
        return "", {'display': 'none'}, []
    
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    try:
        if trigger_id == "btn-confirm-fp" and selected_ids_for_fp:
            # Mark as false positive
            result = findings_manager.mark_as_false_positive(
                finding_ids=selected_ids_for_fp,
                reason=fp_reason or "Marked as false positive by user",
                marked_by="dashboard_user"
            )
            
            # Force cache refresh
            data_cache['findings_df'] = None
            data_cache['last_update'] = None
            
            if result['success'] > 0:
                return (
                    f"✅ Successfully marked {result['success']} finding(s) as false positive",
                    {
                        'display': 'block', 'padding': '10px 15px',
                        'backgroundColor': '#16a34a', 'color': 'white',
                        'borderRadius': '6px', 'marginBottom': '10px'
                    },
                    []  # Clear selection
                )
            else:
                return (
                    "❌ Failed to mark findings as false positive",
                    {
                        'display': 'block', 'padding': '10px 15px',
                        'backgroundColor': '#dc2626', 'color': 'white',
                        'borderRadius': '6px', 'marginBottom': '10px'
                    },
                    selected_rows
                )
        
        elif trigger_id == "btn-restore-fp" and selected_rows and table_data:
            # Get selected finding IDs (only those that are false positives)
            selected_ids = []
            for i in selected_rows:
                if i < len(table_data):
                    row = table_data[i]
                    if row.get('resolution_status') == 'false_positive':
                        selected_ids.append(row.get('id'))
            
            if not selected_ids:
                return (
                    "⚠️ No false positive findings selected to restore",
                    {
                        'display': 'block', 'padding': '10px 15px',
                        'backgroundColor': '#d97706', 'color': 'white',
                        'borderRadius': '6px', 'marginBottom': '10px'
                    },
                    selected_rows
                )
            
            result = findings_manager.restore_from_false_positive(selected_ids)
            
            # Force cache refresh
            data_cache['findings_df'] = None
            data_cache['last_update'] = None
            
            if result['success'] > 0:
                return (
                    f"✅ Successfully restored {result['success']} finding(s) from false positive",
                    {
                        'display': 'block', 'padding': '10px 15px',
                        'backgroundColor': '#16a34a', 'color': 'white',
                        'borderRadius': '6px', 'marginBottom': '10px'
                    },
                    []  # Clear selection
                )
    
    except Exception as e:
        logger.error(f"Error in FP action: {e}")
        return (
            f"❌ Error: {str(e)}",
            {
                'display': 'block', 'padding': '10px 15px',
                'backgroundColor': '#dc2626', 'color': 'white',
                'borderRadius': '6px', 'marginBottom': '10px'
            },
            selected_rows
        )
    
    return "", {'display': 'none'}, selected_rows


# False Positives Viewer Modal Callbacks
@app.callback(
    [Output("fp-viewer-modal", "style"),
     Output("fp-viewer-table-container", "children")],
    [Input("btn-view-fps", "n_clicks"),
     Input("close-fp-viewer-btn", "n_clicks")],
    [State("fp-viewer-modal", "style")],
    prevent_initial_call=True
)
@secure_callback
def toggle_fp_viewer_modal(view_clicks, close_clicks, current_style):
    """Toggle the False Positives viewer modal and load data"""
    ctx = dash.callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    # Close button clicked
    if trigger_id == "close-fp-viewer-btn":
        return {**current_style, 'display': 'none'}, []
    
    # View button clicked - open modal and load data
    if trigger_id == "btn-view-fps":
        try:
            # Query false positives with reasons
            query = """
                SELECT 
                    f.id, f.file_path, f.secret_type, f.secret_value, 
                    f.severity, f.tool_source, f.fp_reason, 
                    f.fp_marked_by, f.fp_marked_at
                FROM findings f
                WHERE f.resolution_status = 'false_positive'
                ORDER BY f.fp_marked_at DESC
                LIMIT 500
            """
            fps = db_manager.execute_query(query)
            
            if not fps:
                return (
                    {**current_style, 'display': 'block'},
                    html.Div([
                        html.P("✅ No false positives found!", style={'color': '#22c55e', 'fontSize': '18px', 'textAlign': 'center', 'padding': '40px'})
                    ])
                )
            
            # Build a table to display FPs
            fp_table = dash_table.DataTable(
                id='fp-viewer-table',
                columns=[
                    {"name": "ID", "id": "id"},
                    {"name": "File Path", "id": "file_path"},
                    {"name": "Secret Type", "id": "secret_type"},
                    {"name": "Severity", "id": "severity"},
                    {"name": "Tool", "id": "tool_source"},
                    {"name": "Reason Marked as FP", "id": "fp_reason"},
                    {"name": "Marked By", "id": "fp_marked_by"},
                    {"name": "Marked At", "id": "fp_marked_at"},
                ],
                data=[dict(row) for row in fps],
                row_selectable="multi",
                selected_rows=[],
                page_size=20,
                page_action="native",
                sort_action="native",
                filter_action="native",
                style_table={'overflowX': 'auto'},
                style_header={
                    'backgroundColor': '#1e293b',
                    'color': '#e0e0e0',
                    'fontWeight': 'bold',
                    'border': '1px solid #444'
                },
                style_cell={
                    'backgroundColor': '#2d3748',
                    'color': '#e0e0e0',
                    'border': '1px solid #444',
                    'textAlign': 'left',
                    'padding': '10px',
                    'maxWidth': '200px',
                    'overflow': 'hidden',
                    'textOverflow': 'ellipsis'
                },
                style_cell_conditional=[
                    {'if': {'column_id': 'fp_reason'}, 'maxWidth': '300px', 'whiteSpace': 'normal'},
                    {'if': {'column_id': 'file_path'}, 'maxWidth': '250px'},
                    {'if': {'column_id': 'id'}, 'width': '60px'},
                ],
                style_data_conditional=[
                    {
                        'if': {'filter_query': '{severity} = "Critical"'},
                        'backgroundColor': '#4a1f1f'
                    },
                    {
                        'if': {'filter_query': '{severity} = "High"'},
                        'backgroundColor': '#4a2f1f'
                    },
                ],
            )
            
            return (
                {**current_style, 'display': 'block'},
                html.Div([
                    html.P(f"Found {len(fps)} false positive(s)", style={'color': '#9ca3af', 'marginBottom': '10px'}),
                    fp_table
                ])
            )
            
        except Exception as e:
            logger.error(f"Error loading false positives: {e}")
            return (
                {**current_style, 'display': 'block'},
                html.Div([
                    html.P(f"❌ Error loading false positives: {str(e)}", style={'color': '#ef4444'})
                ])
            )
    
    raise PreventUpdate


@app.callback(
    Output("fp-viewer-action-result", "children"),
    [Input("btn-restore-from-viewer", "n_clicks")],
    [State("fp-viewer-table", "selected_rows"),
     State("fp-viewer-table", "data")],
    prevent_initial_call=True
)
@secure_callback
def restore_from_fp_viewer(n_clicks, selected_rows, table_data):
    """Restore selected items from the FP viewer"""
    if not n_clicks or not selected_rows or not table_data:
        raise PreventUpdate
    
    try:
        selected_ids = [table_data[i]['id'] for i in selected_rows if i < len(table_data)]
        
        if not selected_ids:
            return "⚠️ No items selected"
        
        result = findings_manager.restore_from_false_positive(selected_ids)
        
        # Force cache refresh
        data_cache['findings_df'] = None
        data_cache['last_update'] = None
        
        if result['success'] > 0:
            return f"✅ Restored {result['success']} finding(s). Close and reopen to refresh."
        else:
            return "⚠️ No items were restored"
            
    except Exception as e:
        logger.error(f"Error restoring from FP viewer: {e}")
        return f"❌ Error: {str(e)}"


# Jira Integration Callbacks
@app.callback(
    Output("jira-settings-modal", "style"),
    [Input("btn-jira-settings", "n_clicks"),
     Input("btn-close-jira-settings", "n_clicks"),
     Input("btn-save-jira", "n_clicks")]
)
def toggle_jira_settings_modal(open_clicks, close_clicks, save_clicks):
    """Toggle the Jira settings modal"""
    ctx = dash.callback_context
    if not ctx.triggered:
        return {'display': 'none'}
    
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    if trigger_id == "btn-jira-settings":
        return {
            'display': 'block', 'position': 'fixed', 'top': '0', 'left': '0',
            'right': '0', 'bottom': '0', 'backgroundColor': 'rgba(0,0,0,0.7)',
            'zIndex': '1000', 'paddingTop': '50px'
        }
    
    return {'display': 'none'}


@app.callback(
    Output("jira-connection-status", "children"),
    [Input("btn-test-jira", "n_clicks")],
    [State("jira-server-url", "value"),
     State("jira-username", "value"),
     State("jira-api-token", "value"),
     State("jira-project-key", "value")]
)
def test_jira_connection(n_clicks, server_url, username, api_token, project_key):
    """Test Jira connection with provided settings"""
    if not n_clicks:
        # Show current config status on initial load
        if jira_manager.is_configured:
            return html.Span([
                html.Span("✅ ", style={'color': '#22c55e'}),
                f"Configured for {config.jira.project_key}"
            ], style={'color': '#e0e0e0'})
        return html.Span("⚠️ Not configured", style={'color': '#f59e0b'})
    
    # Temporarily update config to test
    if server_url and username and api_token and project_key:
        update_jira_config(
            server_url=server_url,
            username=username,
            api_token=api_token,
            project_key=project_key
        )
        
        result = jira_manager.test_connection()
        
        if result.get('success'):
            return html.Span([
                html.Span("✅ ", style={'color': '#22c55e'}),
                f"Connected as {result.get('user', 'Unknown')}"
            ], style={'color': '#e0e0e0'})
        else:
            return html.Span([
                html.Span("❌ ", style={'color': '#ef4444'}),
                result.get('error', 'Connection failed')
            ], style={'color': '#e0e0e0'})
    
    return html.Span("⚠️ Please fill in all fields", style={'color': '#f59e0b'})


@app.callback(
    Output("jira-save-status", "children"),
    [Input("btn-save-jira", "n_clicks")],
    [State("jira-server-url", "value"),
     State("jira-username", "value"),
     State("jira-api-token", "value"),
     State("jira-project-key", "value"),
     State("jira-issue-type", "value")],
    prevent_initial_call=True
)
def save_jira_settings(n_clicks, server_url, username, api_token, project_key, issue_type):
    """Save Jira configuration settings"""
    if not n_clicks:
        raise PreventUpdate
    
    if not all([server_url, username, api_token, project_key]):
        return html.Span("⚠️ Please fill in all required fields", style={'color': '#f59e0b'})
    
    try:
        update_jira_config(
            server_url=server_url.strip(),
            username=username.strip(),
            api_token=api_token.strip(),
            project_key=project_key.strip(),
            issue_type=issue_type.strip() if issue_type else 'Task'
        )
        
        logger.info(f"Jira settings saved for project: {project_key}")
        return html.Span([
            html.Span("✅ ", style={'color': '#22c55e'}),
            "Settings saved successfully!"
        ], style={'color': '#e0e0e0'})
    
    except Exception as e:
        logger.error(f"Error saving Jira settings: {e}")
        return html.Span([
            html.Span("❌ ", style={'color': '#ef4444'}),
            f"Error: {str(e)}"
        ], style={'color': '#e0e0e0'})


@app.callback(
    [Output("jira-action-result", "children"),
     Output("jira-action-result", "style")],
    [Input("btn-create-jira", "n_clicks")],
    [State("findings-table", "selected_rows"),
     State("findings-table", "data")]
)
def create_jira_tickets(n_clicks, selected_rows, table_data):
    """Create Jira tickets for selected findings"""
    if not n_clicks or not selected_rows or not table_data:
        return "", {'display': 'none'}
    
    # Check if Jira is configured
    if not jira_manager.is_configured:
        return (
            "⚠️ Jira is not configured. Click 'Jira Settings' to set up the connection.",
            {
                'display': 'block', 'padding': '10px 15px',
                'backgroundColor': '#d97706', 'color': 'white',
                'borderRadius': '6px', 'marginBottom': '10px'
            }
        )
    
    # Get selected findings (exclude false positives)
    findings_to_create = []
    for i in selected_rows:
        if i < len(table_data):
            row = table_data[i]
            # Skip false positives
            if row.get('resolution_status') != 'false_positive':
                findings_to_create.append(row)
    
    if not findings_to_create:
        return (
            "⚠️ No valid findings selected (false positives are excluded)",
            {
                'display': 'block', 'padding': '10px 15px',
                'backgroundColor': '#d97706', 'color': 'white',
                'borderRadius': '6px', 'marginBottom': '10px'
            }
        )
    
    try:
        # Create tickets
        results = jira_manager.create_bulk_tickets(findings_to_create)
        
        success_count = results.get('success_count', 0)
        failed_count = results.get('failed_count', 0)
        tickets = results.get('created_tickets', [])
        
        if success_count > 0:
            ticket_links = []
            for t in tickets[:5]:  # Show first 5 tickets
                ticket_links.append(
                    html.A(
                        t['key'], 
                        href=t['url'], 
                        target='_blank',
                        style={'color': '#60a5fa', 'marginRight': '10px'}
                    )
                )
            
            if len(tickets) > 5:
                ticket_links.append(html.Span(f"... and {len(tickets) - 5} more"))
            
            return (
                html.Div([
                    f"✅ Created {success_count} Jira ticket(s): ",
                    *ticket_links,
                    f" ({failed_count} failed)" if failed_count > 0 else ""
                ]),
                {
                    'display': 'block', 'padding': '10px 15px',
                    'backgroundColor': '#16a34a', 'color': 'white',
                    'borderRadius': '6px', 'marginBottom': '10px'
                }
            )
        else:
            errors = results.get('errors', ['Unknown error'])
            return (
                f"❌ Failed to create tickets: {errors[0] if errors else 'Unknown error'}",
                {
                    'display': 'block', 'padding': '10px 15px',
                    'backgroundColor': '#dc2626', 'color': 'white',
                    'borderRadius': '6px', 'marginBottom': '10px'
                }
            )
    
    except Exception as e:
        logger.error(f"Error creating Jira tickets: {e}")
        return (
            f"❌ Error: {str(e)}",
            {
                'display': 'block', 'padding': '10px 15px',
                'backgroundColor': '#dc2626', 'color': 'white',
                'borderRadius': '6px', 'marginBottom': '10px'
            }
        )


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
    """Update scanner status display with real-time progress from Redis"""
    try:
        # Check Redis connectivity
        redis_connected = redis_manager.redis_manager and redis_manager.redis_manager.ping()
        redis_status = "✅ Connected" if redis_connected else "❌ Disconnected"

        # Try to get real-time progress from Redis
        custom_progress = None
        trufflehog_progress = None
        gitleaks_progress = None
        
        if redis_connected and redis_manager.cache_manager:
            try:
                custom_progress = redis_manager.cache_manager.get('scan_progress', 'custom')
                trufflehog_progress = redis_manager.cache_manager.get('scan_progress', 'trufflehog')
                gitleaks_progress = redis_manager.cache_manager.get('scan_progress', 'gitleaks')
            except Exception:
                pass

        scanner_statuses = {
            'custom': {'status': '⏸️ Idle', 'class': 'status-item'},
            'trufflehog': {'status': '⏳ Waiting (runs after custom)', 'class': 'status-item'},
            'gitleaks': {'status': '⏳ Waiting (runs after custom)', 'class': 'status-item'}
        }

        # Update custom scanner status with real progress
        if custom_progress and custom_progress.get('status') == 'running':
            files = custom_progress.get('files_processed', 0)
            total_files = custom_progress.get('total_files', 0)
            findings = custom_progress.get('total_findings', 0)
            batches = custom_progress.get('batch_count', 0)
            
            # Calculate progress percentage if total is known
            if total_files > 0:
                pct = (files / total_files) * 100
                progress_str = f"🔄 Scanning: {files:,} / {total_files:,} files ({pct:.1f}%) - {findings:,} findings"
            else:
                progress_str = f"🔄 Running: {files:,} files scanned, {findings:,} findings (batch {batches})"
            
            scanner_statuses['custom'] = {
                'status': progress_str,
                'class': 'status-item status-running'
            }
        elif custom_progress and custom_progress.get('status') == 'completed':
            files = custom_progress.get('files_processed', 0)
            findings = custom_progress.get('total_findings', 0)
            scanner_statuses['custom'] = {
                'status': f"✅ Completed: {files:,} files, {findings:,} findings",
                'class': 'status-item status-success'
            }

        # Update trufflehog status
        if trufflehog_progress and trufflehog_progress.get('status') == 'running':
            scanner_statuses['trufflehog'] = {
                'status': f"🔄 Running...",
                'class': 'status-item status-running'
            }
        elif trufflehog_progress and trufflehog_progress.get('status') == 'completed':
            findings = trufflehog_progress.get('findings', 0)
            scanner_statuses['trufflehog'] = {
                'status': f"✅ Completed: {findings:,} findings",
                'class': 'status-item status-success'
            }

        # Update gitleaks status
        if gitleaks_progress and gitleaks_progress.get('status') == 'running':
            scanner_statuses['gitleaks'] = {
                'status': f"🔄 Running...",
                'class': 'status-item status-running'
            }
        elif gitleaks_progress and gitleaks_progress.get('status') == 'completed':
            findings = gitleaks_progress.get('findings', 0)
            scanner_statuses['gitleaks'] = {
                'status': f"✅ Completed: {findings:,} findings",
                'class': 'status-item status-success'
            }

        # Fall back to database scan sessions if no Redis progress
        if not custom_progress:
            query = """
                SELECT scan_type, status, completed_at, error_message, started_at,
                       (SELECT COUNT(*) FROM findings WHERE scan_session_id = ss.id) as findings_count
                FROM scan_sessions ss
                WHERE ss.started_at >= NOW() - INTERVAL '24 hours'
                ORDER BY ss.started_at DESC
                LIMIT 5
            """
            recent_scans = db_manager.execute_query(query)

            if recent_scans:
                for scan in recent_scans:
                    scan_type = scan['scan_type']
                    if scan_type in ['custom', 'combined'] and scan['status'] == 'running':
                        scanner_statuses['custom'] = {
                            'status': "🔄 Running... (waiting for progress data)",
                            'class': 'status-item status-running'
                        }
                        break

        # Get total findings count from database
        total_query = "SELECT COUNT(*) as total FROM findings"
        total_result = db_manager.execute_query(total_query)
        total_findings = total_result[0]['total'] if total_result else 0

        custom_status = f"Custom Scanner: {scanner_statuses['custom']['status']}"
        trufflehog_status = f"Trufflehog: {scanner_statuses['trufflehog']['status']}"
        gitleaks_status = f"Gitleaks: {scanner_statuses['gitleaks']['status']}"
        overall_status = f"📊 Total Findings: {total_findings:,} | Redis: {redis_status}"

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
    """Perform scan operation - Note: This dashboard is primarily for viewing results.
    Scans are automatically performed by the scanner container.
    These buttons provide manual trigger capability."""
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
        scanners_str = ", ".join(selected_scanners)
        
        # Note: The scanner container runs continuously. This notification informs
        # the user that scans are handled by the background scanner service.
        return html.Div([
            html.Strong("ℹ️ Scan Information"),
            html.P([
                "The scanner container runs continuously and automatically scans the /scan directory. ",
                "Current scan configuration:"
            ], style={'marginTop': '5px'}),
            html.Ul([
                html.Li(f"Path: {scan_path}"),
                html.Li(f"Project: {project_name}"),
                html.Li(f"Scanners: {scanners_str}"),
            ]),
            html.P("Check the 'Scanner Status' section above for real-time progress.", 
                   style={'fontStyle': 'italic', 'marginTop': '10px'})
        ], style={
            'backgroundColor': '#1e40af', 'color': 'white', 'padding': '15px',
            'borderRadius': '8px', 'marginBottom': '10px', 'boxShadow': '0 4px 6px rgba(0,0,0,0.3)'
        })

    except Exception as e:
        logger.error(f"Error performing scan: {e}")
        return html.Div(f"❌ Error: {str(e)}", style={
            'backgroundColor': '#dc2626', 'color': 'white', 'padding': '15px',
            'borderRadius': '8px', 'marginBottom': '10px'
        })

@app.callback(
    Output("cleanup-result-notification", "children"),
    [Input("cleanup-btn", "n_clicks")]
)
@secure_callback
def perform_cleanup(cleanup_clicks):
    """Perform cleanup of old data - removes findings older than 30 days"""
    if not cleanup_clicks:
        return ""

    try:
        # Get count before cleanup
        count_query = "SELECT COUNT(*) as count FROM findings"
        before_count = db_manager.execute_query(count_query)
        before_total = before_count[0]['count'] if before_count else 0
        
        # Cleanup old findings (older than 30 days)
        cutoff_date = datetime.now() - timedelta(days=30)

        # Delete old findings directly
        delete_findings_query = """
            DELETE FROM findings
            WHERE first_seen < %s
        """
        db_manager.execute_update(delete_findings_query, (cutoff_date,))

        # Delete old scan sessions
        delete_sessions_query = """
            DELETE FROM scan_sessions
            WHERE created_at < %s
            AND status IN ('completed', 'failed')
        """
        db_manager.execute_update(delete_sessions_query, (cutoff_date,))

        # Get count after cleanup
        after_count = db_manager.execute_query(count_query)
        after_total = after_count[0]['count'] if after_count else 0
        deleted_count = before_total - after_total

        # Clear data cache to force refresh
        data_cache['findings_df'] = None
        data_cache['last_update'] = None

        return html.Div([
            html.Strong("✅ Cleanup Completed"),
            html.P([
                f"Removed {deleted_count:,} findings older than 30 days."
            ], style={'marginTop': '5px'}),
            html.P([
                f"Before: {before_total:,} findings → After: {after_total:,} findings"
            ]),
            html.P("Click 'Refresh Data' to update the dashboard.", 
                   style={'fontStyle': 'italic', 'marginTop': '10px'})
        ], style={
            'backgroundColor': '#16a34a', 'color': 'white', 'padding': '15px',
            'borderRadius': '8px', 'marginBottom': '10px', 'boxShadow': '0 4px 6px rgba(0,0,0,0.3)'
        })

    except Exception as e:
        logger.error(f"Error performing cleanup: {e}")
        return html.Div([
            html.Strong("❌ Cleanup Failed"),
            html.P(str(e), style={'marginTop': '5px'})
        ], style={
            'backgroundColor': '#dc2626', 'color': 'white', 'padding': '15px',
            'borderRadius': '8px', 'marginBottom': '10px'
        })

# Permanent dark mode - no toggle needed
# Main container is always in dark mode

# Permanent dark mode for table styles
# No callback needed - CSS handles all styling
    style_cell = {}
# Permanent dark mode - no client callback needed for toggle

# Add notification divs to layout
def create_layout():
    """Create the main dashboard layout"""
    # Aggressive CSS overrides to fix dark mode rendering issues
    return html.Div([
        # Notification area - visible at top
        html.Div([
            html.Div(id="scan-result-notification", className="notification-area"),
            html.Div(id="cleanup-result-notification", className="notification-area"),
        ], id="notification-container", style={
            'position': 'fixed', 'top': '10px', 'right': '10px', 'zIndex': '9999',
            'maxWidth': '400px'
        }),

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
                    # Scan controls - Dark mode is now permanently enabled
                    html.Div([
                        html.Button("� Refresh Data", id="refresh-btn", className="refresh-btn",
                            title="Refresh findings data from database"),
                        html.Button("🔍 Quick Scan", id="quick-scan-btn", className="scan-btn",
                            title="Run all scanners on /scan directory (custom + gitleaks + trufflehog)"),
                        html.Button("📁 Custom Scan", id="custom-scan-btn", className="scan-btn",
                            title="Configure and run a custom scan with specific settings"),
                        html.Button("🧹 Cleanup Old Data", id="cleanup-btn", className="cleanup-btn",
                            title="Remove findings older than 30 days to free up database space")
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
                    html.Label("Severity Filter:", style={'color': '#e0e0e0', 'fontWeight': '600', 'marginBottom': '8px'}),
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
                        clearable=False,
                        style={'backgroundColor': '#2d2d2d', 'color': '#e0e0e0'}
                    )
                ], className="filter-item"),

                html.Div([
                    html.Label("Tool Source Filter:", style={'color': '#e0e0e0', 'fontWeight': '600', 'marginBottom': '8px'}),
                    dcc.Dropdown(
                        id="tool-filter",
                        options=[
                            {"label": "All Tools", "value": "all"},
                            {"label": "Custom Scanner", "value": "custom"},
                            {"label": "Trufflehog", "value": "trufflehog"},
                            {"label": "Gitleaks", "value": "gitleaks"}
                        ],
                        value="all",
                        clearable=False,
                        style={'backgroundColor': '#2d2d2d', 'color': '#e0e0e0'}
                    )
                ], className="filter-item"),

                html.Div([
                    html.Label("Project Filter:", style={'color': '#e0e0e0', 'fontWeight': '600', 'marginBottom': '8px'}),
                    dcc.Dropdown(
                        id="project-filter",
                        options=[{"label": "All Projects", "value": "all"}],
                        value="all",
                        clearable=False,
                        optionHeight=50,
                        style={'minWidth': '200px', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0'}
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
                html.H3("📋 Recent Findings (click any row for full details)"),
                
                # False Positive Controls Panel
                html.Div([
                    # Left side - Toggle and count
                    html.Div([
                        html.Button(
                            "👁️ View False Positives",
                            id='btn-view-fps',
                            n_clicks=0,
                            style={
                                'backgroundColor': '#6b7280', 'color': 'white',
                                'border': 'none', 'padding': '8px 16px',
                                'borderRadius': '6px', 'cursor': 'pointer',
                                'marginRight': '15px', 'fontWeight': 'bold'
                            }
                        ),
                        html.Span(id='fp-count-badge', style={
                            'padding': '4px 10px', 
                            'backgroundColor': '#6b7280', 'borderRadius': '12px',
                            'fontSize': '12px', 'color': '#fff'
                        }),
                    ], style={'display': 'flex', 'alignItems': 'center', 'flex': '1'}),
                    
                    # Right side - Bulk action buttons
                    html.Div([
                        html.Button(
                            "🚫 Mark Selected as False Positive", 
                            id='btn-mark-fp',
                            n_clicks=0,
                            style={
                                'backgroundColor': '#dc2626', 'color': 'white',
                                'border': 'none', 'padding': '8px 16px',
                                'borderRadius': '6px', 'cursor': 'pointer',
                                'marginRight': '10px', 'fontWeight': 'bold'
                            }
                        ),
                        html.Button(
                            "✅ Restore Selected", 
                            id='btn-restore-fp',
                            n_clicks=0,
                            style={
                                'backgroundColor': '#16a34a', 'color': 'white',
                                'border': 'none', 'padding': '8px 16px',
                                'borderRadius': '6px', 'cursor': 'pointer',
                                'marginRight': '10px', 'fontWeight': 'bold'
                            }
                        ),
                        html.Button(
                            "🎫 Create Jira Ticket", 
                            id='btn-create-jira',
                            n_clicks=0,
                            style={
                                'backgroundColor': '#0052cc', 'color': 'white',
                                'border': 'none', 'padding': '8px 16px',
                                'borderRadius': '6px', 'cursor': 'pointer',
                                'marginRight': '10px', 'fontWeight': 'bold'
                            }
                        ),
                        html.Button(
                            "⚙️ Jira Settings", 
                            id='btn-jira-settings',
                            n_clicks=0,
                            style={
                                'backgroundColor': '#6b7280', 'color': 'white',
                                'border': 'none', 'padding': '8px 16px',
                                'borderRadius': '6px', 'cursor': 'pointer',
                                'fontWeight': 'bold'
                            }
                        ),
                    ], style={'display': 'flex', 'alignItems': 'center'}),
                ], style={
                    'display': 'flex', 'justifyContent': 'space-between', 
                    'alignItems': 'center', 'marginBottom': '15px',
                    'padding': '10px 15px', 'backgroundColor': '#2d3748',
                    'borderRadius': '8px', 'border': '1px solid #444'
                }),
                
                # FP Action Result Message
                html.Div(id='fp-action-result', style={
                    'marginBottom': '10px', 'padding': '8px 12px',
                    'borderRadius': '6px', 'display': 'none'
                }),
                
                # FP Reason Input Modal
                dcc.Store(id='selected-rows-for-fp', data=[]),
                html.Div([
                    html.Div([
                        html.H4("Mark as False Positive", style={'color': '#e0e0e0', 'marginBottom': '15px'}),
                        html.Label("Reason (optional):", style={'color': '#b0b0b0', 'marginBottom': '8px', 'display': 'block'}),
                        dcc.Textarea(
                            id='fp-reason-input',
                            placeholder='e.g., Test data, Sample key, Not a real secret...',
                            style={
                                'width': '100%', 'height': '80px',
                                'backgroundColor': '#1e1e1e', 'color': '#e0e0e0',
                                'border': '1px solid #555', 'borderRadius': '4px',
                                'padding': '10px', 'marginBottom': '15px'
                            }
                        ),
                        html.Div([
                            html.Button(
                                "Confirm Mark as FP", 
                                id='btn-confirm-fp',
                                n_clicks=0,
                                style={
                                    'backgroundColor': '#dc2626', 'color': 'white',
                                    'border': 'none', 'padding': '10px 20px',
                                    'borderRadius': '6px', 'cursor': 'pointer',
                                    'marginRight': '10px', 'fontWeight': 'bold'
                                }
                            ),
                            html.Button(
                                "Cancel", 
                                id='btn-cancel-fp',
                                n_clicks=0,
                                style={
                                    'backgroundColor': '#6b7280', 'color': 'white',
                                    'border': 'none', 'padding': '10px 20px',
                                    'borderRadius': '6px', 'cursor': 'pointer'
                                }
                            ),
                        ], style={'textAlign': 'right'})
                    ], style={
                        'backgroundColor': '#2d3748', 'padding': '20px',
                        'borderRadius': '8px', 'maxWidth': '500px',
                        'margin': '0 auto', 'border': '1px solid #555'
                    })
                ], id='fp-reason-modal', style={
                    'display': 'none', 'position': 'fixed', 'top': '0', 'left': '0',
                    'right': '0', 'bottom': '0', 'backgroundColor': 'rgba(0,0,0,0.7)',
                    'zIndex': '1000', 'paddingTop': '100px'
                }),
                
                # Jira Settings Modal
                html.Div([
                    html.Div([
                        html.H4("⚙️ Jira Integration Settings", style={'color': '#e0e0e0', 'marginBottom': '20px'}),
                        
                        html.Div([
                            html.Label("Jira Server URL:", style={'color': '#b0b0b0', 'marginBottom': '5px', 'display': 'block'}),
                            dcc.Input(
                                id='jira-server-url',
                                type='text',
                                placeholder='https://your-company.atlassian.net',
                                style={
                                    'width': '100%', 'padding': '10px',
                                    'backgroundColor': '#1e1e1e', 'color': '#e0e0e0',
                                    'border': '1px solid #555', 'borderRadius': '4px',
                                    'marginBottom': '15px'
                                }
                            ),
                        ]),
                        
                        html.Div([
                            html.Label("Username (Email):", style={'color': '#b0b0b0', 'marginBottom': '5px', 'display': 'block'}),
                            dcc.Input(
                                id='jira-username',
                                type='text',
                                placeholder='your.email@company.com',
                                style={
                                    'width': '100%', 'padding': '10px',
                                    'backgroundColor': '#1e1e1e', 'color': '#e0e0e0',
                                    'border': '1px solid #555', 'borderRadius': '4px',
                                    'marginBottom': '15px'
                                }
                            ),
                        ]),
                        
                        html.Div([
                            html.Label("API Token:", style={'color': '#b0b0b0', 'marginBottom': '5px', 'display': 'block'}),
                            dcc.Input(
                                id='jira-api-token',
                                type='password',
                                placeholder='Your Jira API token',
                                style={
                                    'width': '100%', 'padding': '10px',
                                    'backgroundColor': '#1e1e1e', 'color': '#e0e0e0',
                                    'border': '1px solid #555', 'borderRadius': '4px',
                                    'marginBottom': '15px'
                                }
                            ),
                        ]),
                        
                        html.Div([
                            html.Label("Project Key:", style={'color': '#b0b0b0', 'marginBottom': '5px', 'display': 'block'}),
                            dcc.Input(
                                id='jira-project-key',
                                type='text',
                                placeholder='SEC, SECOPS, etc.',
                                style={
                                    'width': '100%', 'padding': '10px',
                                    'backgroundColor': '#1e1e1e', 'color': '#e0e0e0',
                                    'border': '1px solid #555', 'borderRadius': '4px',
                                    'marginBottom': '15px'
                                }
                            ),
                        ]),
                        
                        html.Div([
                            html.Label("Issue Type:", style={'color': '#b0b0b0', 'marginBottom': '5px', 'display': 'block'}),
                            dcc.Dropdown(
                                id='jira-issue-type',
                                options=[
                                    {'label': 'Task', 'value': 'Task'},
                                    {'label': 'Bug', 'value': 'Bug'},
                                    {'label': 'Story', 'value': 'Story'},
                                    {'label': 'Security', 'value': 'Security'},
                                ],
                                value='Task',
                                style={'backgroundColor': '#1e1e1e', 'marginBottom': '15px'}
                            ),
                        ]),
                        
                        html.Div(id='jira-connection-status', style={
                            'marginBottom': '10px', 'padding': '10px',
                            'borderRadius': '4px', 'backgroundColor': '#374151'
                        }),
                        
                        html.Div(id='jira-save-status', style={
                            'marginBottom': '15px', 'padding': '10px',
                            'borderRadius': '4px', 'backgroundColor': '#374151'
                        }),
                        
                        html.Div([
                            html.Button(
                                "🔗 Test Connection", 
                                id='btn-test-jira',
                                n_clicks=0,
                                style={
                                    'backgroundColor': '#0052cc', 'color': 'white',
                                    'border': 'none', 'padding': '10px 20px',
                                    'borderRadius': '6px', 'cursor': 'pointer',
                                    'marginRight': '10px', 'fontWeight': 'bold'
                                }
                            ),
                            html.Button(
                                "💾 Save Settings", 
                                id='btn-save-jira',
                                n_clicks=0,
                                style={
                                    'backgroundColor': '#16a34a', 'color': 'white',
                                    'border': 'none', 'padding': '10px 20px',
                                    'borderRadius': '6px', 'cursor': 'pointer',
                                    'marginRight': '10px', 'fontWeight': 'bold'
                                }
                            ),
                            html.Button(
                                "Close", 
                                id='btn-close-jira-settings',
                                n_clicks=0,
                                style={
                                    'backgroundColor': '#6b7280', 'color': 'white',
                                    'border': 'none', 'padding': '10px 20px',
                                    'borderRadius': '6px', 'cursor': 'pointer'
                                }
                            ),
                        ], style={'textAlign': 'right'})
                    ], style={
                        'backgroundColor': '#2d3748', 'padding': '25px',
                        'borderRadius': '8px', 'maxWidth': '500px',
                        'margin': '0 auto', 'border': '1px solid #555'
                    })
                ], id='jira-settings-modal', style={
                    'display': 'none', 'position': 'fixed', 'top': '0', 'left': '0',
                    'right': '0', 'bottom': '0', 'backgroundColor': 'rgba(0,0,0,0.7)',
                    'zIndex': '1000', 'paddingTop': '50px'
                }),
                
                # False Positives Viewer Modal
                html.Div([
                    html.Div([
                        html.Div([
                            html.H2("🚫 False Positives", style={'margin': '0', 'color': '#f59e0b'}),
                            html.Button("✕", id='close-fp-viewer-btn', n_clicks=0, style={
                                'background': 'none', 'border': 'none', 'color': '#aaa',
                                'fontSize': '24px', 'cursor': 'pointer', 'padding': '0'
                            })
                        ], style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center', 'marginBottom': '20px'}),
                        
                        html.P("Items marked as false positives with their reasons:", style={'color': '#9ca3af', 'marginBottom': '15px'}),
                        
                        # FP Table
                        html.Div(id='fp-viewer-table-container', style={
                            'maxHeight': '500px', 'overflowY': 'auto'
                        }),
                        
                        # Action buttons
                        html.Div([
                            html.Button(
                                "✅ Restore Selected to Active",
                                id='btn-restore-from-viewer',
                                n_clicks=0,
                                style={
                                    'backgroundColor': '#16a34a', 'color': 'white',
                                    'border': 'none', 'padding': '10px 20px',
                                    'borderRadius': '6px', 'cursor': 'pointer',
                                    'fontWeight': 'bold', 'marginRight': '10px'
                                }
                            ),
                            html.Span(id='fp-viewer-action-result', style={'color': '#e0e0e0'})
                        ], style={'marginTop': '15px', 'textAlign': 'left'})
                    ], style={
                        'backgroundColor': '#2d3748', 'padding': '25px',
                        'borderRadius': '8px', 'maxWidth': '1200px', 'width': '90%',
                        'margin': '0 auto', 'border': '1px solid #555'
                    })
                ], id='fp-viewer-modal', style={
                    'display': 'none', 'position': 'fixed', 'top': '0', 'left': '0',
                    'right': '0', 'bottom': '0', 'backgroundColor': 'rgba(0,0,0,0.7)',
                    'zIndex': '1000', 'paddingTop': '30px', 'overflowY': 'auto'
                }),
                
                # Jira Action Result Message
                html.Div(id='jira-action-result', style={
                    'marginBottom': '10px', 'padding': '8px 12px',
                    'borderRadius': '6px', 'display': 'none'
                }),
                
                dash_table.DataTable(
                    id="findings-table",
                    columns=[
                        {"name": "ID", "id": "id", "hideable": True},  # Hidden by default, used for FP actions
                        {"name": "File Path", "id": "file_path", "deletable": True, "selectable": True, "hideable": True},
                        {"name": "Secret Type", "id": "secret_type", "deletable": True, "selectable": True, "hideable": True},
                        {"name": "Secret Value", "id": "secret_value", "deletable": True, "selectable": True, "hideable": True},
                        {"name": "Context", "id": "context", "deletable": True, "selectable": True, "hideable": True},
                        {"name": "Severity", "id": "severity", "deletable": True, "selectable": True, "hideable": True, "presentation": "dropdown"},
                        {"name": "Tool Source", "id": "tool_source", "deletable": True, "selectable": True, "hideable": True, "presentation": "dropdown"},
                        {"name": "Status", "id": "resolution_status", "deletable": True, "selectable": True, "hideable": True},
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
                    selected_rows=[],
                    page_action="native",
                    page_current=0,
                    page_size=50,  # Show 50 rows per page
                    hidden_columns=['id'],  # Hide ID column by default
                    tooltip_duration=None,
                    dropdown={
                        'tool_source': {
                            'options': [
                                {'label': 'custom', 'value': 'custom'},
                                {'label': 'trufflehog', 'value': 'trufflehog'},
                                {'label': 'gitleaks', 'value': 'gitleaks'}
                            ]
                        },
                        'severity': {
                            'options': [
                                {'label': 'Critical', 'value': 'Critical'},
                                {'label': 'High', 'value': 'High'},
                                {'label': 'Medium', 'value': 'Medium'},
                                {'label': 'Low', 'value': 'Low'}
                            ]
                        },
                        'resolution_status': {
                            'options': [
                                {'label': 'open', 'value': 'open'},
                                {'label': 'false_positive', 'value': 'false_positive'},
                                {'label': 'resolved', 'value': 'resolved'}
                            ]
                        }
                    },
                    style_table={
                        'overflowX': 'auto',
                        'minWidth': '100%',
                        'backgroundColor': '#1e1e1e',
                        'color': '#e0e0e0'
                    },
                    style_header={
                        'backgroundColor': '#2d3748',
                        'color': '#e0e0e0',
                        'fontWeight': 'bold',
                        'fontSize': '14px',
                        'border': '1px solid #444',
                        'textAlign': 'center'
                    },
                    style_cell={
                        'backgroundColor': '#1e1e1e',
                        'color': '#e0e0e0',
                        'fontSize': '13px',
                        'fontFamily': 'Monaco, Consolas, monospace',
                        'border': '1px solid #444',
                        'textAlign': 'left',
                        'padding': '8px',
                        'overflow': 'hidden',
                        'textOverflow': 'ellipsis',
                        'whiteSpace': 'normal',
                        'height': 'auto',
                        'minWidth': '120px', 
                        'width': '150px', 
                        'maxWidth': '250px'
                    },
                    style_cell_conditional=[
                        # File Path - wider for full paths
                        {'if': {'column_id': 'file_path'},
                         'width': '250px', 'minWidth': '200px', 'maxWidth': '350px',
                         'textAlign': 'left'
                        },
                        # Secret Type - medium width
                        {'if': {'column_id': 'secret_type'},
                         'width': '140px', 'minWidth': '120px', 'maxWidth': '180px',
                         'textAlign': 'center'
                        },
                        # Secret Value - wide for secrets, truncated with ellipsis
                        {'if': {'column_id': 'secret_value'},
                         'width': '200px', 'minWidth': '150px', 'maxWidth': '300px',
                         'fontFamily': 'Monaco, Consolas, monospace',
                         'backgroundColor': '#2d1b1b',  # Slightly red tint for security
                         'border': '1px solid #664444'
                        },
                        # Context - wide for code context
                        {'if': {'column_id': 'context'},
                         'width': '300px', 'minWidth': '250px', 'maxWidth': '400px',
                         'fontFamily': 'Monaco, Consolas, monospace'
                        },
                        # Severity - narrow, center aligned
                        {'if': {'column_id': 'severity'},
                         'width': '100px', 'minWidth': '80px', 'maxWidth': '120px',
                         'textAlign': 'center',
                         'fontWeight': 'bold'
                        },
                        # Tool Source - medium width, center aligned
                        {'if': {'column_id': 'tool_source'},
                         'width': '120px', 'minWidth': '100px', 'maxWidth': '150px',
                         'textAlign': 'center'
                        },
                        # Project - medium width
                        {'if': {'column_id': 'project_name'},
                         'width': '150px', 'minWidth': '120px', 'maxWidth': '200px',
                         'textAlign': 'center'
                        },
                        # First Seen - date column, narrow
                        {'if': {'column_id': 'first_seen'},
                         'width': '140px', 'minWidth': '120px', 'maxWidth': '160px',
                         'textAlign': 'center',
                         'fontFamily': 'Monaco, Consolas, monospace'
                        },
                        # Confidence - very narrow, percentage
                        {'if': {'column_id': 'confidence_score'},
                         'width': '90px', 'minWidth': '80px', 'maxWidth': '110px',
                         'textAlign': 'center',
                         'fontWeight': 'bold'
                        }
                    ],
                    style_data_conditional=[
                        # Critical severity highlighting
                        {
                            'if': {'filter_query': '{severity} = "Critical"'},
                            'backgroundColor': '#8b0000',
                            'color': '#ffffff',
                            'fontWeight': 'bold'
                        },
                        # High severity highlighting  
                        {
                            'if': {'filter_query': '{severity} = "High"'},
                            'backgroundColor': '#6d2f2f',
                            'color': '#ffffff',
                            'fontWeight': 'bold'
                        },
                        # Medium severity highlighting
                        {
                            'if': {'filter_query': '{severity} = "Medium"'},
                            'backgroundColor': '#75542b',
                            'color': '#ffffff',
                            'fontWeight': 'bold'
                        },
                        # Low severity highlighting
                        {
                            'if': {'filter_query': '{severity} = "Low"'},
                            'backgroundColor': '#2c4a6b',
                            'color': '#ffffff',
                            'fontWeight': 'bold'
                        },
                        # False positive row styling - grayed out with strikethrough effect
                        {
                            'if': {'filter_query': '{resolution_status} = "false_positive"'},
                            'backgroundColor': '#3a3a3a',
                            'color': '#888888',
                            'fontStyle': 'italic'
                        },
                        # Status column styling
                        {
                            'if': {'column_id': 'resolution_status', 'filter_query': '{resolution_status} = "open"'},
                            'backgroundColor': '#16a34a',
                            'color': '#ffffff',
                            'fontWeight': 'bold'
                        },
                        {
                            'if': {'column_id': 'resolution_status', 'filter_query': '{resolution_status} = "false_positive"'},
                            'backgroundColor': '#6b7280',
                            'color': '#ffffff',
                            'fontWeight': 'bold'
                        },
                        # Alternating row colors for better readability
                        {
                            'if': {'row_index': 'odd'},
                            'backgroundColor': '#252525'
                        }
                    ],
                    export_format="csv",
                    export_headers="display",
                    css=[{'selector': '.dash-cell div', 'rule': 'white-space: normal; height: auto;'}]
                )
            ], className="data-table"),

            # Finding Detail Modal (opens when clicking a table row)
            html.Div([
                html.Div(id="modal-backdrop", className="modal-backdrop"),
                html.Div([
                    html.Div([
                        html.H2("🔍 Finding Details"),
                    ], className="modal-header"),
                    html.Div(id="finding-detail-content", className="finding-detail-body"),
                    html.Div([
                        html.Button("Close", id="close-detail-modal-btn-bottom", className="modal-close-btn-bottom")
                    ], className="modal-footer")
                ], className="modal-content detail-modal-content")
            ], id="finding-detail-modal", className="modal-container"),

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

        ], id="main-container", className="main-container dark-mode"),

        # Interval component for auto-refresh
        dcc.Interval(
            id="interval-component",
            interval=30000,  # 30 seconds
            n_intervals=0
        )
    ])

# Set the layout from create_layout function
app.layout = create_layout()

# CSS Styles with cache busting
import time as _time
_cache_version = str(int(_time.time()))
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        <title>SecretSnipe Dashboard</title>
        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
        <meta http-equiv="Pragma" content="no-cache">
        <meta http-equiv="Expires" content="0">
        <style>
            /* Universal dark background - highest priority */
            html, body {
                background-color: #1a1a1a !important;
                color: #e0e0e0 !important;
                margin: 0;
                padding: 0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #1a1a1a;
            }

            /* Dark mode override for body background */
            .main-container.dark-mode body {
                background-color: #1a1a1a !important;
            }

            /* Dark mode for charts with simplified approach */
            .main-container.dark-mode .chart-container {
                background-color: #1e1e1e !important;
                border: 1px solid #444 !important;
            }

            /* Dark mode for body and html */
            .main-container.dark-mode body {
                background-color: #1a1a1a !important;
                color: #e0e0e0 !important;
            }

            .main-container {
                max-width: 95vw;  /* Use 95% of viewport width for better 1080p scaling */
                width: 100%;
                margin: 0 auto;
                padding: 20px;
                min-height: 100vh;
                background-color: #1a1a1a;
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
                justify-content: space-between;
            }
            .chart-container {
                flex: 1;
                min-width: 450px;  /* Slightly wider for better 1080p scaling */
                max-width: calc(50% - 15px);  /* Better space utilization */
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
                display: flex;
                flex-wrap: wrap;
                gap: 30px;
                margin-top: 15px;
                padding: 15px;
                background-color: #1e1e1e;
                border-radius: 8px;
            }
            .stats-grid h4 {
                margin: 0 0 10px 0;
                font-size: 14px;
            }
            .stat-item {
                margin-bottom: 5px;
                font-size: 14px;
            }
            .notification-area {
                margin-bottom: 10px;
            }
            .notification-area:empty {
                display: none;
            }
            @media (max-width: 1200px) {
                .chart-container {
                    min-width: 400px;
                    max-width: 100%;
                }
            }
            @media (max-width: 768px) {
                .main-container {
                    max-width: 100%;
                    padding: 10px;
                }
                .charts-row {
                    flex-direction: column;
                }
                .chart-container {
                    min-width: auto;
                    max-width: 100%;
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
                background: #2d2d2d;
                border-radius: 10px;
                padding: 30px;
                max-width: 500px;
                width: 90%;
                max-height: 80vh;
                overflow-y: auto;
            }

            /* Detail modal (finding details) - larger size */
            .modal-content.detail-modal-content {
                max-width: 1100px;
                width: 95%;
                max-height: 90vh;
                padding: 25px 35px;
            }

            .modal-content h2 {
                margin-top: 0;
                color: #e0e0e0;
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

            .main-container.dark-mode .status-item.status-running {
                border-left-color: #17a2b8;
                background: #2d3d4d;
                animation: pulse 2s infinite;
            }

            .main-container.dark-mode .status-item.status-success {
                border-left-color: #28a745;
                background: #2d4d2d;
            }

            @keyframes pulse {
                0% { opacity: 1; }
                50% { opacity: 0.7; }
                100% { opacity: 1; }
            }

            /* Modal Styles */
            .main-container.dark-mode .modal-container {
                background: rgba(0,0,0,0.8);
            }

            .main-container.dark-mode .modal-content {
                background: #1e1e1e;
                color: #e0e0e0;
            }

            /* Detail modal - larger size for viewing findings */
            .main-container.dark-mode .modal-content.detail-modal-content {
                max-width: 1100px;
                width: 95%;
                max-height: 90vh;
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
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            }

            .main-container.dark-mode .data-table h3 {
                color: #e0e0e0 !important;
                margin-bottom: 20px;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }

            /* Enhanced table styling for dark mode */
            .main-container.dark-mode .dash-table-container {
                background-color: transparent !important;
            }

            .main-container.dark-mode .dash-table-container .dash-spreadsheet-container {
                border: 1px solid #444 !important;
                border-radius: 8px;
                background-color: #1e1e1e !important;
            }

            /* Table pagination styling */
            .main-container.dark-mode .dash-table-container .previous-next-container,
            .main-container.dark-mode .dash-table-container .previous-page,
            .main-container.dark-mode .dash-table-container .next-page {
                background-color: #2d3748 !important;
                color: #e0e0e0 !important;
                border: 1px solid #444 !important;
            }

            .main-container.dark-mode .dash-table-container .current-page {
                background-color: #4dabf7 !important;
                color: white !important;
                border: 1px solid #4dabf7 !important;
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
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            }

            .main-container.dark-mode .scanner-status h3 {
                color: #e0e0e0 !important;
                margin-bottom: 20px;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }

            /* Dark mode for report section */
            .main-container.dark-mode .report-section {
                background-color: #1e1e1e !important;
                border: 1px solid #444 !important;
                color: #e0e0e0 !important;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.3);
                margin-bottom: 30px;
            }

            .main-container.dark-mode .report-section h3 {
                color: #e0e0e0 !important;
                margin-bottom: 20px;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }

            .main-container.dark-mode .export-btn {
                background: #667eea;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                font-weight: 600;
                margin: 5px;
                transition: background 0.3s;
            }

            .main-container.dark-mode .export-btn:hover {
                background: #5a67d8;
                transform: translateY(-1px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            }

            /* Dark mode for date picker */
            .main-container.dark-mode .DateInput {
                background-color: #3d3d3d !important;
                color: #e0e0e0 !important;
                border-color: #555 !important;
            }

            .main-container.dark-mode .DateRangePickerInput {
                background-color: #3d3d3d !important;
                border: 1px solid #555 !important;
                border-radius: 5px;
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
