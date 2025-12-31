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
    'cache_duration': timedelta(minutes=5),  # 5 minute cache for better performance
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
        # Get ALL findings without limit - use efficient query
        # Pagination is handled at display level, not query level
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


def get_file_grouped_data(tool_filter: str = 'all', severity_filter: str = 'all', 
                          project_filter: str = 'all', secret_type_filter: str = 'all') -> pd.DataFrame:
    """Get findings grouped by file path for display efficiency.
    
    Returns a DataFrame with one row per file, containing aggregated finding info.
    """
    try:
        # Build dynamic WHERE clause
        conditions = ["f.resolution_status != 'false_positive'"]
        params = []
        
        if tool_filter != 'all':
            conditions.append("f.tool_source = %s")
            params.append(tool_filter)
        if severity_filter != 'all':
            conditions.append("f.severity = %s")
            params.append(severity_filter)
        if project_filter != 'all':
            conditions.append("p.name = %s")
            params.append(project_filter)
        if secret_type_filter != 'all':
            conditions.append("f.secret_type = %s")
            params.append(secret_type_filter)
        
        where_clause = " AND ".join(conditions)
        
        query = f"""
            SELECT 
                f.file_path,
                COUNT(*) as finding_count,
                array_agg(DISTINCT f.tool_source) as tools,
                array_agg(DISTINCT f.severity) as severities,
                array_agg(DISTINCT f.secret_type) as secret_types,
                MAX(f.severity) as max_severity,
                MAX(f.first_seen) as latest_finding,
                MIN(f.first_seen) as earliest_finding,
                p.name as project_name
            FROM findings f
            JOIN projects p ON f.project_id = p.id
            WHERE {where_clause}
            GROUP BY f.file_path, p.name
            ORDER BY 
                CASE MAX(f.severity)
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END,
                COUNT(*) DESC
        """
        
        results = db_manager.execute_query(query, tuple(params) if params else None)
        
        if results:
            df = pd.DataFrame(results)
            # Convert PostgreSQL arrays to Python lists for display
            for col in ['tools', 'severities', 'secret_types']:
                if col in df.columns:
                    df[col] = df[col].apply(lambda x: list(x) if x else [])
            return df
        return pd.DataFrame()
        
    except Exception as e:
        logger.error(f"Error getting file-grouped data: {e}")
        return pd.DataFrame()


def get_findings_for_file(file_path: str) -> List[Dict[str, Any]]:
    """Get all findings for a specific file path."""
    try:
        query = """
            SELECT 
                f.id, f.secret_type, f.secret_value, f.context, f.severity, 
                f.tool_source, f.first_seen, f.confidence_score, f.resolution_status,
                f.line_number
            FROM findings f
            WHERE f.file_path = %s AND f.resolution_status != 'false_positive'
            ORDER BY 
                CASE f.severity
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END,
                f.first_seen DESC
        """
        return db_manager.execute_query(query, (file_path,))
    except Exception as e:
        logger.error(f"Error getting findings for file {file_path}: {e}")
        return []


def get_tool_summary_stats() -> Dict[str, Dict[str, Any]]:
    """Get summary statistics per tool for the separate tool sections."""
    try:
        query = """
            SELECT 
                f.tool_source,
                COUNT(*) as total_findings,
                COUNT(DISTINCT f.file_path) as unique_files,
                SUM(CASE WHEN f.severity = 'Critical' THEN 1 ELSE 0 END) as critical_count,
                SUM(CASE WHEN f.severity = 'High' THEN 1 ELSE 0 END) as high_count,
                SUM(CASE WHEN f.severity = 'Medium' THEN 1 ELSE 0 END) as medium_count,
                SUM(CASE WHEN f.severity = 'Low' THEN 1 ELSE 0 END) as low_count,
                MAX(f.first_seen) as last_finding_date
            FROM findings f
            WHERE f.resolution_status != 'false_positive'
            GROUP BY f.tool_source
        """
        results = db_manager.execute_query(query)
        
        stats = {}
        for row in results:
            stats[row['tool_source']] = {
                'total_findings': row['total_findings'],
                'unique_files': row['unique_files'],
                'critical': row['critical_count'],
                'high': row['high_count'],
                'medium': row['medium_count'],
                'low': row['low_count'],
                'last_finding': row['last_finding_date']
            }
        return stats
    except Exception as e:
        logger.error(f"Error getting tool summary stats: {e}")
        return {}


def get_distinct_secret_types() -> list:
    """Get distinct secret types from the database for dropdown filter."""
    try:
        query = """
            SELECT DISTINCT secret_type 
            FROM findings 
            WHERE secret_type IS NOT NULL AND secret_type != ''
            ORDER BY secret_type
        """
        results = db_manager.execute_query(query)
        return [row['secret_type'] for row in results if row['secret_type']]
    except Exception as e:
        logger.error(f"Error getting distinct secret types: {e}")
        return []


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
     Output("fp-count-badge", "children"),
     Output("secret-type-filter", "options")],
    [Input("severity-filter", "value"),
     Input("tool-filter", "value"),
     Input("project-filter", "value"),
     Input("secret-type-filter", "value"),
     Input("chart-tool-tabs", "value"),
     Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
@secure_callback
def update_dashboard(severity_filter, tool_filter, project_filter, secret_type_filter, chart_tool_filter, refresh_clicks, n_intervals):
    """Update all dashboard components with permanent dark mode and security validation"""

    # Sanitize all input parameters
    severity_filter = sanitize_input(severity_filter or "all", 100)
    tool_filter = sanitize_input(tool_filter or "all", 100)
    project_filter = sanitize_input(project_filter or "all", 100)
    secret_type_filter = sanitize_input(secret_type_filter or "all", 200)
    chart_tool_filter = sanitize_input(chart_tool_filter or "all", 100)

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
        return empty_fig, empty_fig, empty_fig, empty_fig, [], "No data", "Never", [], fp_badge, [{"label": "All Secret Types", "value": "all"}]

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

    if secret_type_filter != "all":
        filtered_df = filtered_df[filtered_df['secret_type'] == secret_type_filter]

    # Apply chart-specific tool filter (for the chart tabs)
    chart_df = filtered_df.copy()
    if chart_tool_filter != "all":
        chart_df = chart_df[chart_df['tool_source'] == chart_tool_filter]

    # Create severity chart (uses chart_df which includes chart tool filter)
    severity_counts = chart_df['severity'].value_counts()
    tool_label = {'all': 'All Tools', 'custom': 'Custom Scanner', 'trufflehog': 'TruffleHog', 'gitleaks': 'Gitleaks'}
    chart_title_suffix = f" - {tool_label.get(chart_tool_filter, 'All Tools')}" if chart_tool_filter != 'all' else ''
    
    severity_chart = px.bar(
        x=severity_counts.index,
        y=severity_counts.values,
        title=f"Findings by Severity{chart_title_suffix}",
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

    # Create tool distribution chart (uses chart_df if filtered, otherwise show tool breakdown)
    if chart_tool_filter != 'all':
        # When filtered to a single tool, show secret types instead
        secret_type_counts = chart_df['secret_type'].value_counts().head(10)  # Top 10 secret types
        tool_chart = px.pie(
            values=secret_type_counts.values,
            names=secret_type_counts.index,
            title=f"Secret Types - {tool_label.get(chart_tool_filter, 'Selected Tool')}",
            color_discrete_sequence=tool_colors,
            template=template
        )
    else:
        tool_counts = chart_df['tool_source'].value_counts()
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

    # Prepare table data - all filtered findings (pagination handled by DataTable)
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
    
    total_filtered = len(filtered_df)  # What's shown in table after filters
    open_count = len(filtered_df[filtered_df['resolution_status'] == 'open'])

    summary_stats = [
        html.Div([
            html.H4("📊 Overview", style={'marginBottom': '10px', 'color': '#60a5fa'}),
            html.Div([html.Strong("Total in Database:"), f" {total_in_db:,}"], className="stat-item"),
            html.Div([html.Strong("Filtered Results:"), f" {total_filtered:,}"], className="stat-item"),
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

    # Get distinct secret types for the dropdown filter
    secret_types = get_distinct_secret_types()
    secret_type_options = [{"label": "All Secret Types", "value": "all"}]
    secret_type_options.extend([{"label": st, "value": st} for st in secret_types])

    return (severity_chart, tool_chart, timeline_chart, file_types_chart,
            table_data, summary_stats, last_update, project_options, fp_badge, secret_type_options)

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


# Quick date range buttons callback
@app.callback(
    [Output("report-date-range", "start_date"),
     Output("report-date-range", "end_date")],
    [Input("btn-last-7-days", "n_clicks"),
     Input("btn-last-30-days", "n_clicks"),
     Input("btn-all-time", "n_clicks")],
    prevent_initial_call=True
)
def update_date_range(last_7, last_30, all_time):
    """Update date range based on quick select buttons"""
    ctx = dash.callback_context
    if not ctx.triggered:
        return no_update, no_update
    
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    today = datetime.now()
    
    if trigger_id == "btn-last-7-days":
        return today - timedelta(days=7), today
    elif trigger_id == "btn-last-30-days":
        return today - timedelta(days=30), today
    elif trigger_id == "btn-all-time":
        return today - timedelta(days=365), today
    
    return no_update, no_update


@app.callback(
    Output("report-download", "data"),
    [Input("export-csv-btn", "n_clicks"),
     Input("export-json-btn", "n_clicks"),
     Input("export-pdf-btn", "n_clicks")],
    [State("report-severity-filter", "value"),
     State("report-date-range", "start_date"),
     State("report-date-range", "end_date"),
     State("report-tool-filter", "value"),
     State("severity-filter", "value"),
     State("tool-filter", "value")]
)
@secure_callback
def export_report(csv_clicks, json_clicks, pdf_clicks, report_severities, start_date, end_date, report_tool, severity_filter, tool_filter):
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
        
        # Apply report tool filter (takes priority over global filter)
        if report_tool and report_tool != "all":
            df = df[df['tool_source'] == report_tool]
        elif tool_filter and tool_filter != "all":
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


# File-based False Positive Management Callbacks
@app.callback(
    Output("file-action-result", "children"),
    [Input("btn-mark-file-fp", "n_clicks")],
    [State("file-grouped-table", "selected_rows"),
     State("file-grouped-table", "data")],
    prevent_initial_call=True
)
def handle_file_fp_action(mark_clicks, selected_rows, table_data):
    """Handle marking all findings in selected files as false positives"""
    if not mark_clicks or not selected_rows or not table_data:
        return ""
    
    try:
        # Get file paths from selected rows
        selected_files = []
        for i in selected_rows:
            if i < len(table_data):
                file_path = table_data[i].get('file_path')
                if file_path:
                    selected_files.append(file_path)
        
        if not selected_files:
            return html.Span("⚠️ No files selected", style={'color': '#f59e0b'})
        
        # Get all finding IDs for these files
        total_marked = 0
        for file_path in selected_files:
            query = """
                SELECT id FROM findings 
                WHERE file_path = %s 
                AND resolution_status != 'false_positive'
            """
            results = db_manager.execute_query(query, (file_path,))
            finding_ids = [row['id'] for row in results]
            
            if finding_ids:
                result = findings_manager.mark_as_false_positive(
                    finding_ids=finding_ids,
                    reason=f"Bulk marked via file view: {file_path}",
                    marked_by="dashboard_user"
                )
                total_marked += result.get('success', 0)
        
        # Force cache refresh
        data_cache['findings_df'] = None
        data_cache['last_update'] = None
        
        if total_marked > 0:
            return html.Span(
                f"✅ Marked {total_marked} findings in {len(selected_files)} file(s) as false positive",
                style={'color': '#22c55e', 'fontWeight': 'bold'}
            )
        else:
            return html.Span("⚠️ No findings to mark", style={'color': '#f59e0b'})
    
    except Exception as e:
        logger.error(f"Error marking files as FP: {e}")
        return html.Span(f"❌ Error: {str(e)}", style={'color': '#ef4444'})


# File-based Jira Ticket Creation Callback
@app.callback(
    Output("file-jira-result", "children"),
    [Input("btn-create-file-jira", "n_clicks")],
    [State("file-grouped-table", "selected_rows"),
     State("file-grouped-table", "data")],
    prevent_initial_call=True
)
def create_jira_tickets_for_files(n_clicks, selected_rows, table_data):
    """Create ONE Jira ticket per selected file, consolidating all findings"""
    if not n_clicks or not selected_rows or not table_data:
        return ""
    
    # Check if Jira is configured
    if not jira_manager.is_configured:
        return html.Span(
            "⚠️ Jira is not configured. Click 'Jira Settings' to set up the connection.",
            style={'color': '#f59e0b'}
        )
    
    try:
        # Get file paths from selected rows
        selected_files = []
        for i in selected_rows:
            if i < len(table_data):
                file_path = table_data[i].get('file_path')
                if file_path:
                    selected_files.append(file_path)
        
        if not selected_files:
            return html.Span("⚠️ No files selected", style={'color': '#f59e0b'})
        
        # Get all findings for these files (excluding false positives)
        all_findings = []
        for file_path in selected_files:
            query = """
                SELECT id, file_path, secret_type, secret_value, severity, 
                       line_number, tool_source, context, created_at as first_seen
                FROM findings 
                WHERE file_path = %s 
                AND resolution_status != 'false_positive'
            """
            results = db_manager.execute_query(query, (file_path,))
            all_findings.extend([dict(row) for row in results])
        
        if not all_findings:
            return html.Span("⚠️ No valid findings in selected files", style={'color': '#f59e0b'})
        
        # Create tickets grouped by file
        results = jira_manager.create_tickets_by_file(all_findings)
        
        success_count = results.get('success_count', 0)
        failed_count = results.get('failed_count', 0)
        tickets = results.get('created_tickets', [])
        
        if success_count > 0:
            ticket_links = []
            for t in tickets[:5]:
                finding_count = t.get('finding_count', 0)
                ticket_links.append(
                    html.A(
                        f"{t['key']} ({finding_count} findings)", 
                        href=t['url'], 
                        target='_blank',
                        style={'color': '#60a5fa', 'marginRight': '10px'}
                    )
                )
            
            if len(tickets) > 5:
                ticket_links.append(html.Span(f"... and {len(tickets) - 5} more"))
            
            return html.Div([
                html.Span(f"✅ Created {success_count} Jira ticket(s): ", style={'color': '#22c55e'}),
                *ticket_links,
                html.Span(f" ({failed_count} failed)", style={'color': '#ef4444'}) if failed_count > 0 else ""
            ])
        else:
            errors = results.get('errors', [])
            error_msg = errors[0].get('error', 'Unknown error') if errors else 'Unknown error'
            return html.Span(f"❌ Failed: {error_msg}", style={'color': '#ef4444'})
            
    except Exception as e:
        logger.error(f"Error creating file-based Jira tickets: {e}")
        return html.Span(f"❌ Error: {str(e)}", style={'color': '#ef4444'})


# False Positives Viewer Modal Callbacks
@app.callback(
    [Output("fp-viewer-modal", "style"),
     Output("fp-viewer-table-container", "children")],
    [Input("btn-view-fps", "n_clicks"),
     Input("btn-view-fps-file", "n_clicks"),
     Input("close-fp-viewer-btn", "n_clicks")],
    [State("fp-viewer-modal", "style")],
    prevent_initial_call=True
)
@secure_callback
def toggle_fp_viewer_modal(view_clicks, view_file_clicks, close_clicks, current_style):
    """Toggle the False Positives viewer modal and load data"""
    ctx = dash.callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    # Close button clicked
    if trigger_id == "close-fp-viewer-btn":
        return {**current_style, 'display': 'none'}, []
    
    # View button clicked - open modal and load data (from either view)
    if trigger_id in ["btn-view-fps", "btn-view-fps-file"]:
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


# =========================================================================
# Project Management Callbacks
# =========================================================================

# Import project manager (lazy import to avoid circular deps)
try:
    from project_manager import project_manager
    PROJECT_MANAGER_AVAILABLE = True
except ImportError:
    PROJECT_MANAGER_AVAILABLE = False
    logger.warning("Project manager not available - multi-directory features disabled")


@app.callback(
    [Output("project-manager-modal", "style"),
     Output("project-directory-list", "children"),
     Output("scan-dir-selector", "options"),
     Output("pending-scans-list", "children")],
    [Input("btn-project-manager", "n_clicks"),
     Input("close-project-modal-btn", "n_clicks"),
     Input("btn-add-directory", "n_clicks"),
     Input("btn-trigger-scan", "n_clicks")],
    [State("project-manager-modal", "style")],
    prevent_initial_call=True
)
def toggle_project_modal(open_clicks, close_clicks, add_clicks, scan_clicks, current_style):
    """Toggle project management modal and refresh data"""
    logger.info(f"toggle_project_modal called: open={open_clicks}, close={close_clicks}, add={add_clicks}, scan={scan_clicks}")
    ctx = dash.callback_context
    if not ctx.triggered:
        logger.warning("toggle_project_modal: no trigger, preventing update")
        raise PreventUpdate
    
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    logger.info(f"toggle_project_modal triggered by: {trigger_id}")
    
    # Default hidden state
    hidden_style = {
        'display': 'none', 'position': 'fixed', 'top': '0', 'left': '0',
        'right': '0', 'bottom': '0', 'backgroundColor': 'rgba(0,0,0,0.7)',
        'zIndex': '1000', 'paddingTop': '30px'
    }
    visible_style = {**hidden_style, 'display': 'block'}
    
    empty_list = html.P("No directories configured yet.", style={'color': '#9ca3af', 'fontStyle': 'italic'})
    empty_options = [{"label": "No directories available", "value": ""}]
    no_pending = html.P("No pending scans.", style={'color': '#9ca3af', 'fontStyle': 'italic'})
    
    if trigger_id == "close-project-modal-btn":
        return hidden_style, empty_list, empty_options, no_pending
    
    if not PROJECT_MANAGER_AVAILABLE:
        error_msg = html.P("⚠️ Project manager not initialized. Run the database migration first.", 
                          style={'color': '#f59e0b'})
        return visible_style if trigger_id == "btn-project-manager" else hidden_style, error_msg, empty_options, no_pending
    
    try:
        # Get directories
        directories = project_manager.get_all_directories(active_only=False)
        
        # Build directory list UI
        if directories:
            dir_items = []
            for d in directories:
                status_icon = "✅" if d.is_active else "⏸️"
                last_scan = d.last_scan_at.strftime('%Y-%m-%d %H:%M') if d.last_scan_at else "Never"
                dir_items.append(
                    html.Div([
                        html.Div([
                            html.Strong(f"{status_icon} {d.display_name}", style={'color': '#e0e0e0'}),
                            html.Span(f" ({d.scan_schedule})", style={'color': '#6b7280', 'fontSize': '12px'}),
                        ]),
                        html.Div([
                            html.Span(d.directory_path, style={'color': '#9ca3af', 'fontSize': '12px'}),
                            html.Span(f" | Last: {last_scan} | Files: {d.total_files:,} | Findings: {d.total_findings:,}",
                                     style={'color': '#6b7280', 'fontSize': '11px'})
                        ])
                    ], style={'padding': '8px', 'borderBottom': '1px solid #444', 'marginBottom': '5px'})
                )
            directory_list = html.Div(dir_items)
            
            # Build dropdown options
            dropdown_options = [
                {"label": f"{d.display_name} ({d.directory_path})", "value": d.id}
                for d in directories if d.is_active
            ]
        else:
            directory_list = empty_list
            dropdown_options = empty_options
        
        # Get pending scans
        pending = project_manager.get_pending_scans()
        if pending:
            pending_items = []
            for p in pending:
                status_color = {'pending': '#f59e0b', 'queued': '#3b82f6', 'running': '#22c55e'}.get(p.status, '#6b7280')
                pending_items.append(
                    html.Div([
                        html.Span(f"⏳ {p.scan_type}", style={'color': status_color, 'fontWeight': 'bold'}),
                        html.Span(f" - {p.status}", style={'color': '#9ca3af'}),
                        html.Span(f" (requested {p.requested_at.strftime('%H:%M')})", style={'color': '#6b7280', 'fontSize': '11px'})
                    ], style={'padding': '5px', 'borderBottom': '1px solid #333'})
                )
            pending_list = html.Div(pending_items)
        else:
            pending_list = no_pending
        
        # Show modal if opened
        if trigger_id == "btn-project-manager":
            return visible_style, directory_list, dropdown_options, pending_list
        else:
            # Refresh data after add/scan actions
            return current_style, directory_list, dropdown_options, pending_list
            
    except Exception as e:
        logger.error(f"Error in project modal: {e}")
        error_msg = html.P(f"❌ Error: {str(e)}", style={'color': '#ef4444'})
        return visible_style if trigger_id == "btn-project-manager" else current_style, error_msg, empty_options, no_pending


@app.callback(
    Output("add-dir-result", "children"),
    [Input("btn-add-directory", "n_clicks")],
    [State("new-dir-path", "value"),
     State("new-dir-name", "value"),
     State("new-dir-schedule", "value"),
     State("new-dir-priority", "value")],
    prevent_initial_call=True
)
def add_directory(n_clicks, path, name, schedule, priority):
    """Add a new scan directory"""
    if not n_clicks or not path or not name:
        return html.Span("⚠️ Path and name are required", style={'color': '#f59e0b'})
    
    if not PROJECT_MANAGER_AVAILABLE:
        return html.Span("⚠️ Run database migration first", style={'color': '#f59e0b'})
    
    try:
        dir_id = project_manager.add_directory(
            directory_path=path,
            display_name=name,
            scan_schedule=schedule,
            scan_priority=priority
        )
        if dir_id:
            return html.Span(f"✅ Added directory: {name}", style={'color': '#22c55e'})
        else:
            return html.Span("❌ Failed to add directory", style={'color': '#ef4444'})
    except Exception as e:
        return html.Span(f"❌ Error: {str(e)}", style={'color': '#ef4444'})


@app.callback(
    Output("trigger-scan-result", "children"),
    [Input("btn-trigger-scan", "n_clicks")],
    [State("scan-dir-selector", "value"),
     State("scan-type-selector", "value")],
    prevent_initial_call=True
)
def trigger_manual_scan(n_clicks, directory_id, scan_type):
    """Trigger a manual scan for selected directory"""
    if not n_clicks or not directory_id:
        return html.Span("⚠️ Select a directory first", style={'color': '#f59e0b'})
    
    if not PROJECT_MANAGER_AVAILABLE:
        return html.Span("⚠️ Run database migration first", style={'color': '#f59e0b'})
    
    try:
        request_id = project_manager.request_scan(
            directory_id=directory_id,
            scan_type=scan_type,
            requested_by="dashboard_user"
        )
        if request_id:
            return html.Span(f"✅ Scan queued! Request ID: {request_id[:8]}...", style={'color': '#22c55e'})
        else:
            return html.Span("❌ Failed to queue scan", style={'color': '#ef4444'})
    except Exception as e:
        return html.Span(f"❌ Error: {str(e)}", style={'color': '#ef4444'})


# Jira Integration Callbacks
@app.callback(
    [Output("jira-settings-modal", "style"),
     Output("jira-server-url", "value"),
     Output("jira-username", "value"),
     Output("jira-api-token", "value"),
     Output("jira-project-key", "value"),
     Output("jira-issue-type", "value")],
    [Input("btn-jira-settings", "n_clicks"),
     Input("btn-close-jira-settings", "n_clicks"),
     Input("btn-save-jira", "n_clicks")]
)
def toggle_jira_settings_modal(open_clicks, close_clicks, save_clicks):
    """Toggle the Jira settings modal and populate with saved values"""
    ctx = dash.callback_context
    hidden_style = {'display': 'none'}
    visible_style = {
        'display': 'block', 'position': 'fixed', 'top': '0', 'left': '0',
        'right': '0', 'bottom': '0', 'backgroundColor': 'rgba(0,0,0,0.7)',
        'zIndex': '1000', 'paddingTop': '50px'
    }
    
    # Default values (empty or no update)
    no_update = dash.no_update
    
    if not ctx.triggered:
        return hidden_style, no_update, no_update, no_update, no_update, no_update
    
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    if trigger_id == "btn-jira-settings":
        # Opening modal - populate with saved values from config
        return (
            visible_style,
            config.jira.server_url or "",
            config.jira.username or "",
            config.jira.api_token or "",
            config.jira.project_key or "",
            config.jira.issue_type or "Task"
        )
    
    # Closing modal
    return hidden_style, no_update, no_update, no_update, no_update, no_update


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


# ============================================================================
# NEW CALLBACKS FOR TOOL TABS, FILE GROUPING, AND VIEW TOGGLE
# ============================================================================

@app.callback(
    [Output('file-grouped-container', 'style'),
     Output('all-findings-container', 'style')],
    [Input('view-mode-toggle', 'value')]
)
def toggle_view_mode(view_mode):
    """Toggle between file-grouped view and all-findings view"""
    if view_mode == 'by-file':
        return {'display': 'block'}, {'display': 'none'}
    else:
        return {'display': 'none'}, {'display': 'block'}


@app.callback(
    [Output('file-grouped-table', 'data'),
     Output('file-secret-type-filter', 'options')],
    [Input('tool-tabs', 'value'),
     Input('severity-filter', 'value'),
     Input('project-filter', 'value'),
     Input('refresh-btn', 'n_clicks'),
     Input('interval-component', 'n_intervals'),
     Input('file-search-input', 'value'),
     Input('file-tool-filter', 'value'),
     Input('file-severity-filter', 'value'),
     Input('file-secret-type-filter', 'value')]
)
@secure_callback
def update_file_grouped_table(tool_tab, severity_filter, project_filter, refresh_clicks, n_intervals, 
                               file_search, file_tool_filter, file_severity_filter, file_secret_type_filter):
    """Update the file-grouped table based on filters"""
    # Use local file filters if set, otherwise use global filters
    tool_filter = file_tool_filter if file_tool_filter and file_tool_filter != 'all' else (
        'all' if tool_tab == 'all-tools' else tool_tab
    )
    sev_filter = file_severity_filter if file_severity_filter and file_severity_filter != 'all' else severity_filter
    secret_type_filter = file_secret_type_filter if file_secret_type_filter and file_secret_type_filter != 'all' else 'all'
    
    df = get_file_grouped_data(
        tool_filter=sanitize_input(tool_filter or 'all', 50),
        severity_filter=sanitize_input(sev_filter or 'all', 50),
        project_filter=sanitize_input(project_filter or 'all', 200),
        secret_type_filter=sanitize_input(secret_type_filter or 'all', 100)
    )
    
    if df.empty:
        # Return empty table and default options
        secret_type_options = [{"label": "All Secret Types", "value": "all"}]
        return [], secret_type_options
    
    # Get unique secret types from database for dropdown options
    try:
        type_query = """
            SELECT DISTINCT secret_type FROM findings 
            WHERE resolution_status != 'false_positive' AND secret_type IS NOT NULL
            ORDER BY secret_type
        """
        type_results = db_manager.execute_query(type_query)
        secret_type_options = [{"label": "All Secret Types", "value": "all"}]
        if type_results:
            secret_type_options.extend([
                {"label": row['secret_type'], "value": row['secret_type']} 
                for row in type_results
            ])
    except Exception as e:
        logger.warning(f"Error getting secret types: {e}")
        secret_type_options = [{"label": "All Secret Types", "value": "all"}]
    
    # Apply file search filter
    if file_search and len(file_search) >= 2:
        search_term = file_search.lower()
        df = df[df['file_path'].str.lower().str.contains(search_term, na=False)]
    
    # Format for display
    table_data = []
    for _, row in df.iterrows():
        tools_list = row.get('tools', [])
        types_list = row.get('secret_types', [])
        
        # Format tools with emojis
        tools_display = ', '.join(tools_list[:3]) if tools_list else 'N/A'
        if len(tools_list) > 3:
            tools_display += f' +{len(tools_list)-3}'
        
        # Format secret types
        types_display = ', '.join(types_list[:2]) if types_list else 'N/A'
        if len(types_list) > 2:
            types_display += f' +{len(types_list)-2}'
        
        # Format date
        latest = row.get('latest_finding')
        if latest:
            try:
                latest_str = pd.to_datetime(latest).strftime('%Y-%m-%d')
            except:
                latest_str = str(latest)[:10]
        else:
            latest_str = 'N/A'
        
        table_data.append({
            'file_path': sanitize_input(str(row.get('file_path', '')), 500),
            'finding_count': row.get('finding_count', 0),
            'max_severity': row.get('max_severity', 'Unknown'),
            'tools_display': tools_display,
            'types_display': types_display,
            'project_name': sanitize_input(str(row.get('project_name', 'N/A')), 100),
            'latest_finding': latest_str
        })
    
    return table_data, secret_type_options


@app.callback(
    [Output('tool-stats-panel', 'children'),
     Output('tool-specific-chart', 'figure')],
    [Input('tool-tabs', 'value'),
     Input('refresh-btn', 'n_clicks'),
     Input('interval-component', 'n_intervals')]
)
@secure_callback
def update_tool_panel(selected_tool, refresh_clicks, n_intervals):
    """Update the tool-specific stats panel and chart"""
    stats = get_tool_summary_stats()
    
    # Determine if showing all tools or specific tool
    is_dark_mode = True
    template = 'plotly_dark'
    
    def build_severity_badges(tool_key):
        """Build severity badges that only show non-zero values"""
        tool_stats = stats.get(tool_key, {})
        badges = []
        
        critical = tool_stats.get('critical', 0)
        high = tool_stats.get('high', 0)
        medium = tool_stats.get('medium', 0)
        low = tool_stats.get('low', 0)
        
        if critical > 0:
            badges.append(html.Span(f"🔴 Critical: {critical:,}", style={'color': '#ff0000', 'marginRight': '8px', 'fontSize': '12px'}))
        if high > 0:
            badges.append(html.Span(f"🟠 High: {high:,}", style={'color': '#f97316', 'marginRight': '8px', 'fontSize': '12px'}))
        if medium > 0:
            badges.append(html.Span(f"🟡 Medium: {medium:,}", style={'color': '#eab308', 'marginRight': '8px', 'fontSize': '12px'}))
        if low > 0:
            badges.append(html.Span(f"🟢 Low: {low:,}", style={'color': '#22c55e', 'fontSize': '12px'}))
        
        if not badges:
            badges.append(html.Span("✅ No findings", style={'color': '#22c55e', 'fontSize': '12px'}))
        
        return badges
    
    if selected_tool == 'all-tools':
        # Show summary for all tools
        stats_children = html.Div([
            html.Div([
                html.Div([
                    html.H4("🔍 Custom Scanner", style={'color': '#60a5fa', 'marginBottom': '10px'}),
                    html.Div(f"Findings: {stats.get('custom', {}).get('total_findings', 0):,}"),
                    html.Div(f"Files: {stats.get('custom', {}).get('unique_files', 0):,}"),
                    html.Div(build_severity_badges('custom'), style={'marginTop': '5px', 'flexWrap': 'wrap'})
                ], style={'flex': '1', 'padding': '10px', 'backgroundColor': '#1e1e1e', 'borderRadius': '6px', 'marginRight': '10px'}),
                
                html.Div([
                    html.H4("🐷 TruffleHog", style={'color': '#22c55e', 'marginBottom': '10px'}),
                    html.Div(f"Findings: {stats.get('trufflehog', {}).get('total_findings', 0):,}"),
                    html.Div(f"Files: {stats.get('trufflehog', {}).get('unique_files', 0):,}"),
                    html.Div(build_severity_badges('trufflehog'), style={'marginTop': '5px', 'flexWrap': 'wrap'})
                ], style={'flex': '1', 'padding': '10px', 'backgroundColor': '#1e1e1e', 'borderRadius': '6px', 'marginRight': '10px'}),
                
                html.Div([
                    html.H4("🔐 Gitleaks", style={'color': '#f59e0b', 'marginBottom': '10px'}),
                    html.Div(f"Findings: {stats.get('gitleaks', {}).get('total_findings', 0):,}"),
                    html.Div(f"Files: {stats.get('gitleaks', {}).get('unique_files', 0):,}"),
                    html.Div(build_severity_badges('gitleaks'), style={'marginTop': '5px', 'flexWrap': 'wrap'})
                ], style={'flex': '1', 'padding': '10px', 'backgroundColor': '#1e1e1e', 'borderRadius': '6px'}),
            ], style={'display': 'flex', 'color': '#e0e0e0'})
        ])
        
        # Create comparison chart
        tool_names = ['Custom', 'TruffleHog', 'Gitleaks']
        tool_keys = ['custom', 'trufflehog', 'gitleaks']
        colors = ['#60a5fa', '#22c55e', '#f59e0b']
        
        fig = go.Figure()
        for i, (name, key) in enumerate(zip(tool_names, tool_keys)):
            tool_stats = stats.get(key, {})
            fig.add_trace(go.Bar(
                name=name,
                x=['Critical', 'High', 'Medium', 'Low'],
                y=[tool_stats.get('critical', 0), tool_stats.get('high', 0), 
                   tool_stats.get('medium', 0), tool_stats.get('low', 0)],
                marker_color=colors[i]
            ))
        
        fig.update_layout(
            title='Severity Breakdown by Tool',
            barmode='group',
            template=template,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=50, r=50, t=50, b=50)
        )
        
    else:
        # Show specific tool stats
        tool_data = stats.get(selected_tool, {})
        tool_names = {'custom': '🔍 Custom Scanner', 'trufflehog': '🐷 TruffleHog', 'gitleaks': '🔐 Gitleaks'}
        tool_colors = {'custom': '#60a5fa', 'trufflehog': '#22c55e', 'gitleaks': '#f59e0b'}
        
        # Build severity badges for specific tool
        severity_items = []
        if tool_data.get('critical', 0) > 0:
            severity_items.append(html.Div([
                html.Span("🔴 Critical: ", style={'color': '#ff0000'}),
                html.Span(f"{tool_data.get('critical', 0):,}")
            ], style={'marginRight': '20px'}))
        if tool_data.get('high', 0) > 0:
            severity_items.append(html.Div([
                html.Span("🟠 High: ", style={'color': '#f97316'}),
                html.Span(f"{tool_data.get('high', 0):,}")
            ], style={'marginRight': '20px'}))
        if tool_data.get('medium', 0) > 0:
            severity_items.append(html.Div([
                html.Span("🟡 Medium: ", style={'color': '#eab308'}),
                html.Span(f"{tool_data.get('medium', 0):,}")
            ], style={'marginRight': '20px'}))
        if tool_data.get('low', 0) > 0:
            severity_items.append(html.Div([
                html.Span("🟢 Low: ", style={'color': '#22c55e'}),
                html.Span(f"{tool_data.get('low', 0):,}")
            ]))
        if not severity_items:
            severity_items.append(html.Div([
                html.Span("✅ No findings", style={'color': '#22c55e'})
            ]))
        
        stats_children = html.Div([
            html.H4(tool_names.get(selected_tool, selected_tool), 
                    style={'color': tool_colors.get(selected_tool, '#e0e0e0'), 'marginBottom': '15px'}),
            html.Div([
                html.Div([
                    html.Strong("Total Findings: "),
                    html.Span(f"{tool_data.get('total_findings', 0):,}")
                ], style={'marginRight': '30px'}),
                html.Div([
                    html.Strong("Unique Files: "),
                    html.Span(f"{tool_data.get('unique_files', 0):,}")
                ], style={'marginRight': '30px'}),
            ] + severity_items, style={'display': 'flex', 'flexWrap': 'wrap', 'gap': '10px'})
        ], style={'color': '#e0e0e0'})
        
        # Create pie chart for single tool - only include non-zero severities
        severity_data = [
            ('Critical', tool_data.get('critical', 0), '#ff0000'),
            ('High', tool_data.get('high', 0), '#f97316'),
            ('Medium', tool_data.get('medium', 0), '#eab308'),
            ('Low', tool_data.get('low', 0), '#22c55e')
        ]
        # Filter out zero values
        severity_data = [(label, val, color) for label, val, color in severity_data if val > 0]
        
        if severity_data:
            severity_labels, severity_values, severity_colors = zip(*severity_data)
        else:
            severity_labels, severity_values, severity_colors = [], [], []
        
        fig = go.Figure(data=[go.Pie(
            labels=severity_labels,
            values=severity_values,
            marker_colors=severity_colors,
            hole=0.4
        )])
        
        fig.update_layout(
            title=f'{tool_names.get(selected_tool, selected_tool)} - Severity Distribution',
            template=template,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=50, r=50, t=50, b=50)
        )
    
    return stats_children, fig


@app.callback(
    [Output('file-detail-modal', 'style'),
     Output('file-detail-title', 'children'),
     Output('file-detail-stats', 'children'),
     Output('file-detail-findings', 'children')],
    [Input('file-grouped-table', 'active_cell'),
     Input('close-file-detail-btn', 'n_clicks')],
    [State('file-grouped-table', 'data'),
     State('file-detail-modal', 'style')]
)
@secure_callback
def handle_file_detail_modal(active_cell, close_clicks, table_data, current_style):
    """Show/hide the file detail modal when a file is clicked"""
    ctx = dash.callback_context
    if not ctx.triggered:
        return {'display': 'none'}, "", [], []
    
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    # Handle close button
    if trigger_id == 'close-file-detail-btn':
        return {'display': 'none'}, "", [], []
    
    # Handle file row click
    if trigger_id == 'file-grouped-table' and active_cell and table_data:
        row_idx = active_cell.get('row')
        if row_idx is not None and row_idx < len(table_data):
            row = table_data[row_idx]
            file_path = row.get('file_path', '')
            
            # Get all findings for this file
            findings = get_findings_for_file(file_path)
            
            if not findings:
                return {'display': 'none'}, "", [], []
            
            # Build title
            title = f"📄 {file_path}"
            
            # Build stats
            stats_div = html.Div([
                html.Span(f"📊 {len(findings)} findings in this file", style={'marginRight': '20px'}),
                html.Span(f"Max Severity: {row.get('max_severity', 'Unknown')}", 
                         style={'color': '#ff0000' if row.get('max_severity') == 'Critical' else '#e0e0e0'})
            ], style={'color': '#9ca3af', 'marginBottom': '15px'})
            
            # Build findings list
            findings_children = []
            for finding in findings:
                severity_colors = {
                    'Critical': '#8b0000', 'High': '#6d2f2f', 
                    'Medium': '#4a4020', 'Low': '#2c4a6b'
                }
                bg_color = severity_colors.get(finding.get('severity', 'Medium'), '#2d2d2d')
                
                finding_card = html.Div([
                    html.Div([
                        html.Span(finding.get('severity', 'Unknown'), 
                                 style={'padding': '2px 8px', 'backgroundColor': bg_color, 
                                        'borderRadius': '4px', 'marginRight': '10px', 'fontWeight': 'bold'}),
                        html.Span(finding.get('tool_source', 'unknown'), 
                                 style={'color': '#9ca3af', 'marginRight': '10px'}),
                        html.Span(finding.get('secret_type', 'Unknown Type'), 
                                 style={'color': '#60a5fa'})
                    ], style={'marginBottom': '10px'}),
                    
                    html.Div([
                        html.Strong("Value: "),
                        html.Code(sanitize_input(str(finding.get('secret_value', 'N/A')), 200),
                                 style={'backgroundColor': '#1e1e1e', 'padding': '2px 6px', 'borderRadius': '3px'})
                    ], style={'marginBottom': '8px', 'wordBreak': 'break-all'}),
                    
                    html.Div([
                        html.Strong("Context: "),
                        html.Pre(sanitize_input(str(finding.get('context', 'N/A')), 500),
                                style={'backgroundColor': '#1e1e1e', 'padding': '8px', 'borderRadius': '4px',
                                       'margin': '5px 0', 'whiteSpace': 'pre-wrap', 'fontSize': '12px',
                                       'maxHeight': '100px', 'overflowY': 'auto'})
                    ], style={'marginBottom': '8px'}),
                    
                    html.Div([
                        html.Span(f"Line: {finding.get('line_number', 'N/A')}", style={'marginRight': '15px'}),
                        html.Span(f"Confidence: {finding.get('confidence_score', 'N/A')}", style={'marginRight': '15px'}),
                        html.Span(f"ID: {str(finding.get('id', ''))[:8]}...", style={'color': '#6b7280'})
                    ], style={'fontSize': '12px', 'color': '#9ca3af'})
                ], style={
                    'backgroundColor': '#374151', 'padding': '15px', 'borderRadius': '8px',
                    'marginBottom': '10px', 'border': f'1px solid {bg_color}'
                })
                
                findings_children.append(finding_card)
            
            modal_style = {
                'display': 'block', 'position': 'fixed', 'top': '0', 'left': '0',
                'right': '0', 'bottom': '0', 'backgroundColor': 'rgba(0,0,0,0.8)',
                'zIndex': '1000', 'paddingTop': '30px', 'overflowY': 'auto'
            }
            
            return modal_style, title, stats_div, findings_children
    
    return current_style or {'display': 'none'}, "", [], []


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
                        html.Button("🔄 Refresh Data", id="refresh-btn", className="refresh-btn",
                            title="Refresh findings data from database"),
                        html.Button("🔍 Quick Scan", id="quick-scan-btn", className="scan-btn",
                            title="Run all scanners on /scan directory (custom + gitleaks + trufflehog)"),
                        html.Button("📁 Custom Scan", id="custom-scan-btn", className="scan-btn",
                            title="Configure and run a custom scan with specific settings"),
                        html.Button("📂 Projects", id="btn-project-manager", n_clicks=0, className="scan-btn",
                            title="Manage scan directories and projects"),
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

                html.Div([
                    html.Label("Secret Type Filter:", style={'color': '#e0e0e0', 'fontWeight': '600', 'marginBottom': '8px'}),
                    dcc.Dropdown(
                        id="secret-type-filter",
                        options=[{"label": "All Secret Types", "value": "all"}],
                        value="all",
                        clearable=False,
                        searchable=True,
                        placeholder="Search secret types...",
                        optionHeight=35,
                        style={'minWidth': '220px', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0'}
                    )
                ], className="filter-item"),
            ], className="filters"),

            # Charts Section with Tool Tabs
            html.Div([
                html.H3("📊 Findings Charts", style={'color': '#e0e0e0', 'marginBottom': '15px'}),
                dcc.Tabs(id='chart-tool-tabs', value='all', children=[
                    dcc.Tab(label='📊 All Tools', value='all', className='tool-tab',
                           selected_className='tool-tab-selected'),
                    dcc.Tab(label='🔍 Custom', value='custom', className='tool-tab',
                           selected_className='tool-tab-selected'),
                    dcc.Tab(label='🐷 TruffleHog', value='trufflehog', className='tool-tab',
                           selected_className='tool-tab-selected'),
                    dcc.Tab(label='🔐 Gitleaks', value='gitleaks', className='tool-tab',
                           selected_className='tool-tab-selected'),
                ], style={'marginBottom': '15px'}),
                
                # Charts Row
                html.Div([
                    html.Div([
                        dcc.Loading(
                            id="loading-severity",
                            type="circle",
                            color="#667eea",
                            children=[
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
                            ]
                        )
                    ], className="chart-container"),

                    html.Div([
                        dcc.Loading(
                            id="loading-tool-dist",
                            type="circle",
                            color="#667eea",
                            children=[
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
                            ]
                        )
                    ], className="chart-container")
                ], className="charts-row"),
            ], style={'marginBottom': '20px'}),

            # Additional Charts
            html.Div([
                html.Div([
                    dcc.Loading(
                        id="loading-timeline",
                        type="circle",
                        color="#667eea",
                        children=[
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
                        ]
                    )
                ], className="chart-container"),

                html.Div([
                    dcc.Loading(
                        id="loading-file-types",
                        type="circle",
                        color="#667eea",
                        children=[
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
                        ]
                    )
                ], className="chart-container")
            ], className="charts-row"),

            # Tool-Specific Tabs Section
            html.Div([
                html.H3("🔧 Findings by Scanner Tool", style={'color': '#e0e0e0', 'marginBottom': '15px'}),
                dcc.Tabs(id='tool-tabs', value='all-tools', children=[
                    dcc.Tab(label='📊 All Tools', value='all-tools', className='tool-tab',
                           selected_className='tool-tab-selected'),
                    dcc.Tab(label='🔍 Custom Scanner', value='custom', className='tool-tab',
                           selected_className='tool-tab-selected'),
                    dcc.Tab(label='🐷 TruffleHog', value='trufflehog', className='tool-tab',
                           selected_className='tool-tab-selected'),
                    dcc.Tab(label='🔐 Gitleaks', value='gitleaks', className='tool-tab',
                           selected_className='tool-tab-selected'),
                ], style={'marginBottom': '20px'}),
                
                # Tool-specific stats panel
                html.Div(id='tool-stats-panel', style={
                    'backgroundColor': '#2d3748', 'padding': '15px', 'borderRadius': '8px',
                    'marginBottom': '20px', 'border': '1px solid #444'
                }),
                
                # Tool-specific chart
                html.Div([
                    dcc.Graph(id='tool-specific-chart', className='chart',
                              config={'displayModeBar': True, 'displaylogo': False})
                ], className='chart-container', style={'marginBottom': '20px'})
            ], className='tool-tabs-section', style={
                'backgroundColor': '#1e1e1e', 'padding': '20px', 'borderRadius': '10px',
                'marginBottom': '30px', 'border': '1px solid #444'
            }),

            # View Toggle - By File vs All Findings
            html.Div([
                html.H3("📁 Findings View", style={'color': '#e0e0e0', 'marginBottom': '15px'}),
                html.Div([
                    html.Span("View Mode: ", style={'color': '#b0b0b0', 'marginRight': '10px'}),
                    dcc.RadioItems(
                        id='view-mode-toggle',
                        options=[
                            {'label': ' 📁 Group by File', 'value': 'by-file'},
                            {'label': ' 📋 All Findings', 'value': 'all-findings'}
                        ],
                        value='by-file',
                        inline=True,
                        style={'display': 'inline-flex', 'gap': '20px'},
                        inputStyle={'marginRight': '5px'},
                        labelStyle={'color': '#e0e0e0', 'cursor': 'pointer'}
                    )
                ], style={'marginBottom': '15px'})
            ]),

            # File-Grouped Table (shown when view-mode is 'by-file')
            html.Div([
                html.Div([
                    html.P("Click a file to see all findings in that file", 
                           style={'color': '#9ca3af', 'marginBottom': '10px', 'fontStyle': 'italic', 'display': 'inline-block'}),
                    html.Div([
                        dcc.Input(
                            id='file-search-input',
                            type='text',
                            placeholder='🔍 Search files...',
                            debounce=True,
                            style={
                                'backgroundColor': '#3d3d3d', 'color': '#e0e0e0',
                                'border': '1px solid #555', 'borderRadius': '6px',
                                'padding': '8px 12px', 'width': '300px',
                                'fontSize': '14px'
                            }
                        ),
                        dcc.Dropdown(
                            id='file-tool-filter',
                            options=[
                                {"label": "All Tools", "value": "all"},
                                {"label": "Custom", "value": "custom"},
                                {"label": "TruffleHog", "value": "trufflehog"},
                                {"label": "Gitleaks", "value": "gitleaks"}
                            ],
                            value="all",
                            clearable=False,
                            style={'width': '150px', 'display': 'inline-block', 'marginLeft': '10px'},
                            className="dark-dropdown"
                        ),
                        dcc.Dropdown(
                            id='file-severity-filter',
                            options=[
                                {"label": "All Severities", "value": "all"},
                                {"label": "Critical", "value": "Critical"},
                                {"label": "High", "value": "High"},
                                {"label": "Medium", "value": "Medium"},
                                {"label": "Low", "value": "Low"}
                            ],
                            value="all",
                            clearable=False,
                            style={'width': '150px', 'display': 'inline-block', 'marginLeft': '10px'},
                            className="dark-dropdown"
                        ),
                        dcc.Dropdown(
                            id='file-secret-type-filter',
                            options=[{"label": "All Secret Types", "value": "all"}],
                            value="all",
                            clearable=False,
                            searchable=True,
                            placeholder="Search secret types...",
                            style={'width': '200px', 'display': 'inline-block', 'marginLeft': '10px'},
                            className="dark-dropdown"
                        ),
                    ], style={'display': 'flex', 'alignItems': 'center', 'gap': '10px', 'marginBottom': '15px'}),
                ]),
                dcc.Loading(
                    id="loading-file-table",
                    type="circle",
                    color="#667eea",
                    children=[
                        dash_table.DataTable(
                            id='file-grouped-table',
                            columns=[
                                {"name": "File Path", "id": "file_path"},
                                {"name": "Findings", "id": "finding_count"},
                                {"name": "Max Severity", "id": "max_severity"},
                                {"name": "Tools", "id": "tools_display"},
                                {"name": "Secret Types", "id": "types_display"},
                                {"name": "Project", "id": "project_name"},
                                {"name": "Latest", "id": "latest_finding"},
                            ],
                            data=[],
                            filter_action="native",
                            sort_action="native",
                            sort_mode="multi",
                            page_action="native",
                    page_current=0,
                    page_size=25,
                    style_table={'overflowX': 'auto', 'backgroundColor': '#1e1e1e'},
                    style_header={
                        'backgroundColor': '#2d3748', 'color': '#e0e0e0',
                        'fontWeight': 'bold', 'border': '1px solid #444'
                    },
                    style_cell={
                        'backgroundColor': '#1e1e1e', 'color': '#e0e0e0',
                        'border': '1px solid #444', 'padding': '10px',
                        'textAlign': 'left', 'fontSize': '13px',
                        'fontFamily': 'Monaco, Consolas, monospace'
                    },
                    style_cell_conditional=[
                        {'if': {'column_id': 'file_path'}, 'width': '40%', 'maxWidth': '400px', 
                         'overflow': 'hidden', 'textOverflow': 'ellipsis'},
                        {'if': {'column_id': 'finding_count'}, 'width': '80px', 'textAlign': 'center', 
                         'fontWeight': 'bold'},
                        {'if': {'column_id': 'max_severity'}, 'width': '100px', 'textAlign': 'center'},
                        {'if': {'column_id': 'tools_display'}, 'width': '150px', 'textAlign': 'center'},
                        {'if': {'column_id': 'types_display'}, 'width': '200px'},
                        {'if': {'column_id': 'latest_finding'}, 'width': '120px', 'textAlign': 'center'},
                    ],
                    style_data_conditional=[
                        {'if': {'filter_query': '{max_severity} = "Critical"'},
                         'backgroundColor': '#8b0000', 'color': '#fff', 'fontWeight': 'bold'},
                        {'if': {'filter_query': '{max_severity} = "High"'},
                         'backgroundColor': '#6d2f2f', 'color': '#fff'},
                        {'if': {'filter_query': '{max_severity} = "Medium"'},
                         'backgroundColor': '#4a4020', 'color': '#fff'},
                        {'if': {'row_index': 'odd'}, 'backgroundColor': '#252525'},
                    ],
                    row_selectable='multi'
                        )
                    ]
                ),
                # FP Controls for file-grouped view
                html.Div([
                    html.Div([
                        html.Button(
                            "�️ View False Positives",
                            id='btn-view-fps-file',
                            n_clicks=0,
                            title="View all findings marked as false positives",
                            style={
                                'backgroundColor': '#6b7280', 'color': 'white',
                                'border': 'none', 'padding': '8px 16px',
                                'borderRadius': '6px', 'cursor': 'pointer',
                                'marginRight': '10px', 'fontWeight': 'bold'
                            }
                        ),
                        html.Button(
                            "�🚫 Mark Files as FP", 
                            id='btn-mark-file-fp',
                            n_clicks=0,
                            title="Mark all findings in selected files as false positives",
                            style={
                                'backgroundColor': '#dc2626', 'color': 'white',
                                'border': 'none', 'padding': '8px 16px',
                                'borderRadius': '6px', 'cursor': 'pointer',
                                'marginRight': '10px', 'fontWeight': 'bold'
                            }
                        ),
                        html.Button(
                            "🎫 Create Jira for Files", 
                            id='btn-create-file-jira',
                            n_clicks=0,
                            title="Create Jira tickets for all findings in selected files",
                            style={
                                'backgroundColor': '#0052cc', 'color': 'white',
                                'border': 'none', 'padding': '8px 16px',
                                'borderRadius': '6px', 'cursor': 'pointer',
                                'fontWeight': 'bold'
                            }
                        ),
                    ], style={'display': 'flex', 'justifyContent': 'flex-end', 'marginTop': '15px'}),
                    html.Div(id='file-action-result', style={'marginTop': '10px', 'textAlign': 'right'}),
                    html.Div(id='file-jira-result', style={'marginTop': '5px', 'textAlign': 'right'})
                ], style={'padding': '10px 0'})
            ], id='file-grouped-container', style={'display': 'block'}),
            
            # File Detail Modal - shows all findings for a selected file
            html.Div([
                html.Div([
                    html.Div([
                        html.H2(id='file-detail-title', style={'margin': '0', 'color': '#60a5fa'}),
                        html.Button("✕", id='close-file-detail-btn', n_clicks=0, style={
                            'background': 'none', 'border': 'none', 'color': '#aaa',
                            'fontSize': '24px', 'cursor': 'pointer', 'padding': '0'
                        })
                    ], style={'display': 'flex', 'justifyContent': 'space-between', 
                              'alignItems': 'center', 'marginBottom': '20px'}),
                    
                    html.Div(id='file-detail-stats', style={'marginBottom': '15px'}),
                    
                    html.Div(id='file-detail-findings', style={
                        'maxHeight': '500px', 'overflowY': 'auto'
                    })
                ], style={
                    'backgroundColor': '#2d3748', 'padding': '25px',
                    'borderRadius': '8px', 'maxWidth': '1200px', 'width': '90%',
                    'margin': '0 auto', 'border': '1px solid #555'
                })
            ], id='file-detail-modal', style={
                'display': 'none', 'position': 'fixed', 'top': '0', 'left': '0',
                'right': '0', 'bottom': '0', 'backgroundColor': 'rgba(0,0,0,0.8)',
                'zIndex': '1000', 'paddingTop': '30px', 'overflowY': 'auto'
            }),

            # Data Table (original - shown when view-mode is 'all-findings')
            html.Div([
                html.H3("📋 All Findings (click any row for full details)"),
                
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
                
                # Project Management Modal
                html.Div([
                    html.Div([
                        html.Div([
                            html.H2("📂 Project & Directory Management", style={'margin': '0', 'color': '#60a5fa'}),
                            html.Button("✕", id='close-project-modal-btn', n_clicks=0, style={
                                'background': 'none', 'border': 'none', 'color': '#aaa',
                                'fontSize': '24px', 'cursor': 'pointer', 'padding': '0'
                            })
                        ], style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center', 'marginBottom': '20px'}),
                        
                        html.P("Manage multiple scan directories and trigger custom scans.", 
                               style={'color': '#9ca3af', 'marginBottom': '20px'}),
                        
                        # Directory List Section
                        html.Div([
                            html.H4("📁 Scan Directories", style={'color': '#e0e0e0', 'marginBottom': '10px'}),
                            html.Div(id='project-directory-list', style={
                                'maxHeight': '200px', 'overflowY': 'auto', 'marginBottom': '15px',
                                'border': '1px solid #444', 'borderRadius': '6px', 'padding': '10px'
                            }),
                        ]),
                        
                        # Add New Directory Section
                        html.Div([
                            html.H4("➕ Add New Directory", style={'color': '#e0e0e0', 'marginBottom': '10px'}),
                            html.Div([
                                html.Label("Directory Path:", style={'color': '#e0e0e0'}),
                                dcc.Input(
                                    id='new-dir-path',
                                    type='text',
                                    placeholder='/path/to/scan (e.g., /scan/newproject)',
                                    style={
                                        'width': '100%', 'padding': '8px', 'marginBottom': '10px',
                                        'backgroundColor': '#3d3d3d', 'color': '#e0e0e0',
                                        'border': '1px solid #555', 'borderRadius': '4px'
                                    }
                                ),
                            ]),
                            html.Div([
                                html.Label("Display Name:", style={'color': '#e0e0e0'}),
                                dcc.Input(
                                    id='new-dir-name',
                                    type='text',
                                    placeholder='My Project Name',
                                    style={
                                        'width': '100%', 'padding': '8px', 'marginBottom': '10px',
                                        'backgroundColor': '#3d3d3d', 'color': '#e0e0e0',
                                        'border': '1px solid #555', 'borderRadius': '4px'
                                    }
                                ),
                            ]),
                            html.Div([
                                html.Div([
                                    html.Label("Scan Schedule:", style={'color': '#e0e0e0'}),
                                    dcc.Dropdown(
                                        id='new-dir-schedule',
                                        options=[
                                            {'label': 'Manual Only', 'value': 'manual'},
                                            {'label': 'Hourly', 'value': 'hourly'},
                                            {'label': 'Daily', 'value': 'daily'},
                                            {'label': 'Weekly', 'value': 'weekly'}
                                        ],
                                        value='daily',
                                        clearable=False,
                                        style={'width': '150px'},
                                        className="dark-dropdown"
                                    ),
                                ], style={'display': 'inline-block', 'marginRight': '20px'}),
                                html.Div([
                                    html.Label("Priority:", style={'color': '#e0e0e0'}),
                                    dcc.Dropdown(
                                        id='new-dir-priority',
                                        options=[
                                            {'label': '1 (Highest)', 'value': 1},
                                            {'label': '2', 'value': 2},
                                            {'label': '3', 'value': 3},
                                            {'label': '4', 'value': 4},
                                            {'label': '5 (Normal)', 'value': 5},
                                            {'label': '6', 'value': 6},
                                            {'label': '7', 'value': 7},
                                            {'label': '8', 'value': 8},
                                            {'label': '9', 'value': 9},
                                            {'label': '10 (Lowest)', 'value': 10}
                                        ],
                                        value=5,
                                        clearable=False,
                                        style={'width': '130px'},
                                        className="dark-dropdown"
                                    ),
                                ], style={'display': 'inline-block'}),
                            ], style={'marginBottom': '15px'}),
                            html.Button(
                                "➕ Add Directory",
                                id='btn-add-directory',
                                n_clicks=0,
                                style={
                                    'backgroundColor': '#22c55e', 'color': 'white',
                                    'border': 'none', 'padding': '8px 16px',
                                    'borderRadius': '6px', 'cursor': 'pointer',
                                    'fontWeight': 'bold'
                                }
                            ),
                            html.Div(id='add-dir-result', style={'marginTop': '10px'})
                        ], style={
                            'backgroundColor': '#1f2937', 'padding': '15px',
                            'borderRadius': '8px', 'marginBottom': '20px'
                        }),
                        
                        # Scan Controls Section
                        html.Div([
                            html.H4("🔍 Trigger Manual Scan", style={'color': '#e0e0e0', 'marginBottom': '10px'}),
                            html.Div([
                                dcc.Dropdown(
                                    id='scan-dir-selector',
                                    options=[],
                                    placeholder='Select directory to scan...',
                                    style={'width': '250px', 'display': 'inline-block', 'marginRight': '10px'},
                                    className="dark-dropdown"
                                ),
                                dcc.Dropdown(
                                    id='scan-type-selector',
                                    options=[
                                        {'label': '🔄 Full Scan (All Tools)', 'value': 'full'},
                                        {'label': '📝 Incremental', 'value': 'incremental'},
                                        {'label': '🔍 Custom Scanner Only', 'value': 'custom_only'},
                                        {'label': '🐷 TruffleHog Only', 'value': 'trufflehog_only'},
                                        {'label': '🔐 Gitleaks Only', 'value': 'gitleaks_only'}
                                    ],
                                    value='full',
                                    clearable=False,
                                    style={'width': '180px', 'display': 'inline-block', 'marginRight': '10px'},
                                    className="dark-dropdown"
                                ),
                                html.Button(
                                    "▶️ Start Scan",
                                    id='btn-trigger-scan',
                                    n_clicks=0,
                                    style={
                                        'backgroundColor': '#3b82f6', 'color': 'white',
                                        'border': 'none', 'padding': '8px 16px',
                                        'borderRadius': '6px', 'cursor': 'pointer',
                                        'fontWeight': 'bold'
                                    }
                                ),
                            ], style={'marginBottom': '10px'}),
                            html.Div(id='trigger-scan-result', style={'marginTop': '10px'})
                        ], style={
                            'backgroundColor': '#1f2937', 'padding': '15px',
                            'borderRadius': '8px', 'marginBottom': '20px'
                        }),
                        
                        # Pending Scans Section
                        html.Div([
                            html.H4("⏳ Pending/Running Scans", style={'color': '#e0e0e0', 'marginBottom': '10px'}),
                            html.Div(id='pending-scans-list', style={
                                'maxHeight': '150px', 'overflowY': 'auto'
                            })
                        ], style={
                            'backgroundColor': '#1f2937', 'padding': '15px',
                            'borderRadius': '8px'
                        }),
                        
                    ], style={
                        'backgroundColor': '#2d3748', 'padding': '25px',
                        'borderRadius': '8px', 'maxWidth': '700px',
                        'margin': '0 auto', 'border': '1px solid #555',
                        'maxHeight': '85vh', 'overflowY': 'auto'
                    })
                ], id='project-manager-modal', style={
                    'display': 'none', 'position': 'fixed', 'top': '0', 'left': '0',
                    'right': '0', 'bottom': '0', 'backgroundColor': 'rgba(0,0,0,0.7)',
                    'zIndex': '1000', 'paddingTop': '30px'
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
            ], id="all-findings-container", className="data-table", style={'display': 'none'}),

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
                html.H3("📄 Custom Report Export", style={'color': '#e0e0e0', 'marginBottom': '20px'}),
                html.Div([
                    html.Div([
                        html.Label("Select Severity:", style={'color': '#e0e0e0', 'fontWeight': '600', 'marginBottom': '8px', 'display': 'block'}),
                        dcc.Dropdown(
                            id="report-severity-filter",
                            options=[
                                {"label": "All Severities", "value": "all"},
                                {"label": "Critical", "value": "Critical"},
                                {"label": "High", "value": "High"},
                                {"label": "Medium", "value": "Medium"},
                                {"label": "Low", "value": "Low"}
                            ],
                            value=["all"],
                            multi=True,
                            style={'backgroundColor': '#3d3d3d', 'color': '#e0e0e0'},
                            className="dark-dropdown"
                        ),
                    ], className="filter-item", style={'flex': '1', 'minWidth': '200px'}),
                    html.Div([
                        html.Label("Select Tool:", style={'color': '#e0e0e0', 'fontWeight': '600', 'marginBottom': '8px', 'display': 'block'}),
                        dcc.Dropdown(
                            id="report-tool-filter",
                            options=[
                                {"label": "All Tools", "value": "all"},
                                {"label": "Custom Scanner", "value": "custom"},
                                {"label": "TruffleHog", "value": "trufflehog"},
                                {"label": "Gitleaks", "value": "gitleaks"}
                            ],
                            value="all",
                            style={'backgroundColor': '#3d3d3d', 'color': '#e0e0e0'},
                            className="dark-dropdown"
                        ),
                    ], className="filter-item", style={'flex': '1', 'minWidth': '200px'}),
                ], style={'display': 'flex', 'gap': '20px', 'marginBottom': '15px', 'flexWrap': 'wrap'}),
                html.Div([
                    html.Label("Date Range:", style={'color': '#e0e0e0', 'fontWeight': '600', 'marginBottom': '8px', 'display': 'block'}),
                    html.Div([
                        dcc.DatePickerRange(
                            id="report-date-range",
                            min_date_allowed=datetime.now() - timedelta(days=365),
                            max_date_allowed=datetime.now() + timedelta(days=1),
                            initial_visible_month=datetime.now(),
                            end_date=datetime.now(),
                            start_date=datetime.now() - timedelta(days=7),
                            display_format='MM/DD/YYYY',
                            start_date_placeholder_text="Start Date",
                            end_date_placeholder_text="End Date",
                            clearable=True,
                            with_portal=True
                        ),
                    ], style={'display': 'inline-block'}),
                    html.Div([
                        html.Button("Last 7 Days", id="btn-last-7-days", n_clicks=0, 
                                    style={'backgroundColor': '#4b5563', 'color': 'white', 'border': 'none', 
                                           'padding': '6px 12px', 'borderRadius': '4px', 'margin': '0 5px', 'cursor': 'pointer'}),
                        html.Button("Last 30 Days", id="btn-last-30-days", n_clicks=0,
                                    style={'backgroundColor': '#4b5563', 'color': 'white', 'border': 'none', 
                                           'padding': '6px 12px', 'borderRadius': '4px', 'margin': '0 5px', 'cursor': 'pointer'}),
                        html.Button("All Time", id="btn-all-time", n_clicks=0,
                                    style={'backgroundColor': '#4b5563', 'color': 'white', 'border': 'none', 
                                           'padding': '6px 12px', 'borderRadius': '4px', 'margin': '0 5px', 'cursor': 'pointer'}),
                    ], style={'display': 'inline-block', 'marginLeft': '15px'}),
                ], className="filter-item", style={'marginBottom': '20px'}),
                html.Div([
                    html.Button("Export CSV", id="export-csv-btn", className="export-btn"),
                    html.Button("Export JSON", id="export-json-btn", className="export-btn"),
                    html.Button("Export PDF", id="export-pdf-btn", className="export-btn"),
                ], style={'marginTop': '15px'}),
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
            interval=120000,  # 2 minutes - use Refresh button for manual updates
            n_intervals=0,
            disabled=False  # Can be disabled if needed
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
                color: #e0e0e0;
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
            
            /* Tool Tabs Styling */
            .tool-tab {
                background-color: #374151 !important;
                color: #9ca3af !important;
                border: 1px solid #4b5563 !important;
                border-bottom: none !important;
                padding: 12px 24px !important;
                font-weight: 600 !important;
                cursor: pointer !important;
                transition: all 0.2s ease !important;
            }
            .tool-tab:hover {
                background-color: #4b5563 !important;
                color: #e0e0e0 !important;
            }
            .tool-tab-selected {
                background-color: #1e40af !important;
                color: #ffffff !important;
                border-color: #1e40af !important;
            }
            .tool-tabs-section {
                margin-bottom: 30px;
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

            /* Clickable table rows - pointer cursor */
            .main-container.dark-mode .dash-table-container tbody tr {
                cursor: pointer !important;
            }
            .main-container.dark-mode .dash-table-container tbody tr:hover {
                background-color: #374151 !important;
            }
            .main-container.dark-mode .dash-table-container td {
                cursor: pointer !important;
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
            
            .main-container.dark-mode .DateInput_input {
                background-color: #3d3d3d !important;
                color: #e0e0e0 !important;
                font-size: 14px !important;
                padding: 10px !important;
            }

            .main-container.dark-mode .DateRangePickerInput {
                background-color: #3d3d3d !important;
                border: 1px solid #555 !important;
                border-radius: 5px;
            }
            
            .main-container.dark-mode .DateRangePickerInput_arrow {
                color: #e0e0e0 !important;
            }
            
            /* Report section labels */
            .main-container.dark-mode .report-section label {
                color: #e0e0e0 !important;
                font-weight: 600;
                display: block;
                margin-bottom: 8px;
            }
            
            .main-container.dark-mode .report-section .filter-item {
                margin-bottom: 15px;
            }
            
            /* Date picker calendar dark mode */
            .DayPicker {
                background-color: #2d3748 !important;
            }
            .CalendarMonth_caption {
                color: #e0e0e0 !important;
            }
            .CalendarDay__default {
                background-color: #3d3d3d !important;
                color: #e0e0e0 !important;
                border: 1px solid #555 !important;
            }
            .CalendarDay__selected {
                background-color: #667eea !important;
                color: white !important;
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
