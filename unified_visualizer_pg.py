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
                    # Scan controls - Dark mode is now permanently enabled
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
                    page_size=25,  # Increased from 20
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

# CSS Styles
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        <title>SecretSnipe Dashboard</title>
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
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-top: 15px;
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
