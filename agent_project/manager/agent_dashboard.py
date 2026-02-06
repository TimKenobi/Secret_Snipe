#!/usr/bin/env python3
"""
SecretSnipe Agent Management Dashboard
Dash-based UI for managing agents, viewing status, assigning jobs, etc.

This can be integrated into the main dashboard or run standalone.
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

import dash
from dash import html, dcc, Input, Output, State, callback_context, no_update
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import requests

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent-dashboard")

# API Configuration
AGENT_API_URL = os.getenv("AGENT_API_URL", "http://localhost:8443/api/v1")
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")


class AgentAPIClient:
    """Client for Agent API calls"""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        })
    
    def _request(self, method: str, endpoint: str, data: dict = None) -> Optional[dict]:
        """Make API request"""
        url = f"{self.base_url}{endpoint}"
        try:
            if method == "GET":
                resp = self.session.get(url, timeout=10)
            elif method == "POST":
                resp = self.session.post(url, json=data, timeout=10)
            elif method == "DELETE":
                resp = self.session.delete(url, timeout=10)
            else:
                return None
            
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.error(f"API error {resp.status_code}: {resp.text}")
                return None
        except Exception as e:
            logger.error(f"API request failed: {e}")
            return None
    
    def get_agents(self) -> List[dict]:
        resp = self._request("GET", "/agents")
        return resp.get("data", []) if resp else []
    
    def get_agent(self, agent_id: str) -> Optional[dict]:
        resp = self._request("GET", f"/agents/{agent_id}")
        return resp.get("data") if resp else None
    
    def delete_agent(self, agent_id: str) -> bool:
        resp = self._request("DELETE", f"/agents/{agent_id}")
        return resp.get("success", False) if resp else False
    
    def get_jobs(self, status: str = None, agent_id: str = None) -> List[dict]:
        params = []
        if status:
            params.append(f"status={status}")
        if agent_id:
            params.append(f"agent_id={agent_id}")
        query = f"?{'&'.join(params)}" if params else ""
        resp = self._request("GET", f"/jobs{query}")
        return resp.get("data", []) if resp else []
    
    def create_job(self, agent_id: str, scan_paths: List[str], 
                   scanners: List[str] = None, priority: int = 5) -> Optional[dict]:
        data = {
            "agent_id": agent_id,
            "scan_paths": scan_paths,
            "scanners": scanners or ["custom", "trufflehog", "gitleaks"],
            "priority": priority
        }
        resp = self._request("POST", "/jobs", data)
        return resp.get("data") if resp else None
    
    def get_stats(self) -> dict:
        resp = self._request("GET", "/stats")
        return resp.get("data", {}) if resp else {}
    
    def get_api_keys(self) -> List[dict]:
        resp = self._request("GET", "/keys")
        return resp.get("data", []) if resp else []
    
    def create_api_key(self, name: str, description: str = "", expires_days: int = 365) -> Optional[dict]:
        data = {"name": name, "description": description, "expires_days": expires_days}
        resp = self._request("POST", "/keys", data)
        return resp.get("data") if resp else None
    
    def revoke_api_key(self, key_id: str) -> bool:
        resp = self._request("DELETE", f"/keys/{key_id}")
        return resp.get("success", False) if resp else False


# Initialize API client
api_client = AgentAPIClient(AGENT_API_URL, AGENT_API_KEY)


def create_agent_dashboard_layout():
    """Create the agent management dashboard layout"""
    
    return html.Div([
        # Header
        html.Div([
            html.H1("🕵️ SecretSnipe Agent Management", style={'color': '#e0e0e0', 'marginBottom': '10px'}),
            html.P("Monitor and manage distributed scanning agents", style={'color': '#9ca3af'})
        ], style={'marginBottom': '30px'}),
        
        # Stats Cards Row
        html.Div(id='agent-stats-cards', className='stats-row'),
        
        # Refresh interval
        dcc.Interval(id='agent-refresh-interval', interval=30000, n_intervals=0),  # 30 seconds
        
        # Main Content Tabs
        dcc.Tabs([
            # Agents Tab
            dcc.Tab(label='🖥️ Agents', children=[
                html.Div([
                    # Agent Controls
                    html.Div([
                        html.Button("🔄 Refresh", id='btn-refresh-agents', n_clicks=0,
                                   style={'backgroundColor': '#3b82f6', 'color': 'white', 
                                          'border': 'none', 'padding': '10px 20px',
                                          'borderRadius': '6px', 'marginRight': '10px'}),
                        html.Button("➕ Create API Key", id='btn-create-api-key', n_clicks=0,
                                   style={'backgroundColor': '#22c55e', 'color': 'white',
                                          'border': 'none', 'padding': '10px 20px',
                                          'borderRadius': '6px'}),
                    ], style={'marginBottom': '20px', 'marginTop': '20px'}),
                    
                    # Agents Table
                    html.Div(id='agents-table-container'),
                    
                    # Agent Details Modal
                    html.Div([
                        html.Div([
                            html.Div([
                                html.H3("Agent Details", style={'margin': '0', 'color': '#3b82f6'}),
                                html.Button("✕", id='close-agent-detail-modal', n_clicks=0,
                                           style={'background': 'none', 'border': 'none',
                                                  'color': '#aaa', 'fontSize': '20px', 'cursor': 'pointer'})
                            ], style={'display': 'flex', 'justifyContent': 'space-between', 
                                      'alignItems': 'center', 'marginBottom': '20px'}),
                            html.Div(id='agent-detail-content'),
                            html.Div([
                                html.Button("🗑️ Delete Agent", id='btn-delete-agent', n_clicks=0,
                                           style={'backgroundColor': '#ef4444', 'color': 'white',
                                                  'border': 'none', 'padding': '10px 20px',
                                                  'borderRadius': '6px', 'marginRight': '10px'}),
                                html.Button("Close", id='btn-close-agent-detail', n_clicks=0,
                                           style={'backgroundColor': '#6b7280', 'color': 'white',
                                                  'border': 'none', 'padding': '10px 20px',
                                                  'borderRadius': '6px'}),
                            ], style={'textAlign': 'right', 'marginTop': '20px'})
                        ], style={'backgroundColor': '#2d3748', 'padding': '25px', 'borderRadius': '8px',
                                  'maxWidth': '700px', 'margin': '50px auto'})
                    ], id='agent-detail-modal', style={'display': 'none', 'position': 'fixed',
                        'top': '0', 'left': '0', 'right': '0', 'bottom': '0',
                        'backgroundColor': 'rgba(0,0,0,0.7)', 'zIndex': '10000'}),
                    
                ], style={'padding': '20px'})
            ], style={'backgroundColor': '#1f2937', 'color': '#e0e0e0'}),
            
            # Jobs Tab
            dcc.Tab(label='📋 Scan Jobs', children=[
                html.Div([
                    # Job Controls
                    html.Div([
                        html.Button("🔄 Refresh", id='btn-refresh-jobs', n_clicks=0,
                                   style={'backgroundColor': '#3b82f6', 'color': 'white',
                                          'border': 'none', 'padding': '10px 20px',
                                          'borderRadius': '6px', 'marginRight': '10px'}),
                        html.Button("➕ Create Job", id='btn-create-job', n_clicks=0,
                                   style={'backgroundColor': '#22c55e', 'color': 'white',
                                          'border': 'none', 'padding': '10px 20px',
                                          'borderRadius': '6px', 'marginRight': '10px'}),
                        dcc.Dropdown(
                            id='job-status-filter',
                            options=[
                                {'label': 'All Jobs', 'value': 'all'},
                                {'label': 'Pending', 'value': 'pending'},
                                {'label': 'Running', 'value': 'running'},
                                {'label': 'Completed', 'value': 'completed'},
                                {'label': 'Failed', 'value': 'failed'},
                            ],
                            value='all',
                            style={'width': '200px', 'display': 'inline-block', 'verticalAlign': 'middle'}
                        ),
                    ], style={'marginBottom': '20px', 'marginTop': '20px'}),
                    
                    # Jobs Table
                    html.Div(id='jobs-table-container'),
                    
                    # Create Job Modal
                    html.Div([
                        html.Div([
                            html.Div([
                                html.H3("Create Scan Job", style={'margin': '0', 'color': '#22c55e'}),
                                html.Button("✕", id='close-create-job-modal', n_clicks=0,
                                           style={'background': 'none', 'border': 'none',
                                                  'color': '#aaa', 'fontSize': '20px', 'cursor': 'pointer'})
                            ], style={'display': 'flex', 'justifyContent': 'space-between',
                                      'alignItems': 'center', 'marginBottom': '20px'}),
                            
                            html.Div([
                                html.Label("Target Agent:", style={'color': '#e0e0e0', 'marginBottom': '5px', 'display': 'block'}),
                                dcc.Dropdown(id='job-agent-selector', options=[], 
                                            placeholder='Select agent or leave empty for any',
                                            style={'backgroundColor': '#1e1e1e'})
                            ], style={'marginBottom': '15px'}),
                            
                            html.Div([
                                html.Label("Scan Paths (one per line):", style={'color': '#e0e0e0', 'marginBottom': '5px', 'display': 'block'}),
                                dcc.Textarea(id='job-scan-paths', 
                                            placeholder='/path/to/scan\n/another/path',
                                            style={'width': '100%', 'height': '100px', 'backgroundColor': '#1e1e1e',
                                                   'color': '#e0e0e0', 'border': '1px solid #555', 'borderRadius': '4px', 'padding': '10px'})
                            ], style={'marginBottom': '15px'}),
                            
                            html.Div([
                                html.Label("Scanners:", style={'color': '#e0e0e0', 'marginBottom': '5px', 'display': 'block'}),
                                dcc.Checklist(
                                    id='job-scanners',
                                    options=[
                                        {'label': ' Custom Scanner', 'value': 'custom'},
                                        {'label': ' TruffleHog', 'value': 'trufflehog'},
                                        {'label': ' Gitleaks', 'value': 'gitleaks'},
                                    ],
                                    value=['custom', 'trufflehog', 'gitleaks'],
                                    style={'color': '#e0e0e0'}
                                )
                            ], style={'marginBottom': '15px'}),
                            
                            html.Div([
                                html.Label("Priority (1-10):", style={'color': '#e0e0e0', 'marginBottom': '5px', 'display': 'block'}),
                                dcc.Slider(id='job-priority', min=1, max=10, value=5, step=1,
                                          marks={1: '1 (Low)', 5: '5 (Normal)', 10: '10 (High)'})
                            ], style={'marginBottom': '25px'}),
                            
                            html.Div(id='create-job-result', style={'marginBottom': '15px'}),
                            
                            html.Div([
                                html.Button("🚀 Create Job", id='btn-submit-job', n_clicks=0,
                                           style={'backgroundColor': '#22c55e', 'color': 'white',
                                                  'border': 'none', 'padding': '10px 20px',
                                                  'borderRadius': '6px', 'marginRight': '10px', 'fontWeight': 'bold'}),
                                html.Button("Cancel", id='btn-cancel-create-job', n_clicks=0,
                                           style={'backgroundColor': '#6b7280', 'color': 'white',
                                                  'border': 'none', 'padding': '10px 20px',
                                                  'borderRadius': '6px'}),
                            ], style={'textAlign': 'right'})
                        ], style={'backgroundColor': '#2d3748', 'padding': '25px', 'borderRadius': '8px',
                                  'maxWidth': '600px', 'margin': '50px auto'})
                    ], id='create-job-modal', style={'display': 'none', 'position': 'fixed',
                        'top': '0', 'left': '0', 'right': '0', 'bottom': '0',
                        'backgroundColor': 'rgba(0,0,0,0.7)', 'zIndex': '10000'}),
                    
                ], style={'padding': '20px'})
            ], style={'backgroundColor': '#1f2937', 'color': '#e0e0e0'}),
            
            # API Keys Tab
            dcc.Tab(label='🔑 API Keys', children=[
                html.Div([
                    html.Div([
                        html.Button("🔄 Refresh", id='btn-refresh-keys', n_clicks=0,
                                   style={'backgroundColor': '#3b82f6', 'color': 'white',
                                          'border': 'none', 'padding': '10px 20px',
                                          'borderRadius': '6px', 'marginRight': '10px'}),
                        html.Button("➕ Create API Key", id='btn-open-create-key', n_clicks=0,
                                   style={'backgroundColor': '#22c55e', 'color': 'white',
                                          'border': 'none', 'padding': '10px 20px',
                                          'borderRadius': '6px'}),
                    ], style={'marginBottom': '20px', 'marginTop': '20px'}),
                    
                    html.Div(id='api-keys-table-container'),
                    
                    # Create API Key Modal
                    html.Div([
                        html.Div([
                            html.Div([
                                html.H3("Create API Key", style={'margin': '0', 'color': '#f59e0b'}),
                                html.Button("✕", id='close-create-key-modal', n_clicks=0,
                                           style={'background': 'none', 'border': 'none',
                                                  'color': '#aaa', 'fontSize': '20px', 'cursor': 'pointer'})
                            ], style={'display': 'flex', 'justifyContent': 'space-between',
                                      'alignItems': 'center', 'marginBottom': '20px'}),
                            
                            html.Div([
                                html.Label("Key Name:", style={'color': '#e0e0e0', 'marginBottom': '5px', 'display': 'block'}),
                                dcc.Input(id='new-key-name', type='text', placeholder='e.g., Production Agent Key',
                                         style={'width': '100%', 'padding': '10px', 'backgroundColor': '#1e1e1e',
                                                'color': '#e0e0e0', 'border': '1px solid #555', 'borderRadius': '4px'})
                            ], style={'marginBottom': '15px'}),
                            
                            html.Div([
                                html.Label("Description:", style={'color': '#e0e0e0', 'marginBottom': '5px', 'display': 'block'}),
                                dcc.Input(id='new-key-description', type='text', placeholder='Optional description',
                                         style={'width': '100%', 'padding': '10px', 'backgroundColor': '#1e1e1e',
                                                'color': '#e0e0e0', 'border': '1px solid #555', 'borderRadius': '4px'})
                            ], style={'marginBottom': '15px'}),
                            
                            html.Div([
                                html.Label("Expires In (days):", style={'color': '#e0e0e0', 'marginBottom': '5px', 'display': 'block'}),
                                dcc.Input(id='new-key-expires', type='number', value=365, min=1, max=3650,
                                         style={'width': '100px', 'padding': '10px', 'backgroundColor': '#1e1e1e',
                                                'color': '#e0e0e0', 'border': '1px solid #555', 'borderRadius': '4px'})
                            ], style={'marginBottom': '20px'}),
                            
                            html.Div(id='create-key-result', style={'marginBottom': '15px'}),
                            
                            html.Div([
                                html.Button("🔐 Generate Key", id='btn-generate-key', n_clicks=0,
                                           style={'backgroundColor': '#f59e0b', 'color': 'white',
                                                  'border': 'none', 'padding': '10px 20px',
                                                  'borderRadius': '6px', 'marginRight': '10px', 'fontWeight': 'bold'}),
                                html.Button("Cancel", id='btn-cancel-create-key', n_clicks=0,
                                           style={'backgroundColor': '#6b7280', 'color': 'white',
                                                  'border': 'none', 'padding': '10px 20px',
                                                  'borderRadius': '6px'}),
                            ], style={'textAlign': 'right'})
                        ], style={'backgroundColor': '#2d3748', 'padding': '25px', 'borderRadius': '8px',
                                  'maxWidth': '500px', 'margin': '50px auto'})
                    ], id='create-key-modal', style={'display': 'none', 'position': 'fixed',
                        'top': '0', 'left': '0', 'right': '0', 'bottom': '0',
                        'backgroundColor': 'rgba(0,0,0,0.7)', 'zIndex': '10000'}),
                    
                ], style={'padding': '20px'})
            ], style={'backgroundColor': '#1f2937', 'color': '#e0e0e0'}),
            
        ], style={'backgroundColor': '#1f2937'}),
        
        # Store for selected agent
        dcc.Store(id='selected-agent-id', data=None),
        
    ], style={'backgroundColor': '#111827', 'minHeight': '100vh', 'padding': '20px'})


def register_agent_callbacks(app):
    """Register all callbacks for the agent dashboard"""
    
    # ========== Stats Cards ==========
    @app.callback(
        Output('agent-stats-cards', 'children'),
        [Input('agent-refresh-interval', 'n_intervals'),
         Input('btn-refresh-agents', 'n_clicks')]
    )
    def update_stats_cards(n_intervals, n_clicks):
        stats = api_client.get_stats()
        
        agents_by_status = stats.get('agents_by_status', {})
        jobs_by_status = stats.get('jobs_by_status', {})
        
        cards = [
            # Total Agents
            html.Div([
                html.Div("🖥️", style={'fontSize': '32px'}),
                html.Div([
                    html.Div(str(stats.get('total_agents', 0)), style={'fontSize': '28px', 'fontWeight': 'bold'}),
                    html.Div("Total Agents", style={'color': '#9ca3af', 'fontSize': '14px'})
                ])
            ], style={'backgroundColor': '#1f2937', 'padding': '20px', 'borderRadius': '8px',
                      'display': 'flex', 'alignItems': 'center', 'gap': '15px', 'flex': '1'}),
            
            # Online Agents
            html.Div([
                html.Div("🟢", style={'fontSize': '32px'}),
                html.Div([
                    html.Div(str(agents_by_status.get('online', 0)), style={'fontSize': '28px', 'fontWeight': 'bold', 'color': '#22c55e'}),
                    html.Div("Online", style={'color': '#9ca3af', 'fontSize': '14px'})
                ])
            ], style={'backgroundColor': '#1f2937', 'padding': '20px', 'borderRadius': '8px',
                      'display': 'flex', 'alignItems': 'center', 'gap': '15px', 'flex': '1'}),
            
            # Scanning Agents
            html.Div([
                html.Div("🔍", style={'fontSize': '32px'}),
                html.Div([
                    html.Div(str(agents_by_status.get('scanning', 0)), style={'fontSize': '28px', 'fontWeight': 'bold', 'color': '#3b82f6'}),
                    html.Div("Scanning", style={'color': '#9ca3af', 'fontSize': '14px'})
                ])
            ], style={'backgroundColor': '#1f2937', 'padding': '20px', 'borderRadius': '8px',
                      'display': 'flex', 'alignItems': 'center', 'gap': '15px', 'flex': '1'}),
            
            # Pending Jobs
            html.Div([
                html.Div("📋", style={'fontSize': '32px'}),
                html.Div([
                    html.Div(str(jobs_by_status.get('pending', 0)), style={'fontSize': '28px', 'fontWeight': 'bold', 'color': '#f59e0b'}),
                    html.Div("Pending Jobs", style={'color': '#9ca3af', 'fontSize': '14px'})
                ])
            ], style={'backgroundColor': '#1f2937', 'padding': '20px', 'borderRadius': '8px',
                      'display': 'flex', 'alignItems': 'center', 'gap': '15px', 'flex': '1'}),
            
            # Total Findings
            html.Div([
                html.Div("🔐", style={'fontSize': '32px'}),
                html.Div([
                    html.Div(str(stats.get('total_findings', 0)), style={'fontSize': '28px', 'fontWeight': 'bold', 'color': '#ef4444'}),
                    html.Div("Findings from Agents", style={'color': '#9ca3af', 'fontSize': '14px'})
                ])
            ], style={'backgroundColor': '#1f2937', 'padding': '20px', 'borderRadius': '8px',
                      'display': 'flex', 'alignItems': 'center', 'gap': '15px', 'flex': '1'}),
        ]
        
        return html.Div(cards, style={'display': 'flex', 'gap': '20px', 'marginBottom': '30px', 'flexWrap': 'wrap'})
    
    # ========== Agents Table ==========
    @app.callback(
        Output('agents-table-container', 'children'),
        [Input('agent-refresh-interval', 'n_intervals'),
         Input('btn-refresh-agents', 'n_clicks')]
    )
    def update_agents_table(n_intervals, n_clicks):
        agents = api_client.get_agents()
        
        if not agents:
            return html.Div([
                html.P("No agents registered yet.", style={'color': '#9ca3af', 'textAlign': 'center', 'padding': '40px'}),
                html.P("Deploy agents to remote hosts and they will appear here.", style={'color': '#6b7280', 'textAlign': 'center'})
            ])
        
        # Status badge styles
        status_colors = {
            'online': '#22c55e',
            'offline': '#ef4444',
            'scanning': '#3b82f6',
            'error': '#f59e0b',
            'pending': '#6b7280'
        }
        
        rows = []
        for agent in agents:
            status = agent.get('status', 'unknown')
            last_hb = agent.get('last_heartbeat')
            if last_hb:
                try:
                    hb_time = datetime.fromisoformat(last_hb.replace('Z', '+00:00'))
                    hb_str = hb_time.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    hb_str = str(last_hb)[:19]
            else:
                hb_str = 'Never'
            
            rows.append(
                html.Tr([
                    html.Td(agent.get('hostname', 'Unknown'), style={'padding': '12px'}),
                    html.Td(agent.get('ip_address', 'N/A'), style={'padding': '12px'}),
                    html.Td(agent.get('os_type', 'N/A'), style={'padding': '12px'}),
                    html.Td(
                        html.Span(status.upper(), style={
                            'backgroundColor': status_colors.get(status, '#6b7280'),
                            'color': 'white', 'padding': '4px 10px', 'borderRadius': '12px',
                            'fontSize': '11px', 'fontWeight': 'bold'
                        }),
                        style={'padding': '12px'}
                    ),
                    html.Td(', '.join(agent.get('capabilities', [])), style={'padding': '12px', 'fontSize': '12px'}),
                    html.Td(hb_str, style={'padding': '12px', 'fontSize': '12px'}),
                    html.Td([
                        html.Button("View", id={'type': 'view-agent-btn', 'index': agent.get('agent_id')},
                                   style={'backgroundColor': '#3b82f6', 'color': 'white', 'border': 'none',
                                          'padding': '5px 15px', 'borderRadius': '4px', 'cursor': 'pointer', 'marginRight': '8px'}),
                        html.Button("🗑️ Delete", id={'type': 'delete-agent-btn', 'index': agent.get('agent_id')},
                                   style={'backgroundColor': '#ef4444', 'color': 'white', 'border': 'none',
                                          'padding': '5px 15px', 'borderRadius': '4px', 'cursor': 'pointer'}),
                    ], style={'padding': '12px'}),
                ], style={'borderBottom': '1px solid #374151'})
            )
        
        return html.Table([
            html.Thead(
                html.Tr([
                    html.Th("Hostname", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("IP Address", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("OS", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Status", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Capabilities", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Last Heartbeat", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Actions", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                ])
            ),
            html.Tbody(rows)
        ], style={'width': '100%', 'backgroundColor': '#1f2937', 'borderRadius': '8px', 'color': '#e0e0e0'})
    
    # ========== Jobs Table ==========
    @app.callback(
        Output('jobs-table-container', 'children'),
        [Input('agent-refresh-interval', 'n_intervals'),
         Input('btn-refresh-jobs', 'n_clicks'),
         Input('job-status-filter', 'value')]
    )
    def update_jobs_table(n_intervals, n_clicks, status_filter):
        status = None if status_filter == 'all' else status_filter
        jobs = api_client.get_jobs(status=status)
        
        if not jobs:
            return html.Div([
                html.P("No scan jobs found.", style={'color': '#9ca3af', 'textAlign': 'center', 'padding': '40px'}),
            ])
        
        status_colors = {
            'pending': '#f59e0b',
            'assigned': '#8b5cf6',
            'running': '#3b82f6',
            'completed': '#22c55e',
            'failed': '#ef4444',
            'cancelled': '#6b7280'
        }
        
        rows = []
        for job in jobs:
            status = job.get('status', 'unknown')
            created = job.get('created_at', '')[:19] if job.get('created_at') else 'N/A'
            
            rows.append(
                html.Tr([
                    html.Td(job.get('job_id', 'N/A')[:12], style={'padding': '12px', 'fontFamily': 'monospace'}),
                    html.Td(job.get('agent_id', 'Any')[:12] if job.get('agent_id') else 'Any', 
                           style={'padding': '12px', 'fontFamily': 'monospace'}),
                    html.Td(
                        html.Span(status.upper(), style={
                            'backgroundColor': status_colors.get(status, '#6b7280'),
                            'color': 'white', 'padding': '4px 10px', 'borderRadius': '12px',
                            'fontSize': '11px', 'fontWeight': 'bold'
                        }),
                        style={'padding': '12px'}
                    ),
                    html.Td(str(len(job.get('scan_paths', []))), style={'padding': '12px'}),
                    html.Td(str(job.get('findings_count', 0)), style={'padding': '12px'}),
                    html.Td(str(job.get('files_scanned', 0)), style={'padding': '12px'}),
                    html.Td(created, style={'padding': '12px', 'fontSize': '12px'}),
                ], style={'borderBottom': '1px solid #374151'})
            )
        
        return html.Table([
            html.Thead(
                html.Tr([
                    html.Th("Job ID", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Agent", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Status", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Paths", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Findings", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Files", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Created", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                ])
            ),
            html.Tbody(rows)
        ], style={'width': '100%', 'backgroundColor': '#1f2937', 'borderRadius': '8px', 'color': '#e0e0e0'})
    
    # ========== Create Job Modal ==========
    @app.callback(
        [Output('create-job-modal', 'style'),
         Output('job-agent-selector', 'options')],
        [Input('btn-create-job', 'n_clicks'),
         Input('close-create-job-modal', 'n_clicks'),
         Input('btn-cancel-create-job', 'n_clicks'),
         Input('btn-submit-job', 'n_clicks')],
        prevent_initial_call=True
    )
    def toggle_create_job_modal(open_clicks, close_clicks, cancel_clicks, submit_clicks):
        ctx = callback_context
        if not ctx.triggered:
            return {'display': 'none'}, []
        
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        
        visible_style = {
            'display': 'block', 'position': 'fixed', 'top': '0', 'left': '0',
            'right': '0', 'bottom': '0', 'backgroundColor': 'rgba(0,0,0,0.7)',
            'zIndex': '10000', 'overflowY': 'auto'
        }
        
        if trigger_id == 'btn-create-job':
            # Load agents for dropdown
            agents = api_client.get_agents()
            options = [{'label': 'Any Available Agent', 'value': ''}]
            for agent in agents:
                if agent.get('status') in ['online', 'scanning']:
                    options.append({
                        'label': f"{agent.get('hostname')} ({agent.get('agent_id')[:8]})",
                        'value': agent.get('agent_id')
                    })
            return visible_style, options
        
        return {'display': 'none'}, []
    
    @app.callback(
        Output('create-job-result', 'children'),
        [Input('btn-submit-job', 'n_clicks')],
        [State('job-agent-selector', 'value'),
         State('job-scan-paths', 'value'),
         State('job-scanners', 'value'),
         State('job-priority', 'value')],
        prevent_initial_call=True
    )
    def submit_new_job(n_clicks, agent_id, scan_paths, scanners, priority):
        if not n_clicks or not scan_paths:
            return ""
        
        paths = [p.strip() for p in scan_paths.strip().split('\n') if p.strip()]
        if not paths:
            return html.Span("❌ Please enter at least one scan path", style={'color': '#ef4444'})
        
        result = api_client.create_job(
            agent_id=agent_id if agent_id else None,
            scan_paths=paths,
            scanners=scanners,
            priority=priority
        )
        
        if result:
            return html.Span(f"✅ Job created: {result.get('job_id')}", style={'color': '#22c55e'})
        return html.Span("❌ Failed to create job", style={'color': '#ef4444'})
    
    # ========== API Keys Table ==========
    @app.callback(
        Output('api-keys-table-container', 'children'),
        [Input('agent-refresh-interval', 'n_intervals'),
         Input('btn-refresh-keys', 'n_clicks')]
    )
    def update_api_keys_table(n_intervals, n_clicks):
        keys = api_client.get_api_keys()
        
        if not keys:
            return html.Div([
                html.P("No API keys found.", style={'color': '#9ca3af', 'textAlign': 'center', 'padding': '40px'}),
            ])
        
        rows = []
        for key in keys:
            is_active = key.get('is_active', False)
            expires = key.get('expires_at', '')[:10] if key.get('expires_at') else 'Never'
            last_used = key.get('last_used_at', '')[:19] if key.get('last_used_at') else 'Never'
            
            rows.append(
                html.Tr([
                    html.Td(key.get('key_prefix', '') + '...', style={'padding': '12px', 'fontFamily': 'monospace'}),
                    html.Td(key.get('name', 'N/A'), style={'padding': '12px'}),
                    html.Td(key.get('description', ''), style={'padding': '12px', 'fontSize': '12px', 'color': '#9ca3af'}),
                    html.Td(
                        html.Span('Active' if is_active else 'Revoked', style={
                            'backgroundColor': '#22c55e' if is_active else '#ef4444',
                            'color': 'white', 'padding': '4px 10px', 'borderRadius': '12px',
                            'fontSize': '11px', 'fontWeight': 'bold'
                        }),
                        style={'padding': '12px'}
                    ),
                    html.Td(expires, style={'padding': '12px', 'fontSize': '12px'}),
                    html.Td(last_used, style={'padding': '12px', 'fontSize': '12px'}),
                    html.Td(
                        html.Button("Revoke", id={'type': 'revoke-key-btn', 'index': str(key.get('id'))},
                                   disabled=not is_active,
                                   style={'backgroundColor': '#ef4444' if is_active else '#6b7280', 
                                          'color': 'white', 'border': 'none',
                                          'padding': '5px 15px', 'borderRadius': '4px', 
                                          'cursor': 'pointer' if is_active else 'not-allowed'}),
                        style={'padding': '12px'}
                    ),
                ], style={'borderBottom': '1px solid #374151'})
            )
        
        return html.Table([
            html.Thead(
                html.Tr([
                    html.Th("Key Prefix", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Name", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Description", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Status", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Expires", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Last Used", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Actions", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                ])
            ),
            html.Tbody(rows)
        ], style={'width': '100%', 'backgroundColor': '#1f2937', 'borderRadius': '8px', 'color': '#e0e0e0'})
    
    # ========== Create API Key Modal ==========
    @app.callback(
        Output('create-key-modal', 'style'),
        [Input('btn-open-create-key', 'n_clicks'),
         Input('btn-create-api-key', 'n_clicks'),
         Input('close-create-key-modal', 'n_clicks'),
         Input('btn-cancel-create-key', 'n_clicks')],
        prevent_initial_call=True
    )
    def toggle_create_key_modal(open1, open2, close1, close2):
        ctx = callback_context
        if not ctx.triggered:
            return {'display': 'none'}
        
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        
        if trigger_id in ['btn-open-create-key', 'btn-create-api-key']:
            return {
                'display': 'block', 'position': 'fixed', 'top': '0', 'left': '0',
                'right': '0', 'bottom': '0', 'backgroundColor': 'rgba(0,0,0,0.7)',
                'zIndex': '10000'
            }
        
        return {'display': 'none'}
    
    @app.callback(
        Output('create-key-result', 'children'),
        [Input('btn-generate-key', 'n_clicks')],
        [State('new-key-name', 'value'),
         State('new-key-description', 'value'),
         State('new-key-expires', 'value')],
        prevent_initial_call=True
    )
    def generate_api_key(n_clicks, name, description, expires_days):
        if not n_clicks or not name:
            return ""
        
        result = api_client.create_api_key(name, description or "", expires_days or 365)
        
        if result and result.get('api_key'):
            return html.Div([
                html.P("✅ API Key Created Successfully!", style={'color': '#22c55e', 'fontWeight': 'bold'}),
                html.P("⚠️ Copy this key now - it won't be shown again!", style={'color': '#f59e0b', 'fontSize': '12px'}),
                html.Div([
                    html.Code(result['api_key'], style={
                        'backgroundColor': '#1e1e1e', 'padding': '15px', 'display': 'block',
                        'borderRadius': '4px', 'wordBreak': 'break-all', 'fontSize': '12px',
                        'border': '2px solid #22c55e'
                    })
                ], style={'marginTop': '10px'})
            ])
        
        return html.Span("❌ Failed to create API key", style={'color': '#ef4444'})

    # ========== Delete Agent from Table ==========
    @app.callback(
        Output('agents-table-container', 'children', allow_duplicate=True),
        [Input({'type': 'delete-agent-btn', 'index': dash.ALL}, 'n_clicks')],
        prevent_initial_call=True
    )
    def delete_agent_from_table(n_clicks_list):
        if not any(n_clicks_list):
            return no_update
        
        ctx = callback_context
        if not ctx.triggered:
            return no_update
        
        # Get which button was clicked
        triggered = ctx.triggered[0]
        prop_id = triggered['prop_id']
        
        # Extract agent_id from the pattern match
        import json as json_module
        try:
            button_id = json_module.loads(prop_id.rsplit('.', 1)[0])
            agent_id = button_id['index']
        except:
            return no_update
        
        # Delete the agent
        if api_client.delete_agent(agent_id):
            logger.info(f"Deleted agent {agent_id}")
        
        # Refresh the table
        agents = api_client.get_agents()
        
        if not agents:
            return html.Div([
                html.P("No agents registered yet.", style={'color': '#9ca3af', 'textAlign': 'center', 'padding': '40px'}),
                html.P("Deploy agents to remote hosts and they will appear here.", style={'color': '#6b7280', 'textAlign': 'center'})
            ])
        
        status_colors = {
            'online': '#22c55e', 'offline': '#ef4444', 'scanning': '#3b82f6',
            'error': '#f59e0b', 'pending': '#6b7280'
        }
        
        rows = []
        for agent in agents:
            status = agent.get('status', 'unknown')
            last_hb = agent.get('last_heartbeat')
            hb_str = str(last_hb)[:19] if last_hb else 'Never'
            
            rows.append(
                html.Tr([
                    html.Td(agent.get('hostname', 'Unknown'), style={'padding': '12px'}),
                    html.Td(agent.get('ip_address', 'N/A'), style={'padding': '12px'}),
                    html.Td(agent.get('os_type', 'N/A'), style={'padding': '12px'}),
                    html.Td(
                        html.Span(status.upper(), style={
                            'backgroundColor': status_colors.get(status, '#6b7280'),
                            'color': 'white', 'padding': '4px 10px', 'borderRadius': '12px',
                            'fontSize': '11px', 'fontWeight': 'bold'
                        }), style={'padding': '12px'}
                    ),
                    html.Td(', '.join(agent.get('capabilities', [])), style={'padding': '12px', 'fontSize': '12px'}),
                    html.Td(hb_str, style={'padding': '12px', 'fontSize': '12px'}),
                    html.Td([
                        html.Button("View", id={'type': 'view-agent-btn', 'index': agent.get('agent_id')},
                                   style={'backgroundColor': '#3b82f6', 'color': 'white', 'border': 'none',
                                          'padding': '5px 15px', 'borderRadius': '4px', 'cursor': 'pointer', 'marginRight': '8px'}),
                        html.Button("🗑️ Delete", id={'type': 'delete-agent-btn', 'index': agent.get('agent_id')},
                                   style={'backgroundColor': '#ef4444', 'color': 'white', 'border': 'none',
                                          'padding': '5px 15px', 'borderRadius': '4px', 'cursor': 'pointer'}),
                    ], style={'padding': '12px'}),
                ], style={'borderBottom': '1px solid #374151'})
            )
        
        return html.Table([
            html.Thead(
                html.Tr([
                    html.Th("Hostname", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("IP Address", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("OS", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Status", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Capabilities", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Last Heartbeat", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                    html.Th("Actions", style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #374151'}),
                ])
            ),
            html.Tbody(rows)
        ], style={'width': '100%', 'backgroundColor': '#1f2937', 'borderRadius': '8px', 'color': '#e0e0e0'})


# ==================== Standalone App ====================

def create_standalone_app():
    """Create standalone Dash app for agent management"""
    app = dash.Dash(
        __name__,
        external_stylesheets=[dbc.themes.DARKLY],
        suppress_callback_exceptions=True
    )
    
    app.layout = create_agent_dashboard_layout()
    register_agent_callbacks(app)
    
    return app


if __name__ == "__main__":
    app = create_standalone_app()
    app.run(debug=False, host='0.0.0.0', port=8051)
