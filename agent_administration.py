"""
SecretSnipe Agent Administration Module
=======================================
This module adds agent fleet management capabilities to the unified dashboard.
It can be imported and integrated into unified_visualizer_pg.py.

Features:
- Agent Fleet Overview (status, health, metrics)
- Job Management (create, monitor, cancel)
- Finding Management (review, resolve, false positive)
- Schedule Management (CRUD operations)
- Watch Path Configuration
- Remote Configuration Push
- Agent Logs Viewer
- Real-time Updates
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from functools import wraps
import hashlib

from dash import html, dcc, dash_table, Input, Output, State, callback, no_update, ALL, MATCH
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

logger = logging.getLogger(__name__)

# ============================================================================
# AGENT DATABASE MANAGER
# ============================================================================

class AgentDatabaseManager:
    """Database operations for agent management - connects to AGENT MANAGER database"""
    
    def __init__(self, db_manager):
        """Initialize with existing database manager from unified_visualizer (for local tables)"""
        self.main_db = db_manager
        # Agent manager database connection settings
        self.agent_db_host = os.environ.get('AGENT_DB_HOST', '10.150.110.24')
        self.agent_db_port = int(os.environ.get('AGENT_DB_PORT', 5433))
        self.agent_db_name = 'secretsnipe_agents'
        self.agent_db_user = 'secretsnipe'
        self.agent_db_pass = 'secretsnipe_secure_pass'
    
    def _get_agent_db_connection(self):
        """Get connection to agent manager database"""
        import psycopg2
        import psycopg2.extras
        return psycopg2.connect(
            host=self.agent_db_host,
            port=self.agent_db_port,
            database=self.agent_db_name,
            user=self.agent_db_user,
            password=self.agent_db_pass,
            cursor_factory=psycopg2.extras.RealDictCursor
        )
    
    def _execute_agent_query(self, query, params=None):
        """Execute query on agent database"""
        try:
            conn = self._get_agent_db_connection()
            cur = conn.cursor()
            cur.execute(query, params or ())
            if query.strip().upper().startswith('SELECT'):
                results = cur.fetchall()
            else:
                conn.commit()
                results = cur.rowcount
            cur.close()
            conn.close()
            return results
        except Exception as e:
            logger.error(f"Agent DB query error: {e}")
            return None
    
    def get_agent_stats(self) -> Dict:
        """Get aggregate agent statistics from agent manager database"""
        query = """
            SELECT
                COUNT(*) FILTER (WHERE status = 'online' OR (status = 'idle' AND last_heartbeat > NOW() - INTERVAL '2 minutes')) as online_agents,
                COUNT(*) FILTER (WHERE status = 'offline' OR (last_heartbeat < NOW() - INTERVAL '2 minutes' AND status != 'online')) as offline_agents,
                COUNT(*) FILTER (WHERE status = 'error') as error_agents,
                COUNT(*) FILTER (WHERE status = 'pending') as pending_agents,
                (SELECT COUNT(*) FROM agent_jobs WHERE status = 'pending') as pending_jobs,
                (SELECT COUNT(*) FROM agent_jobs WHERE status = 'running') as running_jobs,
                (SELECT COUNT(*) FROM agent_findings WHERE status = 'open') as open_findings,
                (SELECT COUNT(*) FROM agent_findings WHERE status = 'open' AND severity = 'Critical') as critical_findings,
                (SELECT COUNT(*) FROM agent_findings WHERE status = 'open' AND severity = 'High') as high_findings
            FROM agents
        """
        try:
            results = self._execute_agent_query(query)
            if results and len(results) > 0:
                return dict(results[0])
            return {'online_agents': 0, 'offline_agents': 0, 'error_agents': 0, 'pending_agents': 0,
                    'pending_jobs': 0, 'running_jobs': 0, 'open_findings': 0, 'critical_findings': 0, 'high_findings': 0}
        except Exception as e:
            logger.error(f"Error getting agent stats: {e}")
            return {'online_agents': 0, 'offline_agents': 0, 'error_agents': 0, 'pending_agents': 0,
                    'pending_jobs': 0, 'running_jobs': 0, 'open_findings': 0, 'critical_findings': 0, 'high_findings': 0}
    
    def list_agents(self, status: str = None) -> List[Dict]:
        """List all agents from agent manager database"""
        query = """
            SELECT 
                agent_id,
                hostname,
                ip_address,
                os_type,
                status,
                last_heartbeat,
                EXTRACT(EPOCH FROM (NOW() - last_heartbeat)) as seconds_since_heartbeat,
                capabilities,
                registered_at
            FROM agents
        """
        
        if status:
            query += f" WHERE status = '{status}'"
        
        query += " ORDER BY hostname"
        
        try:
            results = self._execute_agent_query(query)
            if results:
                return [dict(r) for r in results]
            return []
        except Exception as e:
            logger.error(f"Error listing agents: {e}")
            return []
    
    def mark_stale_agents_offline(self):
        """Mark agents offline if no heartbeat in 2 minutes"""
        query = """
            UPDATE agents 
            SET status = 'offline'
            WHERE status NOT IN ('offline', 'pending', 'error')
            AND last_heartbeat < NOW() - INTERVAL '2 minutes'
        """
        try:
            self._execute_agent_query(query)
        except Exception as e:
            logger.error(f"Error marking stale agents: {e}")
    
    def list_jobs(self, limit: int = 100, status: str = None, agent_id: str = None) -> List[Dict]:
        """List jobs with filters from agent manager database"""
        conditions = []
        if status:
            conditions.append(f"aj.status = '{status}'")
        if agent_id:
            conditions.append(f"aj.agent_id = '{agent_id}'::uuid")
        
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        
        query = f"""
            SELECT 
                aj.*,
                a.hostname as agent_hostname
            FROM agent_jobs aj
            LEFT JOIN agents a ON aj.agent_id = a.agent_id
            {where_clause}
            ORDER BY aj.created_at DESC
            LIMIT {limit}
        """
        
        try:
            results = self._execute_agent_query(query)
            return [dict(r) for r in results] if results else []
        except Exception as e:
            logger.error(f"Error listing jobs: {e}")
            return []
    
    def create_job(self, agent_id: str, scan_paths: List[str], scanners: List[str] = None,
                   job_type: str = 'scan', priority: int = 5) -> Optional[Dict]:
        """Create a new scan job in agent manager database"""
        import uuid
        job_id = str(uuid.uuid4())
        scanners = scanners or ['custom', 'gitleaks', 'trufflehog']
        
        try:
            conn = self._get_agent_db_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO agent_jobs (job_id, agent_id, job_type, scan_paths, scanners, priority, status)
                VALUES (%s::uuid, %s::uuid, %s, %s::jsonb, %s::jsonb, %s, 'pending')
                RETURNING *
            """, (job_id, agent_id, job_type, json.dumps(scan_paths), json.dumps(scanners), priority))
            result = cur.fetchone()
            conn.commit()
            cur.close()
            conn.close()
            return dict(result) if result else None
        except Exception as e:
            logger.error(f"Error creating job: {e}")
            return None
    
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a pending or running job"""
        try:
            conn = self._get_agent_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE agent_jobs 
                SET status = 'cancelled', completed_at = NOW()
                WHERE job_id = %s::uuid AND status IN ('pending', 'assigned')
                RETURNING job_id
            """, (job_id,))
            result = cur.fetchone()
            conn.commit()
            cur.close()
            conn.close()
            return bool(result)
        except Exception as e:
            logger.error(f"Error cancelling job: {e}")
            return False
    
    def list_findings(self, limit: int = 500, status: str = None, 
                      severity: str = None, agent_id: str = None) -> List[Dict]:
        """List agent findings with filters from agent manager database"""
        conditions = []
        if status:
            conditions.append(f"af.status = '{status}'")
        if severity:
            conditions.append(f"af.severity = '{severity}'")
        if agent_id:
            conditions.append(f"af.agent_id = '{agent_id}'::uuid")
        
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        
        query = f"""
            SELECT 
                af.*,
                a.hostname as agent_hostname
            FROM agent_findings af
            LEFT JOIN agents a ON af.agent_id = a.agent_id
            {where_clause}
            ORDER BY af.found_at DESC
            LIMIT {limit}
        """
        
        try:
            results = self._execute_agent_query(query)
            return [dict(r) for r in results] if results else []
        except Exception as e:
            logger.error(f"Error listing findings: {e}")
            return []
    
    def update_finding_status(self, finding_id: str, status: str, 
                              reviewed_by: str = None, notes: str = None) -> bool:
        """Update finding status in agent manager database"""
        is_false_positive = status == 'false_positive'
        try:
            conn = self._get_agent_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE agent_findings 
                SET status = %s, reviewed_by = %s, reviewed_at = NOW(), notes = %s,
                    is_false_positive = %s
                WHERE finding_id = %s::uuid
                RETURNING finding_id
            """, (status, reviewed_by, notes, is_false_positive, finding_id))
            result = cur.fetchone()
            conn.commit()
            cur.close()
            conn.close()
            return bool(result)
        except Exception as e:
            logger.error(f"Error updating finding: {e}")
            return False
    
    def list_schedules(self, agent_id: str = None) -> List[Dict]:
        """List scheduled scans from agent manager database"""
        query = """
            SELECT 
                s.*,
                a.hostname as agent_hostname
            FROM scan_schedules s
            LEFT JOIN agents a ON s.agent_id = a.agent_id
        """
        if agent_id:
            query += f" WHERE s.agent_id = '{agent_id}'::uuid"
        query += " ORDER BY s.name"
        
        try:
            results = self._execute_agent_query(query)
            return [dict(r) for r in results] if results else []
        except Exception as e:
            logger.error(f"Error listing schedules: {e}")
            return []
    
    def get_agent_logs(self, agent_id: str = None, level: str = None, 
                       limit: int = 500) -> List[Dict]:
        """Get agent logs from agent manager database"""
        conditions = []
        if agent_id:
            conditions.append(f"al.agent_id = '{agent_id}'::uuid")
        if level:
            conditions.append(f"al.level = '{level}'")
        
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        
        query = f"""
            SELECT 
                al.*,
                a.hostname as agent_hostname
            FROM agent_logs al
            LEFT JOIN agents a ON al.agent_id = a.agent_id
            {where_clause}
            ORDER BY al.timestamp DESC
            LIMIT {limit}
        """
        
        try:
            results = self._execute_agent_query(query)
            return [dict(r) for r in results] if results else []
        except Exception as e:
            logger.error(f"Error getting logs: {e}")
            return []
    
    # ========== API Key Management ==========
    
    def list_api_keys(self) -> List[Dict]:
        """List all API keys from agent manager database"""
        query = """
            SELECT id, key_prefix, name, description, is_active, 
                   created_at, expires_at, last_used_at
            FROM agent_api_keys
            ORDER BY created_at DESC
        """
        try:
            results = self._execute_agent_query(query)
            return [dict(r) for r in results] if results else []
        except Exception as e:
            logger.error(f"Error listing API keys: {e}")
            return []
    
    def create_api_key(self, name: str, description: str = "", expires_days: int = 365) -> tuple:
        """Create a new API key in agent manager database. Returns (key, key_id)"""
        import secrets
        # Generate 128-character key (96 bytes base64)
        key = secrets.token_urlsafe(96)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        key_prefix = key[:8]
        
        try:
            conn = self._get_agent_db_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO agent_api_keys (key_hash, key_prefix, name, description, expires_at)
                VALUES (%s, %s, %s, %s, NOW() + interval '%s days')
                RETURNING id
            """, (key_hash, key_prefix, name, description, expires_days))
            result = cur.fetchone()
            conn.commit()
            cur.close()
            conn.close()
            return key, str(result['id']) if result else None
        except Exception as e:
            logger.error(f"Error creating API key: {e}")
            raise
    
    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key by setting is_active to false"""
        try:
            conn = self._get_agent_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE agent_api_keys SET is_active = false WHERE id = %s
            """, (int(key_id),))
            affected = cur.rowcount
            conn.commit()
            cur.close()
            conn.close()
            return affected > 0
        except Exception as e:
            logger.error(f"Error revoking API key: {e}")
            return False
    
    def update_api_key_expiration(self, key_id: str, new_expires: datetime) -> bool:
        """Update API key expiration date"""
        try:
            conn = self._get_agent_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE agent_api_keys SET expires_at = %s WHERE id = %s
            """, (new_expires, int(key_id)))
            affected = cur.rowcount
            conn.commit()
            cur.close()
            conn.close()
            return affected > 0
        except Exception as e:
            logger.error(f"Error updating API key expiration: {e}")
            return False
    
    # ========== Agent Commands ==========
    
    def queue_agent_command(self, agent_id: str, command: str, parameters: Dict = None) -> str:
        """Queue a command for an agent to execute on next heartbeat"""
        try:
            conn = self._get_agent_db_connection()
            cur = conn.cursor()
            
            # Ensure table exists
            cur.execute("""
                CREATE TABLE IF NOT EXISTS agent_commands (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    agent_id VARCHAR(64) NOT NULL,
                    command VARCHAR(50) NOT NULL,
                    parameters JSONB DEFAULT '{}',
                    status VARCHAR(50) DEFAULT 'pending',
                    result JSONB,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    completed_at TIMESTAMP WITH TIME ZONE
                )
            """)
            
            cur.execute("""
                INSERT INTO agent_commands (agent_id, command, parameters, status)
                VALUES (%s, %s, %s, 'pending')
                RETURNING id
            """, (agent_id, command, json.dumps(parameters or {})))
            result = cur.fetchone()
            conn.commit()
            cur.close()
            conn.close()
            return str(result['id']) if result else None
        except Exception as e:
            logger.error(f"Error queuing agent command: {e}")
            raise
    
    def get_agent_paths(self, agent_id: str) -> List[str]:
        """Get available paths from agent (from command results)"""
        try:
            query = """
                SELECT result FROM agent_commands
                WHERE agent_id = %s AND command = 'list_paths' AND status = 'completed'
                ORDER BY completed_at DESC
                LIMIT 1
            """
            conn = self._get_agent_db_connection()
            cur = conn.cursor()
            cur.execute(query, (agent_id,))
            result = cur.fetchone()
            cur.close()
            conn.close()
            
            if result and result.get('result'):
                paths_data = result['result'] if isinstance(result['result'], dict) else json.loads(result['result'])
                return paths_data.get('paths', [])
            return []
        except Exception as e:
            logger.error(f"Error getting agent paths: {e}")
            return []
    
    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent from the database"""
        try:
            conn = self._get_agent_db_connection()
            cur = conn.cursor()
            cur.execute("DELETE FROM agents WHERE agent_id = %s", (agent_id,))
            affected = cur.rowcount
            conn.commit()
            cur.close()
            conn.close()
            return affected > 0
        except Exception as e:
            logger.error(f"Error deleting agent: {e}")
            return False


# ============================================================================
# LAYOUT COMPONENTS
# ============================================================================

def create_stat_card(title: str, value: Any, icon: str, color: str = "primary") -> html.Div:
    """Create a statistics card"""
    return html.Div([
        html.Div([
            html.Span(icon, style={'fontSize': '24px'}),
            html.H3(str(value), style={'margin': '5px 0', 'fontSize': '28px', 'fontWeight': 'bold'}),
            html.P(title, style={'margin': '0', 'fontSize': '12px', 'opacity': '0.8'})
        ], style={
            'textAlign': 'center',
            'padding': '15px',
            'backgroundColor': f'var(--{color}-bg, #2d3748)',
            'borderRadius': '8px',
            'border': f'1px solid var(--{color}-border, #4a5568)'
        })
    ], className='stat-card')


# ============================================================================
# SCAN CONFIGURATION SECTION (NEW - Unified scan management)
# ============================================================================

def create_scan_configuration_section() -> html.Div:
    """Create the unified scan configuration section - the heart of scan management"""
    return html.Div([
        html.H3("⚙️ Scan Configuration", style={'marginBottom': '20px'}),
        html.P("Configure how and where scanning is performed. Define scan targets and assign them to the server or specific agents.",
               style={'color': '#888', 'marginBottom': '20px'}),
        
        # Scanning Mode Selection
        html.Div([
            html.H4("🎯 Scanning Mode", style={'marginBottom': '15px'}),
            dcc.RadioItems(
                id='admin-scan-mode',
                options=[
                    {'label': html.Span([
                        html.Strong('Server Only'), 
                        html.Span(' - Scanner runs on this server only', style={'color': '#888', 'marginLeft': '10px'})
                    ]), 'value': 'server'},
                    {'label': html.Span([
                        html.Strong('Agents Only'),
                        html.Span(' - Remote agents handle all scanning', style={'color': '#888', 'marginLeft': '10px'})
                    ]), 'value': 'agents'},
                    {'label': html.Span([
                        html.Strong('Hybrid'),
                        html.Span(' - Server + Agents (assign per target)', style={'color': '#888', 'marginLeft': '10px'})
                    ]), 'value': 'hybrid'},
                ],
                value=None,  # Will be set by load_scan_mode callback from stored value
                style={'display': 'flex', 'flexDirection': 'column', 'gap': '12px'},
                labelStyle={'display': 'flex', 'alignItems': 'center', 'padding': '10px', 
                           'backgroundColor': '#252525', 'borderRadius': '6px', 'cursor': 'pointer'}
            ),
        ], className='admin-section', style={'marginBottom': '20px'}),
        
        # Scan Targets
        html.Div([
            html.Div([
                html.H4("📁 Scan Targets", style={'margin': '0'}),
                html.Button("➕ Add Target", id='admin-add-target-btn', className='btn-primary',
                           title='Add a new scan target with path and scanner configuration')
            ], style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center', 'marginBottom': '15px'}),
            
            html.P("Define what paths to scan and which scanner (server or agent) handles each target.",
                   style={'color': '#888', 'fontSize': '13px', 'marginBottom': '15px'}),
            
            # Target list
            dash_table.DataTable(
                id='admin-scan-targets-table',
                columns=[
                    {'name': '✓', 'id': 'enabled'},
                    {'name': 'Target Name', 'id': 'name'},
                    {'name': 'Scan Paths', 'id': 'paths'},
                    {'name': 'Scanner', 'id': 'scanner_name'},
                    {'name': 'Tools', 'id': 'tools'},
                    {'name': 'Schedule', 'id': 'schedule'},
                    {'name': 'Last Scan', 'id': 'last_scan'},
                    {'name': 'Status', 'id': 'status'},
                ],
                data=[
                    # Example data - will be populated from database
                    {'enabled': '✅', 'name': 'Server Local Scan', 'paths': '/scan', 
                     'scanner_name': '🖥️ Server', 'tools': 'All', 'schedule': 'Continuous', 
                     'last_scan': '2m ago', 'status': '🟢 Running'},
                ],
                style_table={'overflowX': 'auto'},
                style_cell={
                    'backgroundColor': '#1e1e1e',
                    'color': '#e0e0e0',
                    'textAlign': 'left',
                    'padding': '12px'
                },
                style_header={
                    'backgroundColor': '#2d2d2d',
                    'fontWeight': 'bold'
                },
                row_selectable='single',
                page_size=10,
            ),
            
            # Quick actions for selected target
            html.Div([
                html.Button("▶️ Run Now", id='admin-run-target-btn', className='btn-success', 
                           title='Immediately start a scan for the selected target',
                           style={'marginRight': '10px'}),
                html.Button("✏️ Edit", id='admin-edit-target-btn', className='btn-secondary',
                           title='Edit the selected scan target configuration',
                           style={'marginRight': '10px'}),
                html.Button("🗑️ Delete", id='admin-delete-target-btn', className='btn-warning',
                           title='Delete the selected scan target (cannot be undone)'),
            ], style={'marginTop': '15px'})
        ], className='admin-section', style={'marginBottom': '20px'}),
        
        # Store for tracking edit state
        dcc.Store(id='admin-target-edit-id', data=None),
        
        # Add/Edit Target Modal (inline form)
        html.Div([
            html.H4("➕ Add Scan Target", id='admin-target-form-title', style={'marginBottom': '15px'}),
            
            html.Div([
                html.Div([
                    html.Label("Target Name:"),
                    dcc.Input(id='admin-target-name', placeholder='e.g., Finance Share',
                              style={'width': '100%', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                                     'border': '1px solid #444', 'padding': '10px', 'borderRadius': '4px'})
                ], style={'flex': '1'}),
                html.Div([
                    html.Label("Scan Path(s):"),
                    dcc.Input(id='admin-target-paths', 
                              placeholder='e.g., \\\\server\\share or /mnt/data (comma-separated for multiple)',
                              style={'width': '100%', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                                     'border': '1px solid #444', 'padding': '10px', 'borderRadius': '4px'})
                ], style={'flex': '2'}),
            ], style={'display': 'flex', 'gap': '15px', 'marginBottom': '15px'}),
            
            html.Div([
                html.Div([
                    html.Label("Assigned Scanner:"),
                    dcc.Dropdown(
                        id='admin-target-scanner',
                        options=[
                            {'label': '🖥️ Server (Local)', 'value': 'server'},
                            # Agent options populated dynamically
                        ],
                        placeholder='Select scanner...',
                        style={'backgroundColor': '#2d2d2d'}
                    ),
                    html.Small("Choose which scanner can access this path", 
                              style={'color': '#666', 'fontSize': '11px'})
                ], style={'flex': '1'}),
                html.Div([
                    html.Label("Scanner Tools:"),
                    dcc.Checklist(
                        id='admin-target-tools',
                        options=[
                            {'label': ' 🔍 Custom Patterns', 'value': 'custom'},
                            {'label': ' 🐷 TruffleHog', 'value': 'trufflehog'},
                            {'label': ' 🔐 Gitleaks', 'value': 'gitleaks'},
                        ],
                        value=['custom', 'trufflehog', 'gitleaks'],
                        style={'display': 'flex', 'gap': '15px'},
                        labelStyle={'display': 'flex', 'alignItems': 'center'}
                    )
                ], style={'flex': '2'}),
            ], style={'display': 'flex', 'gap': '15px', 'marginBottom': '15px'}),
            
            html.Div([
                html.Div([
                    html.Label("Schedule:"),
                    dcc.Dropdown(
                        id='admin-target-schedule',
                        options=[
                            {'label': '🔄 Continuous (watch for changes)', 'value': 'continuous'},
                            {'label': '⏰ Every Hour', 'value': '0 * * * *'},
                            {'label': '📅 Daily at Midnight', 'value': '0 0 * * *'},
                            {'label': '📅 Weekly (Sunday)', 'value': '0 0 * * 0'},
                            {'label': '🖱️ Manual Only', 'value': 'manual'},
                            {'label': '⚙️ Custom Cron...', 'value': 'custom'},
                        ],
                        value='continuous',
                        style={'backgroundColor': '#2d2d2d'}
                    )
                ], style={'flex': '1'}),
                html.Div([
                    html.Label("Custom Cron (if selected):"),
                    dcc.Input(id='admin-target-cron', placeholder='e.g., */30 * * * *',
                              style={'width': '100%', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                                     'border': '1px solid #444', 'padding': '10px', 'borderRadius': '4px'})
                ], style={'flex': '1'}),
            ], style={'display': 'flex', 'gap': '15px', 'marginBottom': '20px'}),
            
            html.Div([
                html.Button("💾 Save Target", id='admin-save-target-btn', className='btn-primary'),
                html.Button("Cancel", id='admin-cancel-target-btn', className='btn-secondary', 
                           style={'marginLeft': '10px'}),
            ]),
            html.Div(id='admin-target-save-result', style={'marginTop': '10px'})
        ], id='admin-target-form', className='admin-form', 
           style={'display': 'none', 'marginTop': '20px'}),  # Hidden by default
    ])


def create_agent_overview_section() -> html.Div:
    """Create the agent fleet overview section with path assignments"""
    return html.Div([
        html.H3("🖥️ Agent Fleet", style={'marginBottom': '20px'}),
        html.P("Each agent can only scan paths it has direct access to. Assign scan targets to specific agents in Scan Config.",
               style={'color': '#888', 'marginBottom': '20px', 'fontSize': '13px'}),
        
        # Action Result Div
        html.Div(id='admin-agent-action-result', style={'marginBottom': '15px'}),
        
        # Stats Row
        html.Div([
            html.Div(id='admin-stat-online', className='admin-stat-card'),
            html.Div(id='admin-stat-offline', className='admin-stat-card'),
            html.Div(id='admin-stat-jobs', className='admin-stat-card'),
            html.Div(id='admin-stat-findings', className='admin-stat-card'),
            html.Div(id='admin-stat-critical', className='admin-stat-card'),
        ], style={
            'display': 'grid',
            'gridTemplateColumns': 'repeat(5, 1fr)',
            'gap': '15px',
            'marginBottom': '20px'
        }),
        
        # Agents Table - Enhanced with configured paths
        html.Div([
            html.Div([
                html.H4("Registered Agents"),
                html.Div([
                    html.Button("🔄 Refresh", id='admin-refresh-agents', className='btn-secondary',
                               title='Refresh agent list and status'),
                ], style={'display': 'flex', 'gap': '10px'})
            ], style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center'}),
            
            html.P("💡 Tip: Each agent should be deployed on the server that has direct access to the shares/paths it will scan.",
                   style={'color': '#666', 'fontSize': '12px', 'marginBottom': '15px', 'fontStyle': 'italic'}),
            
            # Dynamic agent list with delete buttons
            html.Div(id='admin-agents-list', children=[]),
            
            # Agent Management Actions
            html.Div([
                html.H5("Agent Actions", style={'marginBottom': '10px', 'marginTop': '20px'}),
                html.P("Select an agent above to manage it. Actions are queued and executed on the next heartbeat.",
                       style={'color': '#666', 'fontSize': '12px', 'marginBottom': '15px'}),
                html.Div([
                    html.Button("🔍 Discover Paths", id='admin-agent-discover-paths', className='btn-secondary',
                               title='Request agent to list available directories/drives that can be scanned',
                               style={'marginRight': '10px'}),
                    html.Button("🔄 Restart Agent", id='admin-agent-restart', className='btn-warning',
                               title='Restart the agent service remotely (may briefly interrupt scans)',
                               style={'marginRight': '10px'}),
                    html.Button("⬆️ Update Agent", id='admin-agent-update', className='btn-primary',
                               title='Push agent software update (agent will download and restart)',
                               style={'marginRight': '10px'}),
                    html.Button("🗑️ Remove Agent", id='admin-agent-remove', className='btn-warning',
                               title='Remove agent registration from server (agent will need to re-register)'),
                ], style={'marginBottom': '15px'}),
                
                # Store for selected agent
                dcc.Store(id='admin-selected-agent-id', data=None),
                
                # Agent paths display
                html.Div(id='admin-agent-paths-display', style={'marginTop': '15px'}),
            ], className='admin-form', style={'backgroundColor': '#252525', 'padding': '20px', 'borderRadius': '8px'})
            
        ], className='admin-section')
    ])


def create_job_management_section() -> html.Div:
    """Create the job management section"""
    return html.Div([
        html.H3("📋 Job Management", style={'marginBottom': '20px'}),
        
        # Create Job Form
        html.Div([
            html.H4("Create New Scan Job"),
            html.Div([
                html.Div([
                    html.Label("Target Agent:"),
                    dcc.Dropdown(
                        id='admin-job-agent-select',
                        placeholder='Select an agent...',
                        style={'backgroundColor': '#2d2d2d'}
                    ),
                    html.Button("🔍 Browse Paths", id='admin-browse-agent-paths', className='btn-secondary',
                               title='Discover available paths on the selected agent',
                               style={'marginTop': '5px', 'fontSize': '11px', 'padding': '4px 8px'}),
                ], style={'flex': '1'}),
                
                html.Div([
                    html.Label("Scan Path:"),
                    html.Div([
                        dcc.Input(
                            id='admin-job-path',
                            type='text',
                            placeholder='e.g., C:\\SharedDrives or /mnt/cifs',
                            style={'width': '100%', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                                   'border': '1px solid #444', 'padding': '8px', 'borderRadius': '4px'}
                        ),
                        # Path suggestions dropdown (populated after Browse Paths)
                        dcc.Dropdown(
                            id='admin-job-path-suggestions',
                            placeholder='Or select from discovered paths...',
                            style={'backgroundColor': '#2d2d2d', 'marginTop': '5px'},
                            options=[]
                        ),
                    ])
                ], style={'flex': '2'}),
                
                html.Div([
                    html.Label("Scanners:"),
                    dcc.Checklist(
                        id='admin-job-scanners',
                        options=[
                            {'label': ' Custom', 'value': 'custom'},
                            {'label': ' Gitleaks', 'value': 'gitleaks'},
                            {'label': ' Trufflehog', 'value': 'trufflehog'},
                        ],
                        value=['custom', 'gitleaks', 'trufflehog'],
                        inline=True,
                        style={'color': '#e0e0e0'}
                    )
                ], style={'flex': '1'}),
                
                html.Button("🚀 Create Job", id='admin-create-job-btn', className='btn-primary',
                           title='Create a new scan job for the selected agent and path')
            ], style={'display': 'flex', 'gap': '15px', 'alignItems': 'flex-end', 'marginBottom': '15px'}),
            
            # Path discovery result
            html.Div(id='admin-path-discovery-result', style={'marginBottom': '10px'}),
            html.Div(id='admin-job-result', style={'marginTop': '10px'})
        ], className='admin-form'),
        
        # Jobs Table
        html.Div([
            html.Div([
                html.H4("Recent Jobs"),
                html.Div([
                    dcc.Dropdown(
                        id='admin-job-status-filter',
                        options=[
                            {'label': 'All Status', 'value': 'all'},
                            {'label': 'Pending', 'value': 'pending'},
                            {'label': 'Running', 'value': 'running'},
                            {'label': 'Completed', 'value': 'completed'},
                            {'label': 'Failed', 'value': 'failed'},
                        ],
                        value='all',
                        style={'width': '150px', 'backgroundColor': '#2d2d2d'}
                    ),
                    html.Button("🔄 Refresh", id='admin-refresh-jobs', className='btn-secondary',
                               title='Refresh the jobs table')
                ], style={'display': 'flex', 'gap': '10px'})
            ], style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center'}),
            
            dash_table.DataTable(
                id='admin-jobs-table',
                columns=[
                    {'name': 'Status', 'id': 'status_icon'},
                    {'name': 'Agent', 'id': 'agent_hostname'},
                    {'name': 'Type', 'id': 'job_type'},
                    {'name': 'Paths', 'id': 'scan_paths_str'},
                    {'name': 'Files', 'id': 'files_scanned'},
                    {'name': 'Findings', 'id': 'findings_count'},
                    {'name': 'Created', 'id': 'created_str'},
                    {'name': 'Duration', 'id': 'duration'},
                ],
                data=[],
                style_table={'overflowX': 'auto'},
                style_cell={
                    'backgroundColor': '#1e1e1e',
                    'color': '#e0e0e0',
                    'textAlign': 'left',
                    'padding': '10px'
                },
                style_header={
                    'backgroundColor': '#2d2d2d',
                    'fontWeight': 'bold'
                },
                row_selectable='single',
                page_size=15,
            )
        ], className='admin-section')
    ])


def create_findings_section() -> html.Div:
    """Create the agent findings management section"""
    return html.Div([
        html.H3("🔍 Agent Findings", style={'marginBottom': '20px'}),
        
        # Filters
        html.Div([
            html.Div([
                html.Label("Severity:"),
                dcc.Dropdown(
                    id='admin-finding-severity-filter',
                    options=[
                        {'label': 'All', 'value': 'all'},
                        {'label': 'Critical', 'value': 'Critical'},
                        {'label': 'High', 'value': 'High'},
                        {'label': 'Medium', 'value': 'Medium'},
                        {'label': 'Low', 'value': 'Low'},
                    ],
                    value='all',
                    style={'backgroundColor': '#2d2d2d'}
                )
            ], style={'flex': '1'}),
            
            html.Div([
                html.Label("Status:"),
                dcc.Dropdown(
                    id='admin-finding-status-filter',
                    options=[
                        {'label': 'All', 'value': 'all'},
                        {'label': 'Open', 'value': 'open'},
                        {'label': 'Resolved', 'value': 'resolved'},
                        {'label': 'False Positive', 'value': 'false_positive'},
                        {'label': 'Accepted Risk', 'value': 'accepted_risk'},
                    ],
                    value='open',
                    style={'backgroundColor': '#2d2d2d'}
                )
            ], style={'flex': '1'}),
            
            html.Div([
                html.Label("Agent:"),
                dcc.Dropdown(
                    id='admin-finding-agent-filter',
                    placeholder='All Agents',
                    style={'backgroundColor': '#2d2d2d'}
                )
            ], style={'flex': '1'}),
            
            html.Button("🔄 Refresh", id='admin-refresh-findings', className='btn-secondary',
                       style={'alignSelf': 'flex-end'})
        ], style={'display': 'flex', 'gap': '15px', 'marginBottom': '20px'}),
        
        # Auto-sync notice
        html.Div([
            html.Span("ℹ️ ", style={'color': '#4dabf7'}),
            html.Span("Findings are automatically synced from agents in real-time when discovered.",
                     style={'color': '#888', 'fontSize': '13px'})
        ], style={'marginBottom': '15px', 'padding': '10px', 'backgroundColor': '#1a2a4a', 
                 'borderRadius': '4px', 'border': '1px solid #2d4a6f'}),
        
        # Bulk Actions
        html.Div([
            html.Button("✅ Mark Resolved", id='admin-bulk-resolve', className='btn-success',
                       title='Mark selected findings as resolved'),
            html.Button("🚫 Mark False Positive", id='admin-bulk-false-positive', className='btn-warning',
                       title='Mark selected findings as false positives (they will be ignored in future scans)'),
        ], style={'display': 'flex', 'gap': '10px', 'marginBottom': '15px'}),
        
        # Hidden sync button (for callback compatibility)
        html.Button("Sync", id='admin-sync-findings', style={'display': 'none'}),
        
        # Findings Table
        dash_table.DataTable(
            id='admin-findings-table',
            columns=[
                {'name': 'Sev', 'id': 'severity_icon'},
                {'name': 'Type', 'id': 'secret_type'},
                {'name': 'File', 'id': 'file_path'},
                {'name': 'Line', 'id': 'line_number'},
                {'name': 'Scanner', 'id': 'scanner'},
                {'name': 'Agent', 'id': 'agent_hostname'},
                {'name': 'Found', 'id': 'found_str'},
                {'name': 'Status', 'id': 'status'},
            ],
            data=[],
            style_table={'overflowX': 'auto'},
            style_cell={
                'backgroundColor': '#1e1e1e',
                'color': '#e0e0e0',
                'textAlign': 'left',
                'padding': '10px',
                'maxWidth': '300px',
                'overflow': 'hidden',
                'textOverflow': 'ellipsis'
            },
            style_header={
                'backgroundColor': '#2d2d2d',
                'fontWeight': 'bold'
            },
            style_data_conditional=[
                {'if': {'filter_query': '{severity} = Critical'}, 'backgroundColor': '#4a1a1a'},
                {'if': {'filter_query': '{severity} = High'}, 'backgroundColor': '#3a2a1a'},
                {'if': {'filter_query': '{status} = resolved'}, 'backgroundColor': '#1a3a2a'},
            ],
            row_selectable='multi',
            page_size=20,
        ),
        
        # Finding Detail Modal
        html.Div(id='admin-finding-detail-modal')
    ])


def create_logs_section() -> html.Div:
    """Create the agent logs viewer section"""
    return html.Div([
        html.H3("📜 Agent Logs", style={'marginBottom': '20px'}),
        
        # Filters
        html.Div([
            html.Div([
                html.Label("Agent:"),
                dcc.Dropdown(
                    id='admin-log-agent-filter',
                    placeholder='All Agents',
                    style={'backgroundColor': '#2d2d2d'}
                )
            ], style={'flex': '1'}),
            
            html.Div([
                html.Label("Level:"),
                dcc.Dropdown(
                    id='admin-log-level-filter',
                    options=[
                        {'label': 'All Levels', 'value': 'all'},
                        {'label': 'ERROR', 'value': 'ERROR'},
                        {'label': 'WARNING', 'value': 'WARNING'},
                        {'label': 'INFO', 'value': 'INFO'},
                        {'label': 'DEBUG', 'value': 'DEBUG'},
                    ],
                    value='all',
                    style={'backgroundColor': '#2d2d2d'}
                )
            ], style={'flex': '1'}),
            
            html.Div([
                html.Label("Search:"),
                dcc.Input(
                    id='admin-log-search',
                    type='text',
                    placeholder='Search logs...',
                    style={'width': '100%', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                           'border': '1px solid #444', 'padding': '8px', 'borderRadius': '4px'}
                )
            ], style={'flex': '2'}),
            
            html.Button("🔄 Refresh", id='admin-refresh-logs', className='btn-secondary',
                       style={'alignSelf': 'flex-end'})
        ], style={'display': 'flex', 'gap': '15px', 'marginBottom': '20px'}),
        
        # Logs Container
        html.Div(
            id='admin-logs-container',
            style={
                'backgroundColor': '#0d0d0d',
                'padding': '15px',
                'borderRadius': '8px',
                'fontFamily': 'monospace',
                'fontSize': '12px',
                'maxHeight': '500px',
                'overflowY': 'auto',
                'border': '1px solid #333'
            }
        ),
        
        # Auto-refresh toggle
        html.Div([
            dcc.Checklist(
                id='admin-log-auto-refresh',
                options=[{'label': ' Auto-refresh every 10 seconds', 'value': 'auto'}],
                value=[],
                style={'color': '#e0e0e0'}
            )
        ], style={'marginTop': '10px'})
    ])


def create_schedules_section() -> html.Div:
    """Create the schedule management section"""
    return html.Div([
        html.H3("📅 Scheduled Scans", style={'marginBottom': '20px'}),
        html.P("Configure scheduled scans and continuous monitoring for your agents.",
               style={'color': '#888', 'marginBottom': '20px'}),
        
        # Schedule Type Selection
        html.Div([
            html.H4("Schedule Type", style={'marginBottom': '15px'}),
            dcc.RadioItems(
                id='admin-schedule-type',
                options=[
                    {'label': ' ⏰ Scheduled Scan - Run at regular intervals', 'value': 'scheduled'},
                    {'label': ' 👁️ Continuous Monitoring - Watch for file changes', 'value': 'continuous'},
                ],
                value='scheduled',
                style={'color': '#e0e0e0'},
                labelStyle={'display': 'block', 'marginBottom': '10px', 'padding': '10px',
                           'backgroundColor': '#252525', 'borderRadius': '6px', 'cursor': 'pointer'}
            ),
        ], className='admin-form', style={'marginBottom': '20px'}),
        
        # Scheduled Scan Form - Updated for Windows compatibility (interval-based)
        html.Div([
            html.H4("Create Scheduled Scan"),
            html.P("Schedules use interval-based execution compatible with Windows Task Scheduler.",
                   style={'color': '#888', 'fontSize': '12px', 'marginBottom': '15px'}),
            html.Div([
                html.Div([
                    html.Label("Agent:"),
                    dcc.Dropdown(
                        id='admin-schedule-agent',
                        placeholder='Select agent...',
                        style={'backgroundColor': '#2d2d2d'}
                    )
                ], style={'flex': '1'}),
                
                html.Div([
                    html.Label("Schedule Name:"),
                    dcc.Input(
                        id='admin-schedule-name',
                        type='text',
                        placeholder='e.g., Nightly CIFS Scan',
                        style={'width': '100%', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                               'border': '1px solid #444', 'padding': '8px', 'borderRadius': '4px'}
                    )
                ], style={'flex': '1'}),
            ], style={'display': 'flex', 'gap': '15px', 'marginBottom': '15px'}),
            
            html.Div([
                html.Div([
                    html.Label("Repeat Interval:"),
                    dcc.Dropdown(
                        id='admin-schedule-preset',
                        options=[
                            {'label': 'Every Hour', 'value': '1h'},
                            {'label': 'Every 6 Hours', 'value': '6h'},
                            {'label': 'Every 12 Hours', 'value': '12h'},
                            {'label': 'Daily (24 Hours)', 'value': '24h'},
                            {'label': 'Every 3 Days', 'value': '72h'},
                            {'label': 'Weekly (7 Days)', 'value': '168h'},
                            {'label': 'Monthly (30 Days)', 'value': '720h'},
                            {'label': 'Custom Interval...', 'value': 'custom'},
                        ],
                        value='24h',
                        style={'backgroundColor': '#2d2d2d'}
                    )
                ], style={'flex': '1'}),
                
                html.Div([
                    html.Label("Custom Interval (hours):"),
                    dcc.Input(
                        id='admin-schedule-cron',
                        type='number',
                        placeholder='e.g., 48 for every 2 days',
                        min=1,
                        max=8760,
                        style={'width': '100%', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                               'border': '1px solid #444', 'padding': '8px', 'borderRadius': '4px'}
                    ),
                    html.Small("Format: minute hour day month weekday", style={'color': '#666', 'fontSize': '11px'})
                ], style={'flex': '1'}),
                
                html.Div([
                    html.Label("Scan Paths:"),
                    dcc.Input(
                        id='admin-schedule-paths',
                        type='text',
                        placeholder='Comma-separated paths',
                        style={'width': '100%', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                               'border': '1px solid #444', 'padding': '8px', 'borderRadius': '4px'}
                    )
                ], style={'flex': '2'}),
            ], style={'display': 'flex', 'gap': '15px', 'marginBottom': '15px'}),
            
            html.Button("➕ Create Schedule", id='admin-create-schedule-btn', className='btn-primary',
                       title='Create a new scheduled scan that will run at the specified times'),
            html.Div(id='admin-schedule-result', style={'marginTop': '10px'})
        ], id='admin-scheduled-form', className='admin-form'),
        
        # Continuous Monitoring Form
        html.Div([
            html.H4("Configure Continuous Monitoring"),
            html.P("Agents will perform an initial full scan, then monitor for file changes and re-scan modified files.",
                   style={'color': '#888', 'marginBottom': '15px', 'fontSize': '13px'}),
            html.Div([
                html.Div([
                    html.Label("Agent:"),
                    dcc.Dropdown(
                        id='admin-continuous-agent',
                        placeholder='Select agent...',
                        style={'backgroundColor': '#2d2d2d'}
                    )
                ], style={'flex': '1'}),
                
                html.Div([
                    html.Label("Watch Paths:"),
                    dcc.Input(
                        id='admin-continuous-paths',
                        type='text',
                        placeholder='Paths to monitor for changes',
                        style={'width': '100%', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                               'border': '1px solid #444', 'padding': '8px', 'borderRadius': '4px'}
                    )
                ], style={'flex': '2'}),
            ], style={'display': 'flex', 'gap': '15px', 'marginBottom': '15px'}),
            
            html.Div([
                html.Div([
                    html.Label("Scan on Change Delay (seconds):"),
                    dcc.Input(
                        id='admin-continuous-delay',
                        type='number',
                        value=5,
                        min=1,
                        max=300,
                        style={'width': '100px', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                               'border': '1px solid #444', 'padding': '8px', 'borderRadius': '4px'}
                    ),
                    html.Small("Wait this long after a change before scanning", style={'color': '#666', 'fontSize': '11px'})
                ], style={'flex': '1'}),
                
                html.Div([
                    html.Label("Full Rescan Interval (hours):"),
                    dcc.Input(
                        id='admin-continuous-rescan',
                        type='number',
                        value=24,
                        min=1,
                        max=720,
                        style={'width': '100px', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                               'border': '1px solid #444', 'padding': '8px', 'borderRadius': '4px'}
                    ),
                    html.Small("Do a full scan after this many hours (catches any missed changes)", style={'color': '#666', 'fontSize': '11px'})
                ], style={'flex': '1'}),
            ], style={'display': 'flex', 'gap': '15px', 'marginBottom': '15px'}),
            
            html.Button("▶️ Start Monitoring", id='admin-start-continuous-btn', className='btn-success',
                       title='Start continuous monitoring for the selected agent and paths'),
            html.Div(id='admin-continuous-result', style={'marginTop': '10px'})
        ], id='admin-continuous-form', className='admin-form', style={'display': 'none'}),
        
        # Schedules Table
        html.Div([
            html.Div([
                html.H4("Active Schedules & Monitors"),
                html.Button("🔄 Refresh", id='admin-refresh-schedules', className='btn-secondary',
                           title='Refresh the schedules list')
            ], style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center', 'marginBottom': '15px'}),
            dash_table.DataTable(
                id='admin-schedules-table',
                columns=[
                    {'name': 'Enabled', 'id': 'enabled_icon'},
                    {'name': 'Name', 'id': 'name'},
                    {'name': 'Agent', 'id': 'agent_hostname'},
                    {'name': 'Cron', 'id': 'cron_expression'},
                    {'name': 'Paths', 'id': 'scan_paths_str'},
                    {'name': 'Last Run', 'id': 'last_run_str'},
                    {'name': 'Next Run', 'id': 'next_run_str'},
                ],
                data=[],
                style_table={'overflowX': 'auto'},
                style_cell={
                    'backgroundColor': '#1e1e1e',
                    'color': '#e0e0e0',
                    'textAlign': 'left',
                    'padding': '10px'
                },
                style_header={
                    'backgroundColor': '#2d2d2d',
                    'fontWeight': 'bold'
                },
                row_selectable='single',
                page_size=10,
            )
        ], className='admin-section')
    ])


def create_downloads_section() -> html.Div:
    """Create the agent downloads section"""
    return html.Div([
        html.H3("📥 Agent Downloads", style={'marginBottom': '20px'}),
        html.P("Download and install SecretSnipe agents on your endpoints.", 
               style={'color': '#888', 'marginBottom': '30px'}),
        
        # Windows Agent
        html.Div([
            html.Div([
                html.Div([
                    html.Span("🪟", style={'fontSize': '48px'}),
                ], style={'marginRight': '20px'}),
                html.Div([
                    html.H4("Windows Agent", style={'margin': '0 0 5px 0', 'color': '#4dabf7'}),
                    html.P("For Windows Server 2016+, Windows 10/11", 
                           style={'color': '#888', 'margin': '0 0 10px 0', 'fontSize': '13px'}),
                    html.Ul([
                        html.Li("Runs as Windows Service via NSSM"),
                        html.Li("DPAPI encryption for secure credential storage"),
                        html.Li("Automatic restart on failure"),
                        html.Li("Scans CIFS/SMB shares, local directories"),
                        html.Li("Supports Gitleaks, TruffleHog, Custom scanner"),
                    ], style={'color': '#aaa', 'fontSize': '12px', 'marginBottom': '15px'}),
                ], style={'flex': '1'}),
            ], style={'display': 'flex', 'alignItems': 'flex-start'}),
            html.Div([
                html.A(
                    html.Button("⬇️ Download Installer (PowerShell)", className='btn-primary',
                               style={'marginRight': '10px'}),
                    href='/api/download/agent/windows-installer',
                    download='Install-SecretSnipeAgent.ps1'
                ),
                html.A(
                    html.Button("📄 View Documentation", className='btn-secondary'),
                    href='/api/download/agent/windows-readme',
                    target='_blank'
                ),
            ], style={'marginTop': '15px'}),
        ], style={
            'backgroundColor': '#252525',
            'border': '1px solid #0078d4',
            'borderRadius': '8px',
            'padding': '25px',
            'marginBottom': '20px'
        }),
        
        # Linux Agent (Coming Soon)
        html.Div([
            html.Div([
                html.Div([
                    html.Span("🐧", style={'fontSize': '48px', 'opacity': '0.5'}),
                ], style={'marginRight': '20px'}),
                html.Div([
                    html.H4("Linux Agent", style={'margin': '0 0 5px 0', 'color': '#888'}),
                    html.Span("Coming Soon", style={
                        'backgroundColor': '#444',
                        'color': '#888',
                        'padding': '2px 8px',
                        'borderRadius': '4px',
                        'fontSize': '11px',
                        'marginLeft': '10px'
                    }),
                    html.P("For RHEL, Ubuntu, Debian, CentOS", 
                           style={'color': '#666', 'margin': '10px 0 0 0', 'fontSize': '13px'}),
                ], style={'flex': '1'}),
            ], style={'display': 'flex', 'alignItems': 'flex-start'}),
        ], style={
            'backgroundColor': '#252525',
            'border': '1px solid #444',
            'borderRadius': '8px',
            'padding': '25px',
            'marginBottom': '20px',
            'opacity': '0.6'
        }),
        
        # Installation Instructions
        html.Div([
            html.H4("🚀 Quick Start Installation", style={'marginBottom': '15px'}),
            html.Div([
                html.H5("1. Download the installer", style={'color': '#4dabf7', 'marginBottom': '5px'}),
                html.P("Click the download button above to get the PowerShell installer script.",
                      style={'color': '#aaa', 'marginBottom': '15px'}),
                
                html.H5("2. Run as Administrator", style={'color': '#4dabf7', 'marginBottom': '5px'}),
                html.Pre(
                    "# Right-click PowerShell and 'Run as Administrator'\n"
                    "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force\n"
                    ".\\Install-SecretSnipeAgent.ps1 -ManagerUrl \"https://your-server:8443\" -ApiKey \"your-api-key\"",
                    style={
                        'backgroundColor': '#1a1a1a',
                        'color': '#4ec9b0',
                        'padding': '15px',
                        'borderRadius': '6px',
                        'fontSize': '12px',
                        'overflow': 'auto',
                        'border': '1px solid #333'
                    }
                ),
                
                html.H5("3. Verify Installation", style={'color': '#4dabf7', 'marginBottom': '5px', 'marginTop': '15px'}),
                html.Pre(
                    "# Check service status\n"
                    "Get-Service SecretSnipeAgent\n\n"
                    "# View logs\n"
                    "Get-Content 'C:\\ProgramData\\SecretSnipe\\logs\\agent.log' -Tail 50",
                    style={
                        'backgroundColor': '#1a1a1a',
                        'color': '#4ec9b0',
                        'padding': '15px',
                        'borderRadius': '6px',
                        'fontSize': '12px',
                        'overflow': 'auto',
                        'border': '1px solid #333'
                    }
                ),
            ], style={'marginTop': '10px'}),
        ], className='admin-section'),
        
        # API Key Generation
        html.Div([
            html.H4("🔑 Generate API Key", style={'marginBottom': '15px'}),
            html.P("Generate a new API key for agent authentication. Keep this secure!",
                  style={'color': '#888', 'marginBottom': '15px'}),
            html.Div([
                dcc.Input(
                    id='admin-apikey-name',
                    placeholder='Key name (e.g., "Production Windows Agents")',
                    style={'flex': '1', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                           'border': '1px solid #444', 'padding': '10px', 'borderRadius': '4px'}
                ),
                html.Button("🔐 Generate Key", id='admin-generate-apikey-btn', className='btn-primary'),
            ], style={'display': 'flex', 'gap': '10px', 'marginBottom': '15px'}),
            html.Div(id='admin-apikey-result'),
        ], className='admin-section'),
    ])


def create_apikeys_section() -> html.Div:
    """Create the API Key management section"""
    return html.Div([
        html.H3("🔑 API Key Management", style={'marginBottom': '20px'}),
        html.P("Manage API keys for agent authentication. Keys are hashed and cannot be recovered once created.",
               style={'color': '#888', 'marginBottom': '20px'}),
        
        # Create New Key Form
        html.Div([
            html.H4("Create New API Key", style={'marginBottom': '15px'}),
            html.Div([
                html.Div([
                    html.Label("Key Name:"),
                    dcc.Input(
                        id='admin-new-key-name',
                        type='text',
                        placeholder='e.g., Production Agents',
                        style={'width': '100%', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                               'border': '1px solid #444', 'padding': '8px', 'borderRadius': '4px'}
                    )
                ], style={'flex': '1'}),
                
                html.Div([
                    html.Label("Description:"),
                    dcc.Input(
                        id='admin-new-key-description',
                        type='text',
                        placeholder='Optional description',
                        style={'width': '100%', 'backgroundColor': '#2d2d2d', 'color': '#e0e0e0',
                               'border': '1px solid #444', 'padding': '8px', 'borderRadius': '4px'}
                    )
                ], style={'flex': '2'}),
                
                html.Div([
                    html.Label("Expires In:"),
                    dcc.Dropdown(
                        id='admin-new-key-expires',
                        options=[
                            {'label': '30 Days', 'value': 30},
                            {'label': '90 Days', 'value': 90},
                            {'label': '180 Days', 'value': 180},
                            {'label': '1 Year', 'value': 365},
                            {'label': '2 Years', 'value': 730},
                            {'label': 'Never (not recommended)', 'value': 3650},
                        ],
                        value=365,
                        style={'backgroundColor': '#2d2d2d'}
                    )
                ], style={'flex': '1'}),
                
                html.Button("🔐 Generate Key", id='admin-create-key-btn', className='btn-primary',
                           title='Generate a new API key for agent authentication'),
            ], style={'display': 'flex', 'gap': '15px', 'alignItems': 'flex-end'}),
            
            html.Div(id='admin-new-key-result', style={'marginTop': '15px'})
        ], className='admin-form', style={'marginBottom': '30px'}),
        
        # Existing Keys Table
        html.Div([
            html.Div([
                html.H4("Existing API Keys"),
                html.Button("🔄 Refresh", id='admin-refresh-keys', className='btn-secondary',
                           title='Refresh the list of API keys')
            ], style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center', 'marginBottom': '15px'}),
            
            dash_table.DataTable(
                id='admin-apikeys-table',
                columns=[
                    {'name': 'Status', 'id': 'status_icon'},
                    {'name': 'Key Prefix', 'id': 'key_prefix'},
                    {'name': 'Name', 'id': 'name'},
                    {'name': 'Description', 'id': 'description'},
                    {'name': 'Created', 'id': 'created_at_str'},
                    {'name': 'Expires', 'id': 'expires_at_str'},
                    {'name': 'Last Used', 'id': 'last_used_str'},
                    {'name': 'Agents', 'id': 'agents_count'},
                ],
                data=[],
                style_table={'overflowX': 'auto'},
                style_cell={
                    'backgroundColor': '#1e1e1e',
                    'color': '#e0e0e0',
                    'textAlign': 'left',
                    'padding': '10px'
                },
                style_header={
                    'backgroundColor': '#2d2d2d',
                    'fontWeight': 'bold'
                },
                row_selectable='single',
                page_size=10,
            ),
            
            # Key Actions
            html.Div([
                html.Button("⏸️ Revoke Key", id='admin-revoke-key-btn', className='btn-warning',
                           style={'marginRight': '10px'},
                           title='Revoke the selected API key (agents using it will stop working)'),
                html.Button("📅 Extend Expiration", id='admin-extend-key-btn', className='btn-secondary',
                           style={'marginRight': '10px'},
                           title='Extend the expiration date of the selected key'),
                html.Button("🔍 View Usage", id='admin-key-usage-btn', className='btn-secondary',
                           title='View detailed usage statistics for the selected key'),
            ], style={'marginTop': '15px'}),
            
            html.Div(id='admin-key-action-result', style={'marginTop': '15px'}),
        ], className='admin-section'),
        
        # Security Recommendations
        html.Div([
            html.H4("🛡️ Security Best Practices", style={'marginBottom': '15px'}),
            html.Ul([
                html.Li("Rotate API keys regularly (every 90-180 days recommended)"),
                html.Li("Use separate keys for different environments (production, staging, etc.)"),
                html.Li("Revoke keys immediately if compromised"),
                html.Li("Monitor key usage for suspicious activity"),
                html.Li("Never share API keys via email or chat - use secure channels"),
                html.Li("Keys are 128+ characters and cryptographically secure"),
            ], style={'color': '#888', 'fontSize': '13px'})
        ], className='admin-section', style={'backgroundColor': '#1a2332', 'border': '1px solid #2d4a6f'})
    ])


def create_administration_layout() -> html.Div:
    """Create the full administration page layout"""
    return html.Div([
        # Header
        html.Div([
            html.H1("🛡️ SecretSnipe Agent Administration", 
                   style={'margin': '0', 'color': '#e0e0e0'}),
            html.P("Fleet Management & Monitoring", 
                  style={'margin': '5px 0 0 0', 'color': '#888', 'fontSize': '14px'}),
            html.Div([
                html.Span(id='admin-last-updated', style={'color': '#666', 'fontSize': '12px'}),
                html.Button("↩️ Back to Dashboard", id='admin-back-btn', className='btn-secondary')
            ], style={'display': 'flex', 'alignItems': 'center', 'gap': '15px'})
        ], style={
            'display': 'flex',
            'justifyContent': 'space-between',
            'alignItems': 'center',
            'padding': '20px',
            'backgroundColor': '#1a1a1a',
            'borderBottom': '1px solid #333'
        }),
        
        # Navigation Tabs - Reorganized for clarity
        dcc.Tabs(id='admin-tabs', value='config', children=[
            dcc.Tab(label='⚙️ Scan Config', value='config', className='admin-tab'),
            dcc.Tab(label='🖥️ Agents', value='overview', className='admin-tab'),
            dcc.Tab(label='📋 Jobs', value='jobs', className='admin-tab'),
            dcc.Tab(label='� Schedules', value='schedules', className='admin-tab'),
            dcc.Tab(label='🔍 Findings', value='findings', className='admin-tab'),
            dcc.Tab(label='🔑 API Keys', value='apikeys', className='admin-tab'),
            dcc.Tab(label='📜 Logs', value='logs', className='admin-tab'),
            dcc.Tab(label='📥 Downloads', value='downloads', className='admin-tab'),
        ], style={'marginBottom': '0'}),
        
        # Tab Content
        html.Div(id='admin-tab-content', style={
            'padding': '20px',
            'backgroundColor': '#1e1e1e',
            'minHeight': 'calc(100vh - 150px)'
        }),
        
        # Auto-refresh interval
        dcc.Interval(
            id='admin-refresh-interval',
            interval=30*1000,  # 30 seconds
            n_intervals=0
        ),
        
        # Stores for data
        dcc.Store(id='admin-agents-store', data=[]),
        dcc.Store(id='admin-selected-agent', data=None),
        dcc.Store(id='admin-scan-mode-store', data='hybrid', storage_type='local'),
    ], id='administration-page', style={
        'backgroundColor': '#1a1a1a',
        'color': '#e0e0e0',
        'minHeight': '100vh'
    })


# ============================================================================
# CSS STYLES
# ============================================================================

ADMIN_CSS = """
/* Administration Page Styles */
.admin-tab {
    backgroundColor: #2d2d2d !important;
    color: #e0e0e0 !important;
    border: none !important;
    padding: 10px 20px !important;
}

.admin-tab--selected {
    backgroundColor: #3d3d3d !important;
    borderBottom: 2px solid #667eea !important;
}

.admin-stat-card {
    backgroundColor: #2d3748;
    borderRadius: 8px;
    padding: 15px;
    textAlign: center;
    border: 1px solid #4a5568;
}

.admin-section {
    backgroundColor: #252525;
    borderRadius: 8px;
    padding: 20px;
    marginBottom: 20px;
    border: 1px solid #333;
}

.admin-form {
    backgroundColor: #252525;
    borderRadius: 8px;
    padding: 20px;
    marginBottom: 20px;
    border: 1px solid #444;
}

.btn-primary {
    backgroundColor: #667eea !important;
    color: white !important;
    border: none !important;
    padding: 10px 20px !important;
    borderRadius: 6px !important;
    cursor: pointer !important;
    fontWeight: 600 !important;
}

.btn-primary:hover {
    backgroundColor: #5a6fd6 !important;
}

.btn-secondary {
    backgroundColor: #4a5568 !important;
    color: white !important;
    border: none !important;
    padding: 8px 16px !important;
    borderRadius: 6px !important;
    cursor: pointer !important;
}

.btn-success {
    backgroundColor: #38a169 !important;
    color: white !important;
    border: none !important;
    padding: 8px 16px !important;
    borderRadius: 6px !important;
    cursor: pointer !important;
}

.btn-warning {
    backgroundColor: #d69e2e !important;
    color: white !important;
    border: none !important;
    padding: 8px 16px !important;
    borderRadius: 6px !important;
    cursor: pointer !important;
}

.log-entry {
    padding: 4px 8px;
    borderBottom: 1px solid #222;
    fontFamily: 'Consolas', 'Monaco', monospace;
}

.log-error {
    color: #fc8181;
    backgroundColor: #2d1f1f;
}

.log-warning {
    color: #f6e05e;
    backgroundColor: #2d2d1f;
}

.log-info {
    color: #90cdf4;
}

.log-debug {
    color: #a0aec0;
}
"""


# ============================================================================
# INTEGRATION HELPER
# ============================================================================

def integrate_with_unified_visualizer(app, db_manager):
    """
    Integrate administration module with the unified visualizer app.
    
    Call this function from unified_visualizer_pg.py to add the administration page.
    
    Usage in unified_visualizer_pg.py:
        from agent_administration import integrate_with_unified_visualizer, create_administration_layout
        
        # After creating the app
        integrate_with_unified_visualizer(app, db_manager)
    """
    
    agent_db = AgentDatabaseManager(db_manager)
    
    # Register callbacks for administration page
    
    @app.callback(
        Output('admin-tab-content', 'children'),
        Input('admin-tabs', 'value')
    )
    def render_admin_tab(tab):
        if tab == 'config':
            return create_scan_configuration_section()
        elif tab == 'overview':
            return create_agent_overview_section()
        elif tab == 'jobs':
            return create_job_management_section()
        elif tab == 'schedules':
            return create_schedules_section()
        elif tab == 'findings':
            return create_findings_section()
        elif tab == 'apikeys':
            return create_apikeys_section()
        elif tab == 'logs':
            return create_logs_section()
        elif tab == 'downloads':
            return create_downloads_section()
        return html.Div("Select a tab")
    
    @app.callback(
        [Output('admin-stat-online', 'children'),
         Output('admin-stat-offline', 'children'),
         Output('admin-stat-jobs', 'children'),
         Output('admin-stat-findings', 'children'),
         Output('admin-stat-critical', 'children')],
        [Input('admin-refresh-interval', 'n_intervals'),
         Input('admin-refresh-agents', 'n_clicks')]
    )
    def update_admin_stats(n_intervals, n_clicks):
        # Mark stale agents offline first
        agent_db.mark_stale_agents_offline()
        
        stats = agent_db.get_agent_stats()
        
        return (
            create_stat_card("Online Agents", stats.get('online_agents', 0), "🟢", "success"),
            create_stat_card("Offline Agents", stats.get('offline_agents', 0), "🔴", "danger"),
            create_stat_card("Running Jobs", stats.get('running_jobs', 0), "⚡", "primary"),
            create_stat_card("Open Findings", stats.get('open_findings', 0), "🔍", "warning"),
            create_stat_card("Critical", stats.get('critical_findings', 0), "🚨", "danger"),
        )
    
    @app.callback(
        Output('admin-agents-list', 'children'),
        [Input('admin-refresh-interval', 'n_intervals'),
         Input('admin-refresh-agents', 'n_clicks')]
    )
    def update_agents_list(n_intervals, n_clicks):
        """Build agent table with selectable rows and delete buttons"""
        agents = agent_db.list_agents()
        
        if not agents:
            return html.Div("No agents registered yet. Deploy an agent to get started.", 
                          style={'color': '#888', 'padding': '20px', 'textAlign': 'center'})
        
        # Use DataTable for proper alignment and selection
        data = []
        for a in agents:
            status_icon = {
                'online': '🟢', 'idle': '🟢',
                'offline': '🔴',
                'pending': '🟡',
                'error': '⚠️'
            }.get(a.get('status', 'offline'), '❓')
            
            last_hb = a.get('last_heartbeat')
            if last_hb:
                secs = a.get('seconds_since_heartbeat', 0) or 0
                if secs < 60:
                    last_seen = f"{int(secs)}s ago"
                elif secs < 3600:
                    last_seen = f"{int(secs/60)}m ago"
                else:
                    last_seen = f"{int(secs/3600)}h ago"
            else:
                last_seen = "Never"
            
            agent_id = str(a.get('agent_id', ''))
            data.append({
                'agent_id': agent_id,
                'status': status_icon,
                'hostname': a.get('hostname', 'Unknown'),
                'ip_address': str(a.get('ip_address', '')),
                'os_type': a.get('os_type', ''),
                'assigned_targets': '—',
                'last_seen': last_seen,
                'jobs': 0,
                'findings': 0,
            })
        
        # Return DataTable for proper alignment
        return dash_table.DataTable(
            id='admin-agents-datatable',
            columns=[
                {'name': 'Status', 'id': 'status'},
                {'name': 'Hostname', 'id': 'hostname'},
                {'name': 'IP Address', 'id': 'ip_address'},
                {'name': 'OS', 'id': 'os_type'},
                {'name': 'Assigned Targets', 'id': 'assigned_targets'},
                {'name': 'Last Seen', 'id': 'last_seen'},
                {'name': 'Jobs', 'id': 'jobs'},
                {'name': 'Findings', 'id': 'findings'},
            ],
            data=data,
            row_selectable='single',
            selected_rows=[],
            style_table={'overflowX': 'auto'},
            style_cell={
                'backgroundColor': '#1e1e1e',
                'color': '#e0e0e0',
                'textAlign': 'left',
                'padding': '12px 15px',
                'fontFamily': 'inherit',
                'fontSize': '14px',
                'border': '1px solid #333',
            },
            style_header={
                'backgroundColor': '#2d2d2d',
                'fontWeight': 'bold',
                'borderBottom': '2px solid #4a5568',
            },
            style_cell_conditional=[
                {'if': {'column_id': 'status'}, 'width': '70px', 'textAlign': 'center'},
                {'if': {'column_id': 'hostname'}, 'width': '180px'},
                {'if': {'column_id': 'ip_address'}, 'width': '140px'},
                {'if': {'column_id': 'os_type'}, 'width': '90px'},
                {'if': {'column_id': 'assigned_targets'}, 'width': '150px'},
                {'if': {'column_id': 'last_seen'}, 'width': '100px'},
                {'if': {'column_id': 'jobs'}, 'width': '60px', 'textAlign': 'center'},
                {'if': {'column_id': 'findings'}, 'width': '80px', 'textAlign': 'center'},
            ],
            style_data_conditional=[
                {'if': {'row_index': 'odd'}, 'backgroundColor': '#252525'},
            ],
        )
    
    @app.callback(
        Output('admin-job-agent-select', 'options'),
        Input('admin-refresh-interval', 'n_intervals')
    )
    def update_agent_dropdown(n_intervals):
        agents = agent_db.list_agents()
        return [
            {'label': f"{a['hostname']} ({a['status']})", 'value': str(a['agent_id'])}
            for a in agents
        ]
    
    # Callback to populate scanner dropdown with agents
    @app.callback(
        Output('admin-target-scanner', 'options'),
        Input('admin-refresh-interval', 'n_intervals')
    )
    def update_scanner_options(n_intervals):
        options = [{'label': '🖥️ Server (Local)', 'value': 'server'}]
        agents = agent_db.list_agents()
        for a in agents:
            status_icon = '🟢' if a.get('status') == 'online' else '🔴'
            options.append({
                'label': f"{status_icon} {a['hostname']}",
                'value': str(a['agent_id'])
            })
        return options
    
    # Show/hide target form
    @app.callback(
        Output('admin-target-form', 'style'),
        [Input('admin-add-target-btn', 'n_clicks'),
         Input('admin-edit-target-btn', 'n_clicks'),
         Input('admin-cancel-target-btn', 'n_clicks'),
         Input('admin-save-target-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def toggle_target_form(add_clicks, edit_clicks, cancel_clicks, save_clicks):
        from dash import ctx
        if not ctx.triggered:
            return {'display': 'none', 'marginTop': '20px'}
        
        trigger = ctx.triggered_id
        if trigger in ['admin-add-target-btn', 'admin-edit-target-btn']:
            return {'display': 'block', 'marginTop': '20px'}
        return {'display': 'none', 'marginTop': '20px'}
    
    # ========== EDIT TARGET CALLBACK ==========
    @app.callback(
        [Output('admin-target-name', 'value'),
         Output('admin-target-paths', 'value'),
         Output('admin-target-scanner', 'value'),
         Output('admin-target-tools', 'value'),
         Output('admin-target-schedule', 'value'),
         Output('admin-target-cron', 'value'),
         Output('admin-target-edit-id', 'data'),
         Output('admin-target-form-title', 'children')],
        [Input('admin-add-target-btn', 'n_clicks'),
         Input('admin-edit-target-btn', 'n_clicks')],
        [State('admin-scan-targets-table', 'selected_rows'),
         State('admin-scan-targets-table', 'data')],
        prevent_initial_call=True
    )
    def setup_target_form(add_clicks, edit_clicks, selected_rows, data):
        """Setup the target form for add or edit"""
        from dash import ctx
        trigger = ctx.triggered_id
        
        if trigger == 'admin-add-target-btn':
            # Clear form for new target
            return '', '', 'server', ['custom', 'trufflehog', 'gitleaks'], 'continuous', '', None, "➕ Add Scan Target"
        
        elif trigger == 'admin-edit-target-btn':
            if not selected_rows or not data:
                return no_update, no_update, no_update, no_update, no_update, no_update, no_update, no_update
            
            selected_idx = selected_rows[0]
            target = data[selected_idx]
            
            # Load full target data from database
            try:
                query = "SELECT * FROM scan_targets WHERE id = %s"
                results = db_manager.execute_query(query, (target.get('id'),))
                if results:
                    t = results[0]
                    tools = t.get('tools', ['custom'])
                    if isinstance(tools, str):
                        tools = json.loads(tools)
                    return (
                        t.get('name', ''),
                        t.get('paths', ''),
                        t.get('scanner', 'server'),
                        tools,
                        t.get('schedule', 'continuous'),
                        t.get('cron_expression', ''),
                        t.get('id'),
                        "✏️ Edit Scan Target"
                    )
            except Exception as e:
                logger.error(f"Error loading target for edit: {e}")
            
            return no_update, no_update, no_update, no_update, no_update, no_update, no_update, no_update
        
        return no_update, no_update, no_update, no_update, no_update, no_update, no_update, no_update
    
    # ========== SCAN MODE CALLBACKS ==========
    @app.callback(
        Output('admin-scan-mode', 'value'),
        Input('admin-scan-mode-store', 'data'),
        prevent_initial_call=False
    )
    def load_scan_mode(stored_mode):
        """Load the saved scan mode from store"""
        if stored_mode:
            return stored_mode
        return 'hybrid'
    
    @app.callback(
        Output('admin-scan-mode-store', 'data'),
        Input('admin-scan-mode', 'value'),
        prevent_initial_call=True
    )
    def save_scan_mode(mode):
        """Save the selected scan mode to persistent storage"""
        if mode is None:
            return no_update  # Don't save None value
        logger.info(f"Scan mode changed to: {mode}")
        return mode
    
    # ========== SCAN TARGETS TABLE POPULATION ==========
    @app.callback(
        Output('admin-scan-targets-table', 'data'),
        [Input('admin-refresh-interval', 'n_intervals'),
         Input('admin-tabs', 'value')]
    )
    def populate_scan_targets_table(n_intervals, tab):
        """Populate the scan targets table"""
        if tab != 'config':
            return no_update
        
        # Get scan targets from main database (these are local configuration)
        try:
            query = """
                SELECT id, name, paths, scanner, tools, schedule, cron_expression, 
                       enabled, last_scan, created_at
                FROM scan_targets
                ORDER BY name
            """
            results = db_manager.execute_query(query)
            if results:
                data = []
                for r in results:
                    data.append({
                        'id': r.get('id'),
                        'name': r.get('name', ''),
                        'paths': r.get('paths', ''),
                        'scanner': r.get('scanner', 'server'),
                        'schedule': r.get('schedule', 'manual'),
                        'enabled': '✅' if r.get('enabled', True) else '❌',
                        'last_scan': str(r.get('last_scan', 'Never'))[:16] if r.get('last_scan') else 'Never'
                    })
                return data
        except Exception as e:
            logger.error(f"Error loading scan targets: {e}")
        return []
    
    # ========== SAVE SCAN TARGET ==========
    @app.callback(
        Output('admin-target-save-result', 'children'),
        Input('admin-save-target-btn', 'n_clicks'),
        [State('admin-target-name', 'value'),
         State('admin-target-paths', 'value'),
         State('admin-target-scanner', 'value'),
         State('admin-target-tools', 'value'),
         State('admin-target-schedule', 'value'),
         State('admin-target-cron', 'value'),
         State('admin-target-edit-id', 'data')],
        prevent_initial_call=True
    )
    def save_scan_target(n_clicks, name, paths, scanner, tools, schedule, cron, edit_id):
        """Save a new or update existing scan target"""
        if not n_clicks:
            return ""
        
        if not name or not paths:
            return html.Div("❌ Name and paths are required", style={'color': '#f56565'})
        
        try:
            # Ensure scan_targets table exists
            db_manager.execute_update("""
                CREATE TABLE IF NOT EXISTS scan_targets (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    paths TEXT,
                    scanner VARCHAR(100) DEFAULT 'server',
                    tools JSONB DEFAULT '["custom"]',
                    schedule VARCHAR(50) DEFAULT 'manual',
                    cron_expression VARCHAR(100),
                    enabled BOOLEAN DEFAULT true,
                    last_scan TIMESTAMP,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)
            
            tools_json = json.dumps(tools if tools else ['custom'])
            
            if edit_id:
                # Update existing target
                query = """
                    UPDATE scan_targets 
                    SET name = %s, paths = %s, scanner = %s, tools = %s::jsonb, 
                        schedule = %s, cron_expression = %s
                    WHERE id = %s
                """
                db_manager.execute_update(query, (name, paths, scanner, tools_json, schedule, cron, edit_id))
                return html.Div("✅ Scan target updated successfully!", style={'color': '#48bb78'})
            else:
                # Insert new target
                query = """
                    INSERT INTO scan_targets (name, paths, scanner, tools, schedule, cron_expression)
                    VALUES (%s, %s, %s, %s::jsonb, %s, %s)
                    RETURNING id
                """
                result = db_manager.execute_query(query, (name, paths, scanner, tools_json, schedule, cron))
                
                if result:
                    return html.Div("✅ Scan target saved successfully!", style={'color': '#48bb78'})
                return html.Div("❌ Failed to save target", style={'color': '#f56565'})
        except Exception as e:
            logger.error(f"Error saving scan target: {e}")
            return html.Div(f"❌ Error: {str(e)}", style={'color': '#f56565'})
    
    # ========== DELETE SCAN TARGET ==========
    @app.callback(
        Output('admin-scan-targets-table', 'data', allow_duplicate=True),
        Input('admin-delete-target-btn', 'n_clicks'),
        State('admin-scan-targets-table', 'selected_rows'),
        State('admin-scan-targets-table', 'data'),
        prevent_initial_call=True
    )
    def delete_scan_target(n_clicks, selected_rows, data):
        """Delete selected scan target"""
        if not n_clicks or not selected_rows or not data:
            return no_update
        
        try:
            selected_idx = selected_rows[0]
            target_id = data[selected_idx].get('id')
            
            if target_id:
                db_manager.execute_update(
                    "DELETE FROM scan_targets WHERE id = %s", (target_id,)
                )
                # Remove from data
                data.pop(selected_idx)
                return data
        except Exception as e:
            logger.error(f"Error deleting scan target: {e}")
        
        return no_update
    
    # ========== RUN NOW CALLBACK ==========
    @app.callback(
        Output('admin-target-save-result', 'children', allow_duplicate=True),
        Input('admin-run-target-btn', 'n_clicks'),
        State('admin-scan-targets-table', 'selected_rows'),
        State('admin-scan-targets-table', 'data'),
        prevent_initial_call=True
    )
    def run_scan_now(n_clicks, selected_rows, data):
        """Run a scan immediately for selected target"""
        if not n_clicks or not selected_rows or not data:
            return "Select a target first"
        
        try:
            selected_idx = selected_rows[0]
            target = data[selected_idx]
            target_name = target.get('name', 'Unknown')
            scanner_id = target.get('scanner', 'server')
            paths = target.get('paths', '')
            
            if scanner_id == 'server':
                # Run server-side scan (existing functionality)
                return html.Div(f"🚀 Server scan initiated for {target_name}", style={'color': '#48bb78'})
            else:
                # Create job for agent
                job = agent_db.create_job(
                    agent_id=scanner_id,
                    scan_paths=[p.strip() for p in paths.split(',')],
                    scanners=['custom', 'gitleaks', 'trufflehog']
                )
                if job:
                    return html.Div(f"🚀 Scan job created for agent. Job ID: {job.get('job_id', 'N/A')[:8]}...", 
                                  style={'color': '#48bb78'})
                return html.Div("❌ Failed to create scan job", style={'color': '#f56565'})
        except Exception as e:
            logger.error(f"Error running scan: {e}")
            return html.Div(f"❌ Error: {str(e)}", style={'color': '#f56565'})
    
    # ========== CREATE JOB CALLBACK ==========
    @app.callback(
        Output('admin-job-result', 'children'),
        Input('admin-create-job-btn', 'n_clicks'),
        [State('admin-job-agent-select', 'value'),
         State('admin-job-path', 'value'),
         State('admin-job-scanners', 'value')],
        prevent_initial_call=True
    )
    def create_scan_job(n_clicks, agent_id, paths, scanners):
        """Create a scan job for an agent"""
        if not n_clicks:
            return ""
        
        if not agent_id or not paths:
            return html.Div("❌ Agent and path are required", style={'color': '#f56565'})
        
        try:
            path_list = [p.strip() for p in paths.split(',')]
            job = agent_db.create_job(
                agent_id=agent_id,
                scan_paths=path_list,
                scanners=scanners or ['custom']
            )
            
            if job:
                return html.Div([
                    html.Span("✅ ", style={'color': '#48bb78'}),
                    html.Span(f"Job created: {str(job.get('job_id', ''))[:8]}...")
                ], style={'color': '#48bb78'})
            return html.Div("❌ Failed to create job", style={'color': '#f56565'})
        except Exception as e:
            logger.error(f"Error creating job: {e}")
            return html.Div(f"❌ Error: {str(e)}", style={'color': '#f56565'})
    
    # ========== JOBS TABLE POPULATION ==========
    @app.callback(
        Output('admin-jobs-table', 'data'),
        [Input('admin-refresh-interval', 'n_intervals'),
         Input('admin-refresh-jobs', 'n_clicks'),
         Input('admin-job-status-filter', 'value')],
        prevent_initial_call=False
    )
    def populate_jobs_table(n_intervals, n_clicks, status_filter):
        """Populate the jobs table"""
        jobs = agent_db.list_jobs(status=status_filter if status_filter != 'all' else None)
        
        data = []
        for j in jobs:
            status = j.get('status', 'unknown')
            status_icon = {
                'pending': '⏳', 'running': '▶️', 'completed': '✅', 
                'failed': '❌', 'cancelled': '⛔', 'assigned': '📤'
            }.get(status, '❓')
            
            # Parse scan paths
            paths = j.get('scan_paths', [])
            if isinstance(paths, str):
                try:
                    paths = json.loads(paths)
                except:
                    paths = [paths]
            paths_str = ', '.join(paths[:2]) + ('...' if len(paths) > 2 else '') if paths else '-'
            
            # Calculate duration
            created = j.get('created_at')
            completed = j.get('completed_at')
            if created and completed:
                try:
                    duration_secs = (completed - created).total_seconds()
                    if duration_secs < 60:
                        duration = f"{int(duration_secs)}s"
                    elif duration_secs < 3600:
                        duration = f"{int(duration_secs/60)}m"
                    else:
                        duration = f"{int(duration_secs/3600)}h {int((duration_secs%3600)/60)}m"
                except:
                    duration = '-'
            else:
                duration = '-' if status not in ('running', 'assigned') else '...'
            
            data.append({
                'status_icon': f"{status_icon} {status.title()}",
                'agent_hostname': j.get('agent_hostname', 'Unknown'),
                'job_type': j.get('job_type', 'scan').title(),
                'scan_paths_str': paths_str,
                'files_scanned': j.get('files_scanned', 0) or 0,
                'findings_count': j.get('findings_count', 0) or 0,
                'created_str': str(j.get('created_at', ''))[:16] if j.get('created_at') else '-',
                'duration': duration,
            })
        return data
    
    # ========== FINDINGS TABLE POPULATION ==========
    @app.callback(
        Output('admin-findings-table', 'data'),
        [Input('admin-refresh-interval', 'n_intervals'),
         Input('admin-refresh-findings', 'n_clicks'),
         Input('admin-finding-severity-filter', 'value'),
         Input('admin-finding-status-filter', 'value')],
        prevent_initial_call=False
    )
    def populate_findings_table(n_intervals, n_clicks, severity, status):
        """Populate the findings table"""
        findings = agent_db.list_findings(
            severity=severity if severity != 'all' else None,
            status=status if status != 'all' else None
        )
        
        data = []
        for f in findings:
            severity = f.get('severity', 'Unknown')
            severity_icons = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
            
            data.append({
                'severity_icon': f"{severity_icons.get(severity, '❓')} {severity}",
                'secret_type': f.get('secret_type', 'Unknown'),
                'file_path': (f.get('file_path', '') or '')[-50:] if f.get('file_path') else '-',
                'line_number': f.get('line_number', '-') or '-',
                'scanner': f.get('scanner', '-') or '-',
                'agent_hostname': f.get('agent_hostname', 'Unknown'),
                'found_str': str(f.get('found_at', ''))[:16] if f.get('found_at') else '-',
                'status': f.get('status', 'open').replace('_', ' ').title(),
            })
        return data

    # API Key Generation
    @app.callback(
        Output('admin-apikey-result', 'children'),
        Input('admin-generate-apikey-btn', 'n_clicks'),
        State('admin-apikey-name', 'value'),
        prevent_initial_call=True
    )
    def generate_api_key(n_clicks, key_name):
        if not n_clicks:
            return ""
        
        import secrets
        import hashlib
        from datetime import datetime
        
        if not key_name:
            return html.Div([
                html.Span("❌ ", style={'color': '#f56565'}),
                html.Span("Please enter a name for the API key")
            ], style={'color': '#f56565', 'padding': '10px'})
        
        # Check for duplicate name in agent database
        try:
            existing = agent_db._execute_agent_query(
                "SELECT id FROM agent_api_keys WHERE name = %s AND is_active = true", (key_name,)
            )
            if existing:
                return html.Div([
                    html.Span("❌ ", style={'color': '#f56565'}),
                    html.Span(f"An active API key with name '{key_name}' already exists. Use a unique name.")
                ], style={'color': '#f56565', 'padding': '10px', 'backgroundColor': '#3a1a1a', 
                         'borderRadius': '4px', 'marginTop': '10px'})
        except Exception as e:
            logger.warning(f"Could not check for duplicate key name: {e}")
        
        # Generate a secure API key (128 characters)
        api_key = f"ss_{secrets.token_urlsafe(96)}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        key_prefix = api_key[:12]  # Store prefix for identification
        
        # Store ONLY in Agent Manager database (the source of truth)
        try:
            import psycopg2
            agent_db_conn = psycopg2.connect(
                host=os.environ.get('AGENT_DB_HOST', '10.150.110.24'),
                port=int(os.environ.get('AGENT_DB_PORT', 5433)),
                database='secretsnipe_agents',
                user='secretsnipe',
                password='secretsnipe_secure_pass'
            )
            agent_db_cur = agent_db_conn.cursor()
            agent_db_cur.execute("""
                INSERT INTO agent_api_keys (key_hash, key_prefix, name, description, expires_at, is_active)
                VALUES (%s, %s, %s, %s, NOW() + interval '1 year', true)
                RETURNING id
            """, (key_hash, key_prefix, key_name, 'Generated from Downloads page'))
            result = agent_db_cur.fetchone()
            agent_db_conn.commit()
            agent_db_cur.close()
            agent_db_conn.close()
            
            if result:
                return html.Div([
                    html.Div([
                        html.Span("✅ ", style={'color': '#48bb78'}),
                        html.Strong("API Key Generated Successfully!")
                    ], style={'marginBottom': '15px'}),
                    html.Div([
                        html.P("Copy this key now - it won't be shown again:", 
                              style={'color': '#888', 'marginBottom': '10px'}),
                        html.Pre(
                            api_key,
                            style={
                                'backgroundColor': '#1a1a1a',
                                'color': '#4ec9b0',
                                'padding': '15px',
                                'borderRadius': '6px',
                                'fontSize': '12px',
                                'fontFamily': 'Consolas, Monaco, monospace',
                                'wordBreak': 'break-all',
                                'whiteSpace': 'pre-wrap',
                                'border': '1px solid #38a169',
                                'userSelect': 'all'
                            }
                        ),
                        html.P(f"Key Name: {key_name}", style={'color': '#888', 'marginTop': '10px'}),
                        html.P(f"Key Prefix: {key_prefix}", style={'color': '#666', 'fontSize': '12px'}),
                        html.P(f"Key Length: {len(api_key)} characters", style={'color': '#666', 'fontSize': '11px'}),
                    ])
                ], style={
                    'backgroundColor': '#1a3a2a',
                    'border': '1px solid #38a169',
                    'borderRadius': '8px',
                    'padding': '20px',
                    'marginTop': '15px'
                })
        except Exception as e:
            logger.error(f"Error generating API key: {e}")
            return html.Div([
                html.Span("❌ ", style={'color': '#f56565'}),
                html.Span(f"Error generating key: {str(e)}")
            ], style={'color': '#f56565', 'padding': '10px'})
        
        return ""
    
    # Add agent delete callback
    @app.callback(
        Output('admin-agent-action-result', 'children'),
        Input({'type': 'delete-agent-btn', 'index': ALL}, 'n_clicks'),
        State({'type': 'delete-agent-btn', 'index': ALL}, 'id'),
        prevent_initial_call=True
    )
    def delete_agent(n_clicks, ids):
        """Delete an agent from the fleet"""
        from dash import callback_context
        if not callback_context.triggered:
            return ""
        
        # Find which button was clicked
        triggered_id = callback_context.triggered[0]['prop_id']
        if not any(n_clicks):
            return ""
        
        # Extract agent_id from the triggered button
        import json
        try:
            button_id = json.loads(triggered_id.rsplit('.', 1)[0])
            agent_id = button_id.get('index')
        except:
            return html.Div("Error identifying agent", style={'color': '#f56565'})
        
        if not agent_id:
            return ""
        
        # Delete from Agent Manager database
        try:
            import psycopg2
            agent_db_conn = psycopg2.connect(
                host=os.environ.get('AGENT_DB_HOST', '10.150.110.24'),
                port=int(os.environ.get('AGENT_DB_PORT', 5433)),
                database='secretsnipe_agents',
                user='secretsnipe',
                password='secretsnipe_secure_pass'
            )
            agent_db_cur = agent_db_conn.cursor()
            agent_db_cur.execute("DELETE FROM agents WHERE agent_id = %s", (agent_id,))
            deleted = agent_db_cur.rowcount
            agent_db_conn.commit()
            agent_db_cur.close()
            agent_db_conn.close()
            
            if deleted > 0:
                logger.info(f"Agent {agent_id} deleted from fleet")
                return html.Div([
                    html.Span("✅ ", style={'color': '#48bb78'}),
                    html.Span(f"Agent {agent_id[:8]}... deleted successfully. Refresh to see changes.")
                ], style={'color': '#48bb78', 'padding': '10px', 'backgroundColor': '#1a3a2a', 'borderRadius': '4px', 'marginTop': '10px'})
            else:
                return html.Div([
                    html.Span("⚠️ ", style={'color': '#ecc94b'}),
                    html.Span("Agent not found or already deleted")
                ], style={'color': '#ecc94b', 'padding': '10px'})
        except Exception as e:
            logger.error(f"Error deleting agent: {e}")
            return html.Div([
                html.Span("❌ ", style={'color': '#f56565'}),
                html.Span(f"Error deleting agent: {str(e)}")
            ], style={'color': '#f56565', 'padding': '10px'})
    
    # ========== SCHEDULE TYPE TOGGLE ==========
    @app.callback(
        [Output('admin-scheduled-form', 'style'),
         Output('admin-continuous-form', 'style')],
        Input('admin-schedule-type', 'value'),
        prevent_initial_call=True
    )
    def toggle_schedule_forms(schedule_type):
        """Toggle between scheduled scan and continuous monitoring forms"""
        if schedule_type == 'scheduled':
            return {'display': 'block'}, {'display': 'none'}
        return {'display': 'none'}, {'display': 'block'}
    
    # ========== SCHEDULE PRESET TO CRON ==========
    @app.callback(
        Output('admin-schedule-cron', 'value'),
        Input('admin-schedule-preset', 'value'),
        prevent_initial_call=True
    )
    def update_cron_from_preset(preset):
        """Update cron expression when preset is selected"""
        if preset == 'custom':
            return ''
        return preset
    
    # ========== API KEY MANAGEMENT CALLBACKS ==========
    @app.callback(
        Output('admin-apikeys-table', 'data'),
        [Input('admin-tabs', 'value'),
         Input('admin-refresh-keys', 'n_clicks')],
        prevent_initial_call=False
    )
    def populate_apikeys_table(tab, n_clicks):
        """Load API keys into the table"""
        if tab != 'apikeys':
            return no_update
        
        try:
            keys = agent_db.list_api_keys()
            data = []
            for k in keys:
                is_active = k.get('is_active', True)
                expires = k.get('expires_at')
                is_expired = expires and expires < datetime.now() if expires else False
                
                status = '🟢 Active' if is_active and not is_expired else '🔴 Inactive' if not is_active else '⚠️ Expired'
                
                data.append({
                    'id': str(k.get('id', '')),
                    'status_icon': status,
                    'key_prefix': k.get('key_prefix', '')[:8] + '...',
                    'name': k.get('name', ''),
                    'description': k.get('description', '')[:50] + '...' if k.get('description', '') else '',
                    'created_at_str': str(k.get('created_at', ''))[:16],
                    'expires_at_str': str(k.get('expires_at', ''))[:16] if k.get('expires_at') else 'Never',
                    'last_used_str': str(k.get('last_used_at', ''))[:16] if k.get('last_used_at') else 'Never',
                    'agents_count': '-'  # Would need another query
                })
            return data
        except Exception as e:
            logger.error(f"Error loading API keys: {e}")
            return []
    
    @app.callback(
        Output('admin-new-key-result', 'children'),
        Input('admin-create-key-btn', 'n_clicks'),
        [State('admin-new-key-name', 'value'),
         State('admin-new-key-description', 'value'),
         State('admin-new-key-expires', 'value')],
        prevent_initial_call=True
    )
    def create_new_api_key(n_clicks, name, description, expires_days):
        """Create a new API key"""
        if not n_clicks or not name:
            return html.Div("❌ Key name is required", style={'color': '#f56565'})
        
        # Check for duplicate name
        try:
            existing = agent_db._execute_agent_query(
                "SELECT id FROM agent_api_keys WHERE name = %s AND is_active = true", (name,)
            )
            if existing:
                return html.Div([
                    html.Span("❌ ", style={'color': '#f56565'}),
                    html.Span(f"An active API key named '{name}' already exists. Use a unique name.")
                ], style={'color': '#f56565', 'padding': '15px', 'backgroundColor': '#3a1a1a', 
                         'borderRadius': '4px', 'border': '1px solid #f56565'})
        except Exception as e:
            logger.warning(f"Could not check for duplicate key name: {e}")
        
        try:
            key, key_id = agent_db.create_api_key(name, description or '', expires_days or 365)
            
            return html.Div([
                html.Div([
                    html.H5("🔐 API Key Generated Successfully!", style={'color': '#48bb78', 'marginBottom': '10px'}),
                    html.P("⚠️ Copy this key now! It will NOT be shown again.", 
                           style={'color': '#f6ad55', 'fontWeight': 'bold'}),
                    html.Pre(
                        key,
                        style={
                            'backgroundColor': '#1a1a1a',
                            'color': '#48bb78',
                            'padding': '15px',
                            'borderRadius': '6px',
                            'fontFamily': 'monospace',
                            'fontSize': '11px',
                            'wordBreak': 'break-all',
                            'whiteSpace': 'pre-wrap',
                            'userSelect': 'all'
                        }
                    ),
                    html.P(f"Key Name: {name}", style={'color': '#888', 'marginTop': '10px'}),
                    html.P(f"Key Length: {len(key)} characters", style={'color': '#666', 'fontSize': '11px'}),
                    html.P(f"Expires: {expires_days} days", style={'color': '#666', 'fontSize': '12px'}),
                ])
            ], style={
                'backgroundColor': '#1a3a2a',
                'border': '1px solid #38a169',
                'borderRadius': '8px',
                'padding': '20px'
            })
        except Exception as e:
            logger.error(f"Error creating API key: {e}")
            return html.Div(f"❌ Error: {str(e)}", style={'color': '#f56565'})
    
    @app.callback(
        Output('admin-key-action-result', 'children'),
        [Input('admin-revoke-key-btn', 'n_clicks'),
         Input('admin-extend-key-btn', 'n_clicks')],
        [State('admin-apikeys-table', 'selected_rows'),
         State('admin-apikeys-table', 'data')],
        prevent_initial_call=True
    )
    def handle_key_actions(revoke_clicks, extend_clicks, selected_rows, data):
        """Handle API key actions (revoke, extend)"""
        from dash import ctx
        if not ctx.triggered or not selected_rows or not data:
            return "Select a key first"
        
        trigger = ctx.triggered_id
        selected_idx = selected_rows[0]
        key_id = data[selected_idx].get('id')
        key_name = data[selected_idx].get('name')
        
        if trigger == 'admin-revoke-key-btn':
            try:
                success = agent_db.revoke_api_key(key_id)
                if success:
                    return html.Div(f"✅ Key '{key_name}' has been revoked", style={'color': '#48bb78'})
                return html.Div("❌ Failed to revoke key", style={'color': '#f56565'})
            except Exception as e:
                return html.Div(f"❌ Error: {str(e)}", style={'color': '#f56565'})
        
        elif trigger == 'admin-extend-key-btn':
            try:
                from datetime import datetime, timedelta
                new_expires = datetime.now() + timedelta(days=365)
                success = agent_db.update_api_key_expiration(key_id, new_expires)
                if success:
                    return html.Div(f"✅ Key '{key_name}' extended by 1 year", style={'color': '#48bb78'})
                return html.Div("❌ Failed to extend key", style={'color': '#f56565'})
            except Exception as e:
                return html.Div(f"❌ Error: {str(e)}", style={'color': '#f56565'})
        
        return no_update
    
    # ========== AGENT COMMAND CALLBACKS ==========
    @app.callback(
        Output('admin-agent-paths-display', 'children'),
        Input('admin-agent-discover-paths', 'n_clicks'),
        State('admin-selected-agent-id', 'data'),
        prevent_initial_call=True
    )
    def discover_agent_paths(n_clicks, agent_id):
        """Request agent to list available paths"""
        if not n_clicks or not agent_id:
            return html.Div("Select an agent first", style={'color': '#888'})
        
        try:
            # Queue list_paths command
            command_id = agent_db.queue_agent_command(agent_id, 'list_paths', {})
            if command_id:
                return html.Div([
                    html.Span("🔍 ", style={'color': '#4dabf7'}),
                    html.Span(f"Path discovery command queued for agent. It will be executed on the next heartbeat (~30 sec). "),
                    html.Span(f"Command ID: {command_id[:8]}...", style={'color': '#666', 'fontSize': '12px'})
                ], style={'color': '#4dabf7', 'padding': '10px', 'backgroundColor': '#1a2a4a', 'borderRadius': '4px'})
            return html.Div("❌ Failed to queue command", style={'color': '#f56565'})
        except Exception as e:
            return html.Div(f"❌ Error: {str(e)}", style={'color': '#f56565'})
    
    @app.callback(
        Output('admin-agent-action-result', 'children', allow_duplicate=True),
        [Input('admin-agent-restart', 'n_clicks'),
         Input('admin-agent-update', 'n_clicks'),
         Input('admin-agent-remove', 'n_clicks')],
        State('admin-selected-agent-id', 'data'),
        prevent_initial_call=True
    )
    def handle_agent_commands(restart_clicks, update_clicks, remove_clicks, agent_id):
        """Handle agent management commands"""
        from dash import ctx
        if not ctx.triggered or not agent_id:
            return html.Div("Select an agent first", style={'color': '#888'})
        
        trigger = ctx.triggered_id
        
        try:
            if trigger == 'admin-agent-restart':
                command_id = agent_db.queue_agent_command(agent_id, 'restart', {})
                return html.Div(f"🔄 Restart command queued (ID: {command_id[:8]}...)", style={'color': '#4dabf7'})
            
            elif trigger == 'admin-agent-update':
                command_id = agent_db.queue_agent_command(agent_id, 'update', {'version': 'latest'})
                return html.Div(f"⬆️ Update command queued (ID: {command_id[:8]}...)", style={'color': '#48bb78'})
            
            elif trigger == 'admin-agent-remove':
                # Direct database delete
                agent_db.delete_agent(agent_id)
                return html.Div(f"🗑️ Agent removed successfully", style={'color': '#ecc94b'})
            
        except Exception as e:
            return html.Div(f"❌ Error: {str(e)}", style={'color': '#f56565'})
        
        return no_update
    
    # ========== PATH BROWSING FOR JOBS ==========
    @app.callback(
        [Output('admin-path-discovery-result', 'children'),
         Output('admin-job-path-suggestions', 'options')],
        Input('admin-browse-agent-paths', 'n_clicks'),
        State('admin-job-agent-select', 'value'),
        prevent_initial_call=True
    )
    def browse_agent_paths_for_job(n_clicks, agent_id):
        """Browse paths on selected agent for job creation"""
        if not n_clicks or not agent_id:
            return html.Div("Select an agent first", style={'color': '#888'}), []
        
        try:
            # First check if we have cached paths
            paths = agent_db.get_agent_paths(agent_id)
            
            if paths:
                options = [{'label': p, 'value': p} for p in paths]
                return html.Div([
                    html.Span("✅ ", style={'color': '#48bb78'}),
                    html.Span(f"Found {len(paths)} available paths on agent")
                ], style={'color': '#48bb78'}), options
            else:
                # Queue discovery command
                command_id = agent_db.queue_agent_command(agent_id, 'list_paths', {})
                return html.Div([
                    html.Span("🔍 ", style={'color': '#4dabf7'}),
                    html.Span("Path discovery queued. Please wait ~30 seconds and click again.")
                ], style={'color': '#4dabf7'}), []
        except Exception as e:
            return html.Div(f"❌ Error: {str(e)}", style={'color': '#f56565'}), []
    
    # ========== POPULATE SCHEDULES DROPDOWNS WITH AGENTS ==========
    @app.callback(
        [Output('admin-schedule-agent', 'options'),
         Output('admin-continuous-agent', 'options')],
        [Input('admin-tabs', 'value'),
         Input('admin-refresh-interval', 'n_intervals')],
        prevent_initial_call=False
    )
    def populate_schedule_agent_dropdowns(tab, n_intervals):
        """Populate agent dropdowns in schedules tab"""
        agents = agent_db.list_agents()
        options = [{'label': f"{a['hostname']} ({a['status']})", 'value': str(a['agent_id'])} for a in agents]
        return options, options
    
    # ========== POPULATE LOG AGENT FILTER ==========
    @app.callback(
        Output('admin-log-agent-filter', 'options'),
        [Input('admin-tabs', 'value'),
         Input('admin-refresh-interval', 'n_intervals')],
        prevent_initial_call=False
    )
    def populate_log_agent_dropdown(tab, n_intervals):
        """Populate agent dropdown in logs tab"""
        agents = agent_db.list_agents()
        options = [{'label': 'All Agents', 'value': 'all'}]
        for a in agents:
            options.append({'label': f"{a['hostname']} ({a['status']})", 'value': str(a['agent_id'])})
        return options
    
    # ========== POPULATE FINDING AGENT FILTER ==========
    @app.callback(
        Output('admin-finding-agent-filter', 'options'),
        [Input('admin-tabs', 'value'),
         Input('admin-refresh-interval', 'n_intervals')],
        prevent_initial_call=False
    )
    def populate_finding_agent_dropdown(tab, n_intervals):
        """Populate agent dropdown in findings tab"""
        agents = agent_db.list_agents()
        options = [{'label': 'All Agents', 'value': 'all'}]
        for a in agents:
            options.append({'label': f"{a['hostname']} ({a['status']})", 'value': str(a['agent_id'])})
        return options
    
    # ========== SELECTED AGENT FROM TABLE ==========
    @app.callback(
        Output('admin-selected-agent-id', 'data'),
        Input('admin-agents-datatable', 'selected_rows'),
        State('admin-agents-datatable', 'data'),
        prevent_initial_call=True
    )
    def update_selected_agent(selected_rows, data):
        """Update selected agent store when row is selected in DataTable"""
        if not selected_rows or not data:
            return None
        
        selected_idx = selected_rows[0]
        if selected_idx < len(data):
            return data[selected_idx].get('agent_id')
        return None
    
    # ========== SELECTED AGENT INDICATOR ==========
    @app.callback(
        Output('admin-agent-paths-display', 'children', allow_duplicate=True),
        Input('admin-selected-agent-id', 'data'),
        State('admin-agents-datatable', 'data'),
        prevent_initial_call=True
    )
    def show_selected_agent_info(agent_id, data):
        """Show which agent is currently selected"""
        if not agent_id or not data:
            return html.Div("👆 Select an agent from the table above to manage it", 
                          style={'color': '#888', 'fontStyle': 'italic', 'padding': '10px'})
        
        # Find agent info
        agent_info = None
        for a in data:
            if a.get('agent_id') == agent_id:
                agent_info = a
                break
        
        if agent_info:
            return html.Div([
                html.Span("✓ Selected: ", style={'color': '#48bb78', 'fontWeight': 'bold'}),
                html.Span(f"{agent_info.get('hostname', 'Unknown')} ({agent_info.get('ip_address', '')})", 
                         style={'color': '#e0e0e0'}),
                html.Span(f" - {agent_info.get('status', '')}", style={'color': '#888', 'marginLeft': '10px'})
            ], style={'padding': '10px', 'backgroundColor': '#1a2a4a', 'borderRadius': '4px'})
        
        return html.Div(f"Selected agent ID: {agent_id[:8]}...", 
                       style={'color': '#888', 'padding': '10px'})
    
    # ========== AUTO QUEUE PATH DISCOVERY ON AGENT COMMANDS ==========
    @app.callback(
        Output('admin-agent-action-result', 'children', allow_duplicate=True),
        Input('admin-refresh-agents', 'n_clicks'),
        prevent_initial_call=True
    )
    def queue_auto_path_discovery(n_clicks):
        """Auto-queue path discovery for agents without paths"""
        if not n_clicks:
            return no_update
        
        try:
            agents = agent_db.list_agents()
            queued_count = 0
            for a in agents:
                agent_id = str(a.get('agent_id', ''))
                if agent_id and a.get('status') in ('online', 'idle'):
                    # Check if we already have paths for this agent
                    existing_paths = agent_db.get_agent_paths(agent_id)
                    if not existing_paths:
                        agent_db.queue_agent_command(agent_id, 'list_paths', {})
                        queued_count += 1
            
            if queued_count > 0:
                return html.Div([
                    html.Span("🔍 ", style={'color': '#4dabf7'}),
                    html.Span(f"Auto-queued path discovery for {queued_count} agent(s)")
                ], style={'color': '#4dabf7', 'padding': '5px'})
        except Exception as e:
            logger.error(f"Auto path discovery error: {e}")
        
        return no_update
    
    # ========== POPULATE LOGS CONTAINER ==========
    @app.callback(
        Output('admin-logs-container', 'children'),
        [Input('admin-refresh-logs', 'n_clicks'),
         Input('admin-refresh-interval', 'n_intervals'),
         Input('admin-log-agent-filter', 'value'),
         Input('admin-log-level-filter', 'value'),
         Input('admin-log-search', 'value'),
         Input('admin-log-auto-refresh', 'value')],
        prevent_initial_call=False
    )
    def populate_logs(n_clicks, n_intervals, agent_filter, level_filter, search_term, auto_refresh):
        """Populate the agent logs container"""
        # Only auto-refresh if enabled
        from dash import ctx
        if ctx.triggered_id == 'admin-refresh-interval' and 'auto' not in (auto_refresh or []):
            return no_update
        
        try:
            logs = agent_db.get_agent_logs(
                agent_id=agent_filter if agent_filter and agent_filter != 'all' else None,
                level=level_filter if level_filter and level_filter != 'all' else None,
                limit=500
            )
            
            if not logs:
                return html.Div("No logs found. Logs appear here when agents report activity.",
                              style={'color': '#666', 'padding': '20px', 'textAlign': 'center'})
            
            # Apply search filter
            if search_term:
                search_lower = search_term.lower()
                logs = [l for l in logs if search_lower in (l.get('message', '') or '').lower()]
            
            # Build log entries
            entries = []
            for log in logs:
                level = log.get('level', 'INFO')
                level_class = {
                    'ERROR': 'log-error',
                    'WARNING': 'log-warning',
                    'INFO': 'log-info',
                    'DEBUG': 'log-debug'
                }.get(level, 'log-info')
                
                level_color = {
                    'ERROR': '#fc8181', 'WARNING': '#f6e05e', 
                    'INFO': '#90cdf4', 'DEBUG': '#a0aec0'
                }.get(level, '#e0e0e0')
                
                timestamp = str(log.get('timestamp', ''))[:19]
                hostname = log.get('agent_hostname', 'Unknown')
                message = log.get('message', '')
                
                entries.append(html.Div([
                    html.Span(f"[{timestamp}] ", style={'color': '#666'}),
                    html.Span(f"[{level:7s}] ", style={'color': level_color, 'fontWeight': 'bold'}),
                    html.Span(f"[{hostname}] ", style={'color': '#4dabf7'}),
                    html.Span(message, style={'color': '#e0e0e0'})
                ], style={
                    'padding': '4px 8px',
                    'borderBottom': '1px solid #222',
                    'fontFamily': 'monospace',
                    'fontSize': '12px',
                    'backgroundColor': '#2d1f1f' if level == 'ERROR' else '#2d2d1f' if level == 'WARNING' else 'transparent'
                }))
            
            return entries
        except Exception as e:
            logger.error(f"Error loading logs: {e}")
            return html.Div(f"Error loading logs: {str(e)}", style={'color': '#f56565', 'padding': '20px'})
    
    logger.info("Administration module integrated successfully")
    return agent_db
