"""
SecretSnipe Unified Dashboard - Interactive Secret Scanning Visualizer

This module provides a comprehensive web-based dashboard for visualizing and analyzing
secret scanning results from multiple tools. Built with Dash and Plotly, it offers
real-time data visualization, filtering, and export capabilities.

Core Architecture:
- Dash web application with reactive components
- LMDB database integration for high-performance data storage
- Flask-Caching for optimized data loading and processing
- Client-side callbacks for instant filtering
- Multi-tab interface with findings, analytics, and system monitoring

Key Features:
- Real-time dashboard with 30-minute auto-refresh
- Interactive charts: bar charts, pie charts, network graphs
- Advanced filtering by severity, file extension, and secret type
- Data export to CSV with one-click functionality
- Pagination and virtualization for large datasets
- Process monitoring and system status display
- Responsive design with loading indicators

Performance Optimizations:
- Dash Patch() for incremental figure updates (2.9+)
- Clientside callbacks for fast filtering in browser
- Chunked LMDB reading to handle large datasets
- Flask-Caching with FileSystem backend for data persistence
- Pre-aggregated data storage for faster chart generation
- Separate data reload (30 min) from filter updates (instant)

Data Sources:
- Primary: LMDB database (scanner_data.lmdb) for findings storage
- Secondary: CSV files for backup/legacy data loading
- Real-time: Process status monitoring via psutil

Visualization Components:
- Bar Chart: Secret types by severity with example values
- Pie Chart: File extension distribution (top 10)
- Network Graph: Relationships between files and secret types
- Data Table: Paginated findings with sorting and filtering
- System Monitor: Running process status and resource usage

Integration Points:
- run_secret_scanner.py: Data generation and LMDB updates
- continuous_monitor.py: Real-time data updates and triggers
- LMDB databases: Shared persistent storage across components

Usage:
    python unified_visualizer.py

Configuration:
    Performance settings in PERFORMANCE_CONFIG dictionary
    Cache settings in Flask-Caching configuration
    Update intervals and chunk sizes for scalability

Scalability:
    For very large datasets (>100k findings):
    - Current: Flask-Caching handles up to ~1GB with FileSystem backend
    - Upgrade: Switch to Redis backend: {'CACHE_TYPE': 'RedisCache', 'CACHE_REDIS_URL': 'redis://localhost:6379'}
    - Databricks for distributed processing: databricks-connect
    - Pre-compute aggregations and store in LMDB

Security Considerations:
    - Local web application (not exposed externally by default)
    - No authentication required for local development
    - Data remains in local LMDB database
    - Export functionality for offline analysis
"""

import dash
from dash import dcc, html, dash_table, Patch
from dash.dependencies import Input, Output, State, ClientsideFunction
import plotly.graph_objects as go
import pandas as pd
import logging
from pathlib import Path
import networkx as nx
import re
import lmdb  # New
import json  # Ensure
from flask_caching import Cache  # New: For caching
import os
import time
import subprocess
import psutil
import signal
try:
    import fcntl  # For file locking on Unix-like systems
    HAS_FCNTL = True
except ImportError:
    fcntl = None
    HAS_FCNTL = False
import msvcrt  # For file locking on Windows
from contextlib import contextmanager

# LMDB coordination lock
LMDB_LOCK_FILE = 'scanner_data.lmdb.lock'

@contextmanager
def lmdb_lock(timeout=5):
    """Context manager for coordinating LMDB access across processes"""
    lock_file = LMDB_LOCK_FILE
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            # Try to acquire lock
            if os.name == 'nt':  # Windows
                lock_handle = open(lock_file, 'w')
                msvcrt.locking(lock_handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:  # Unix-like
                if HAS_FCNTL:
                    lock_handle = open(lock_file, 'w')
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    # Fallback for systems without fcntl
                    lock_handle = open(lock_file, 'w')
                    # Simple file-based locking
                    lock_handle.write(str(os.getpid()))

            try:
                yield lock_handle
            finally:
                if os.name == 'nt':
                    msvcrt.locking(lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
                elif HAS_FCNTL:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                lock_handle.close()
                try:
                    os.remove(lock_file)
                except OSError:
                    pass  # Lock file might be removed by another process
            return
        except (OSError, BlockingIOError):
            time.sleep(0.1)  # Wait before retrying

    raise TimeoutError(f"Could not acquire LMDB lock within {timeout} seconds")

def get_lmdb_env_safe(write=False, timeout=5):
    """Get LMDB environment with proper locking - simplified version"""
    if write:
        # For write operations, try to get lock but don't wait too long
        try:
            with lmdb_lock(timeout):
                return lmdb.open('scanner_data.lmdb', map_size=1 << 30,
                               readonly=False, create=True, max_dbs=32)
        except TimeoutError:
            logging.warning("Could not acquire LMDB write lock, using readonly mode")
            return lmdb.open('scanner_data.lmdb', map_size=1 << 30,
                           readonly=True, create=True, max_dbs=32, lock=False)
    else:
        # For read operations, use readonly mode without locking to avoid conflicts
        return lmdb.open('scanner_data.lmdb', map_size=1 << 30,
                       readonly=True, create=True, max_dbs=32, lock=False)

# --- 1. CONFIGURATION ---
PERFORMANCE_CONFIG = {
    "chunk_size": 1000,  # LMDB read chunk size
    "update_interval_ms": 1800000,  # 30 minutes (reduced due to caching)
    "max_chart_points": 1000,  # Limit points for performance
    "enable_patch_updates": True,  # Use Dash Patch() for partial updates
    "enable_clientside_filtering": True,  # Move filtering to browser
    "cache_timeout_seconds": 3600,  # 1 hour cache timeout
}

# --- 2. SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('unified_dashboard.log', mode='w'),
        logging.StreamHandler()
    ]
)

app = dash.Dash(__name__)

# Initialize Flask-Caching with FileSystem backend for large datasets
# To switch to Redis later: change CACHE_TYPE to 'RedisCache' and add CACHE_REDIS_URL
try:
    cache = Cache(app.server, config={
        'CACHE_TYPE': 'FileSystemCache',
        'CACHE_DIR': 'cache_dir',  # Local directory for cache files
        'CACHE_DEFAULT_TIMEOUT': PERFORMANCE_CONFIG["cache_timeout_seconds"],
        'CACHE_THRESHOLD': 1000  # Max cache entries before cleanup
    })
    logging.info("Flask-Caching initialized successfully")
except Exception as e:
    logging.error(f"Failed to initialize Flask-Caching: {e}")
    # Fallback without caching
    cache = None

# Clientside JavaScript function for fast filtering
app.clientside_callback(
    """
    function(selectedSeverities, selectedExtensions, data) {
        if (!data) return [];
        
        selectedSeverities = selectedSeverities || [];
        selectedExtensions = selectedExtensions || [];
        
        let filtered = data.filter(row => {
            let severityMatch = selectedSeverities.length === 0 || selectedSeverities.includes(row.Severities);
            let extensionMatch = selectedExtensions.length === 0 || selectedExtensions.includes(row.Extension);
            return severityMatch && extensionMatch;
        });
        
        return filtered;
    }
    """,
    Output('data-table', 'data'),
    Input('severity-filter', 'value'),
    Input('extension-filter', 'value'),
    State('data-store', 'data')
)

def create_pre_aggregated_data(df):
    """
    Create pre-aggregated data for faster chart generation.
    
    This function pre-computes aggregations for dashboard charts to improve
    performance during interactive filtering and updates. By calculating
    summaries upfront, chart generation becomes much faster.
    
    Args:
        df (pandas.DataFrame): DataFrame containing findings data
        
    Returns:
        dict: Pre-aggregated data for different chart types
        
    Aggregations:
        - Bar Chart: Secret types grouped by severity levels
        - Pie Chart: File extensions with counts (top 10)
        - Network Graph: High-severity findings for relationship analysis
        - Examples: Sample values for each secret type
        
    Performance Benefits:
        - Eliminates need to re-aggregate on every filter change
        - Reduces computation time for chart updates
        - Enables faster dashboard responsiveness
        - Memory efficient storage of aggregated results
        
    Data Structure:
        {
            'bar_data': {secret_type: {severity: count, ...}, ...},
            'bar_examples': {secret_type: sample_value, ...},
            'pie_data': [{'Extension': ext, 'Count': count}, ...],
            'network_data': [finding_records, ...]
        }
    """
    if df.empty:
        return {}
    
    # Pre-aggregate for bar chart
    bar_agg = df.groupby(['SecretTypes', 'Severities']).size().unstack(fill_value=0)
    bar_examples = df.groupby('SecretTypes')['SecretValues'].apply(lambda x: x.iloc[0] if not x.empty else '').to_dict()
    
    # Pre-aggregate for pie chart
    pie_agg = df.groupby('Extension').size().reset_index(name='Count').nlargest(10, 'Count')
    
    # Pre-aggregate for network
    network_df = df[df['Severities'].isin(['Critical', 'High', 'Medium'])]
    
    return {
        'bar_data': bar_agg.to_dict(),
        'bar_examples': bar_examples,
        'pie_data': pie_agg.to_dict('records'),
        'network_data': network_df.to_dict('records')
    }

# --- 2. DATA LOADING ---
def load_data(lmdb_path='scanner_data.lmdb', chunk_size=None, page=0, page_size=1000):
    """
    Load findings data from LMDB database with pagination for better performance.
    
    This function provides a unified interface for loading findings data, automatically
    choosing between cached and uncached loading based on cache availability. It supports
    pagination to handle large datasets efficiently.
    
    Args:
        lmdb_path (str): Path to the LMDB database file
        chunk_size (int): Size of chunks for reading (uses default if None)
        page (int): Page number for pagination (0-based)
        page_size (int): Number of records per page
        
    Returns:
        dict: Processed data dictionary with findings, aggregations, and metadata
        
    Caching Strategy:
        - Uses Flask-Caching when available for improved performance
        - Falls back to direct loading if caching is unavailable
        - Cached results expire based on PERFORMANCE_CONFIG settings
        
    Pagination:
        - Supports loading large datasets in chunks
        - Page-based navigation for memory efficiency
        - Configurable page sizes for different use cases
        
    Data Processing:
        - Handles both single findings and merged finding arrays
        - Expands array-format findings into individual records
        - Adds file extension information for analysis
        - Validates data integrity and handles corrupted entries
    """
    if cache:
        return load_data_cached(lmdb_path, chunk_size, page, page_size)
    else:
        return load_data_uncached(lmdb_path, chunk_size, page, page_size)

@cache.memoize(timeout=PERFORMANCE_CONFIG["cache_timeout_seconds"])  # Cache for configured timeout
def load_data_cached(lmdb_path='scanner_data.lmdb', chunk_size=None, page=0, page_size=1000):
    """Load findings data from LMDB database with pagination for better performance."""
    logging.info(f"Loading data from LMDB (page {page}, size {page_size})")
    if chunk_size is None:
        chunk_size = PERFORMANCE_CONFIG["chunk_size"]

    try:
        env = get_lmdb_env_safe(write=False)
        findings_db = env.open_db(b'findings')
        findings = []

        with env.begin() as txn:
            cursor = txn.cursor(db=findings_db)
            count = 0
            entry_count = 0

            # Skip to the right page
            for key, value in cursor:
                if entry_count < (page * page_size):
                    entry_count += 1
                    continue

                if count >= page_size:
                    break

                try:
                    finding_list = json.loads(value.decode())

                    # Handle both dict and list formats
                    if isinstance(finding_list, dict):
                        # Single finding stored as dict
                        if 'SecretTypes' in finding_list and isinstance(finding_list['SecretTypes'], list):
                            # Handle array format - expand arrays into individual findings
                            for i, secret_type in enumerate(finding_list['SecretTypes']):
                                finding = {
                                    'FilePath': finding_list.get('FilePath', ''),
                                    'SecretTypes': secret_type,
                                    'SecretValues': finding_list.get('SecretValues', [])[i] if i < len(finding_list.get('SecretValues', [])) else '',
                                    'Contexts': finding_list.get('Contexts', [])[i] if i < len(finding_list.get('Contexts', [])) else '',
                                    'Severities': finding_list.get('Severities', [])[i] if i < len(finding_list.get('Severities', [])) else 'Unknown',
                                    'IsValid': finding_list.get('IsValid', True),  # New field
                                    'ValidationReason': finding_list.get('ValidationReason', '')  # New field
                                }
                                findings.append(finding)
                        else:
                            # Single values - convert to finding
                            finding = {
                                'FilePath': finding_list.get('FilePath', ''),
                                'SecretTypes': finding_list.get('SecretTypes', ''),
                                'SecretValues': finding_list.get('SecretValues', ''),
                                'Contexts': finding_list.get('Contexts', ''),
                                'Severities': finding_list.get('Severities', 'Unknown'),
                                'IsValid': finding_list.get('IsValid', True),  # New field
                                'ValidationReason': finding_list.get('ValidationReason', '')  # New field
                            }
                            findings.append(finding)
                    elif isinstance(finding_list, list):
                        # List of findings - ensure each has new fields
                        for finding in finding_list:
                            if isinstance(finding, dict):
                                finding.setdefault('IsValid', True)
                                finding.setdefault('ValidationReason', '')
                        findings.extend(finding_list)
                    else:
                        # Other format - try to convert
                        if isinstance(finding_list, dict):
                            finding_list.setdefault('IsValid', True)
                            finding_list.setdefault('ValidationReason', '')
                        findings.append(finding_list)
                    count += 1
                except json.JSONDecodeError as e:
                    logging.warning(f"Failed to decode finding: {e}")
                    logging.debug(f"Raw value: {value[:200]}...")

        env.close()

        if findings:
            logging.info(f"Loaded {len(findings)} findings from LMDB (page {page})")
            return _process_findings_to_dataframe(findings)
        else:
            logging.warning("No findings in LMDB—falling back to temp files.")
            return _load_from_temp_files()

    except Exception as e:
        logging.error(f"LMDB loading failed: {e}")
        logging.error(f"Exception type: {type(e).__name__}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        return _load_from_temp_files()

def load_data_uncached(lmdb_path='scanner_data.lmdb', chunk_size=None, page=0, page_size=1000):
    """Load findings data without caching."""
    return load_data_cached(lmdb_path, chunk_size, page, page_size)

@cache.memoize(timeout=PERFORMANCE_CONFIG["cache_timeout_seconds"])
def get_total_findings_count(lmdb_path='scanner_data.lmdb'):
    """Get total count of findings for pagination."""
    try:
        env = get_lmdb_env_safe(write=False)
        findings_db = env.open_db(b'findings')
        count = 0

        with env.begin() as txn:
            cursor = txn.cursor(db=findings_db)
            for key, value in cursor:
                try:
                    finding_list = json.loads(value.decode())
                    if isinstance(finding_list, list):
                        count += len(finding_list)
                    else:
                        count += 1
                except json.JSONDecodeError:
                    pass

        env.close()
        return count
    except Exception as e:
        logging.error(f"Failed to get findings count: {e}")
        return 0

def _process_findings_to_dataframe(findings):
    """Process findings list into a pandas DataFrame."""
    if not findings:
        return pd.DataFrame()
    
    df = pd.DataFrame(findings)
    
    # Ensure all required columns exist with proper data types
    required_cols = ['FilePath', 'SecretTypes', 'SecretValues', 'Contexts', 'Severities', 'IsValid', 'ValidationReason']
    for col in required_cols:
        if col not in df.columns:
            if col == 'IsValid':
                df[col] = True
            else:
                df[col] = ''
        else:
            # Convert to string and handle None values
            if col == 'IsValid':
                df[col] = df[col].fillna(True).astype(bool)
            else:
                df[col] = df[col].fillna('').astype(str)
    
    # Remove empty rows
    df = df[df['FilePath'].str.len() > 0].reset_index(drop=True)
    
    # Add Extension column
    df['Extension'] = df['FilePath'].apply(lambda x: Path(x).suffix.lower() if x else '')
    
    logging.info(f"Processed {len(df)} findings into DataFrame")
    return df

def _load_from_temp_files():
    """Load findings from temp JSON files as fallback."""
    import glob
    import os
    
    findings = []
    
    # Look for temp files
    temp_files = glob.glob('temp_*.json')
    logging.info(f"Found temp files: {temp_files}")
    
    for temp_file in temp_files:
        try:
            logging.info(f"Loading from {temp_file}...")
            with open(temp_file, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                # Process gitleaks format
                for item in data:
                    if isinstance(item, dict):
                        finding = {
                            "FilePath": item.get('File', ''),
                            "SecretTypes": item.get('Description', ''),
                            "SecretValues": item.get('Secret', ''),
                            "Contexts": item.get('Match', ''),
                            "Severities": 'High'
                        }
                        if finding['FilePath']:  # Only add if FilePath exists
                            findings.append(finding)
                            
            elif isinstance(data, dict):
                # Handle other formats if needed
                logging.info(f"Dict format in {temp_file}, skipping for now")
                
        except Exception as e:
            logging.error(f"Error loading {temp_file}: {e}")
    
    logging.info(f"Loaded {len(findings)} findings from temp files")
    return _process_findings_to_dataframe(findings)

@cache.memoize(timeout=PERFORMANCE_CONFIG["cache_timeout_seconds"])  # Cache for configured timeout
def load_skipped_data(lmdb_path='scanner_data.lmdb'):
    """Load skipped data from LMDB database or return empty DataFrame."""
    logging.info(f"Loading skipped data from LMDB (cache miss or expired)")
    try:
        env = get_lmdb_env_safe(write=False)
        skipped_db = env.open_db(b'skipped')  # Add
        skipped = []
        with env.begin() as txn:
            cursor = txn.cursor(db=skipped_db)
            for key, value in cursor:
                try:
                    skipped_item = json.loads(value.decode())
                    skipped.append(skipped_item)
                except json.JSONDecodeError as e:
                    logging.warning(f"Failed to decode skipped item: {e}")
        env.close()
        
        if skipped:
            logging.info(f"Loaded {len(skipped)} skipped items from LMDB skipped db")
            df = pd.DataFrame(skipped)
            # Ensure required columns exist
            required_cols = ['FilePath', 'Reason']
            for col in required_cols:
                if col not in df.columns:
                    df[col] = ''
            return df
        else:
            logging.warning("No skipped items in LMDB.")
            return pd.DataFrame(columns=['FilePath', 'Reason'])
    
    except Exception as e:
        logging.error(f"LMDB skipped loading failed: {e}")
        return pd.DataFrame(columns=['FilePath', 'Reason'])

def load_data_from_lmdb(db_path='scanner_data.lmdb'):
    """Load findings and skipped files from LMDB database."""
    all_findings = []
    skipped_files = []
    if not os.path.exists(db_path):
        logging.warning(f"LMDB database not found at {db_path}")
        return pd.DataFrame(), pd.DataFrame()

    try:
        # Match the LMDB parameters used in the scanner (max_dbs=32)
        env = lmdb.open(db_path, readonly=True, lock=False, readahead=False, meminit=False, max_dbs=32)

        # Load findings - use the same approach as run_secret_scanner.py
        with env.begin(write=False) as txn:
            try:
                findings_db = env.open_db(b'findings', txn=txn)
                cursor = txn.cursor(db=findings_db)
                for key, value in cursor:
                    try:
                        loaded_value = json.loads(value.decode('utf-8'))
                        if isinstance(loaded_value, list):
                            all_findings.extend(loaded_value)
                        else:
                            all_findings.append(loaded_value)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        logging.warning(f"Could not decode finding for key: {key.decode(errors='replace')}")
            except lmdb.NotFoundError:
                logging.info("No 'findings' database in LMDB.")

        # Load skipped files
        with env.begin(write=False) as txn:
            try:
                skipped_db = env.open_db(b'skipped', txn=txn)
                cursor = txn.cursor(db=skipped_db)
                for key, value in cursor:
                    try:
                        loaded_value = json.loads(value.decode('utf-8'))
                        if isinstance(loaded_value, list):
                            skipped_files.extend(loaded_value)
                        else:
                            skipped_files.append(loaded_value)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        logging.warning(f"Could not decode skipped file for key: {key.decode(errors='replace')}")
            except lmdb.NotFoundError:
                logging.info("No 'skipped' database in LMDB.")
                
        logging.info(f"Loaded {len(skipped_files)} skipped files from LMDB")

        env.close()
    except Exception as e:
        logging.error(f"Error loading data from LMDB: {e}", exc_info=True)

    # Deduplicate findings
    if all_findings:
        unique_findings = {json.dumps(f, sort_keys=True): f for f in all_findings}.values()
        
        # Process findings to handle different data formats
        processed_findings = []
        for finding in unique_findings:
            if isinstance(finding.get('SecretTypes'), list):
                # Handle merged array format from run_secret_scanner.py
                # This format doesn't have IsValid/ValidationReason fields
                for i, secret_type in enumerate(finding['SecretTypes']):
                    processed_finding = {
                        'FilePath': finding.get('FilePath', ''),
                        'SecretTypes': secret_type,
                        'SecretValues': finding.get('SecretValues', [])[i] if i < len(finding.get('SecretValues', [])) else '',
                        'Contexts': finding.get('Contexts', [])[i] if i < len(finding.get('Contexts', [])) else '',
                        'Severities': finding.get('Severities', [])[i] if i < len(finding.get('Severities', [])) else 'Unknown',
                        'IsValid': True,  # Assume valid since already validated by tools
                        'ValidationReason': ''  # No validation reason for merged format
                    }
                    processed_findings.append(processed_finding)
            else:
                # Handle individual finding format from secret_snipe.py
                processed_finding = {
                    'FilePath': finding.get('FilePath', ''),
                    'SecretTypes': finding.get('SecretTypes', ''),
                    'SecretValues': finding.get('SecretValues', ''),
                    'Contexts': finding.get('Contexts', ''),
                    'Severities': finding.get('Severities', 'Unknown'),
                    'IsValid': finding.get('IsValid', True),
                    'ValidationReason': finding.get('ValidationReason', '')
                }
                processed_findings.append(processed_finding)
        
        findings_df = pd.DataFrame(processed_findings)
        
        # Add Extension column
        findings_df['Extension'] = findings_df['FilePath'].apply(lambda x: Path(x).suffix.lower() if x else '')
        
    else:
        findings_df = pd.DataFrame(columns=['FilePath', 'SecretTypes', 'SecretValues', 'Contexts', 'Severities', 'IsValid', 'ValidationReason', 'Extension'])

    if skipped_files:
        skipped_df = pd.DataFrame(skipped_files)
    else:
        skipped_df = pd.DataFrame(columns=['FilePath', 'Reason'])
        
    return findings_df, skipped_df

# --- 3. VISUALIZATION CREATION FUNCTIONS ---
def create_network_graph(df, show_labels=True):
    if df.empty:
        return go.Figure(layout=go.Layout(title='No Data', plot_bgcolor='#1e1e1e', paper_bgcolor='#1e1e1e', font_color='#e0e0e0'))
    
    G = nx.from_pandas_edgelist(df, 'FilePath', 'SecretTypes')
    severity_colors = {'Critical': '#ff0000', 'High': '#d9534f', 'Medium': '#f0ad4e', 'Low': '#5cb85c', '': '#777777'}  # Added Critical

    for node in G.nodes():
        if node in df['FilePath'].unique():
            G.nodes[node]['type'] = 'File'
            severities = df[df['FilePath'] == node]['Severities']
            sev_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
            top_severity = max(severities, key=lambda s: sev_order.get(s, 0), default='')
            G.nodes[node]['severity'] = top_severity
        else:
            G.nodes[node]['type'] = 'SecretType'

    pos = nx.spring_layout(G, k=0.3, iterations=50, seed=42)
    edge_trace = go.Scatter(x=[], y=[], line=dict(width=0.8, color='#888'), hoverinfo='none', mode='lines')
    for edge in G.edges():
        edge_trace['x'] += (pos[edge[0]][0], pos[edge[1]][0], None)
        edge_trace['y'] += (pos[edge[0]][1], pos[edge[1]][1], None)
    
    node_trace = go.Scatter(x=[], y=[], mode='markers+text' if show_labels else 'markers', hoverinfo='text',
                            textfont=dict(size=9, color='#e0e0e0'), textposition="top center",
                            marker=dict(showscale=False, size=12, line=dict(color='#e0e0e0', width=2)))
    
    node_info = {'hover_text': [], 'display_text': [], 'color': []}
    for node, data in G.nodes(data=True):
        node_trace['x'] += (pos[node][0],)
        node_trace['y'] += (pos[node][1],)
        node_type = data.get('type', 'Unknown')
        # Enhanced hover with proof - truncated for readability
        values = ', '.join(df[df['FilePath'] == node]['SecretValues'].unique()) if node_type == 'File' else ''
        contexts = ', '.join(df[df['FilePath'] == node]['Contexts'].unique()) if node_type == 'File' else ''
        
        # Truncate long values and contexts for hover display
        max_hover_length = 100
        if len(values) > max_hover_length:
            values = values[:max_hover_length] + "..."
        if len(contexts) > max_hover_length:
            contexts = contexts[:max_hover_length] + "..."
        
        hover_text = f"<b>{node}</b><br>Type: {node_type}"
        if values:
            hover_text += f"<br>Values: {values}"
        if contexts:
            hover_text += f"<br>Contexts: {contexts}"
        
        display_text = ''
        if node_type == 'File':
            severity = data.get('severity', '')
            hover_text += f"<br>Top Severity: {severity}"
            node_info['color'].append(severity_colors.get(severity, '#777777'))
            if severity in ['Critical', 'High', 'Medium']: 
                display_text = Path(node).name
        else:
            node_info['color'].append('#5bc0de')
            display_text = node
        node_info['hover_text'].append(hover_text)
        node_info['display_text'].append(display_text)

    node_trace.marker.color = node_info['color']
    node_trace.hovertext = node_info['hover_text']
    node_trace.text = node_info['display_text']

    return go.Figure(data=[edge_trace, node_trace], layout=go.Layout(
        showlegend=False, hovermode='closest', margin=dict(b=20, l=5, r=5, t=5),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor='#1e1e1e', paper_bgcolor='#1e1e1e', font=dict(color='#e0e0e0'),
        clickmode='event+select'))

def create_bar_chart(df):
    if df.empty:
        return go.Figure(layout=go.Layout(title='No Data', plot_bgcolor='#1e1e1e', paper_bgcolor='#1e1e1e', font_color='#e0e0e0'))
    grouped = df.groupby(['SecretTypes', 'Severities']).size().unstack(fill_value=0)
    examples = df.groupby('SecretTypes')['SecretValues'].apply(lambda x: x.iloc[0] if not x.empty else '').to_dict()
    
    def smart_wrap_label(label, max_width=15):
        """
        Intelligently wrap labels to improve readability.
        Prefers breaking at word boundaries and common separators.
        """
        if len(label) <= max_width:
            return label
        
        # Try to break at common separators first
        separators = [' ', '_', '-', '.', '/', '\\']
        for sep in separators:
            if sep in label:
                parts = label.split(sep)
                lines = []
                current_line = ""
                
                for part in parts:
                    if not current_line:
                        current_line = part
                    elif len(current_line + sep + part) <= max_width:
                        current_line += sep + part
                    else:
                        lines.append(current_line)
                        current_line = part
                
                if current_line:
                    lines.append(current_line)
                
                # If we got reasonable breaks, use them
                if len(lines) > 1 and all(len(line) <= max_width * 1.5 for line in lines):
                    return '<br>'.join(lines)
        
        # Fallback to character-based wrapping at word boundaries when possible
        words = label.split()
        if len(words) > 1:
            lines = []
            current_line = ""
            
            for word in words:
                if not current_line:
                    current_line = word
                elif len(current_line + " " + word) <= max_width:
                    current_line += " " + word
                else:
                    lines.append(current_line)
                    current_line = word
            
            if current_line:
                lines.append(current_line)
            
            return '<br>'.join(lines)
        
        # Final fallback: character-based wrapping
        return '<br>'.join([label[i:i+max_width] for i in range(0, len(label), max_width)])
    
    # Apply smart wrapping to x-axis labels
    wrapped_index = [smart_wrap_label(label) for label in grouped.index]
    
    fig = go.Figure()
    colors = {'Critical': '#ff0000', 'High': '#d9534f', 'Medium': '#f0ad4e', 'Low': '#5cb85c', '': '#777777'}
    
    for severity in sorted(grouped.columns, key=lambda x: list(colors).index(x) if x in colors else 99):
        if severity in colors:
            # Create properly structured customdata for hover templates
            customdata = []
            for i, secret_type in enumerate(grouped.index):
                count = grouped[severity][secret_type]
                if count > 0:
                    example = examples.get(secret_type, 'No example available')
                    customdata.append([secret_type, example])
                else:
                    customdata.append([secret_type, 'No example available'])
            
            fig.add_trace(go.Bar(
                x=wrapped_index, 
                y=grouped[severity], 
                name=severity, 
                marker_color=colors[severity],
                customdata=customdata,
                hovertemplate='<b>%{customdata[0]}</b><br>' +
                             'Severity: ' + severity + '<br>' +
                             'Count: %{y} findings<br>' +
                             'Example: %{customdata[1]}<br>' +
                             '<extra></extra>'
            ))
    
    fig.update_layout(
        title='Findings by Secret Type', 
        barmode='stack', 
        margin=dict(t=50, b=120, l=40, r=30),  # Increased margins for better label spacing
        xaxis=dict(
            tickangle=-45,  # Angle for better readability
            tickfont=dict(size=9),  # Slightly smaller font
            automargin=True  # Auto-adjust margins for labels
        ),
        plot_bgcolor='#1e1e1e', 
        paper_bgcolor='#1e1e1e',
        font=dict(color='#e0e0e0'), 
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        height=600  # Increased height to accommodate wrapped labels
    )
    return fig

def create_pie_chart(df):
    if df.empty or 'Extension' not in df.columns:
        return go.Figure(layout=go.Layout(title='No Data', plot_bgcolor='#1e1e1e', paper_bgcolor='#1e1e1e', font_color='#e0e0e0'))
    
    grouped = df.groupby('Extension').size().reset_index(name='Count')
    # Filter out empty extensions and limit to top 10 for readability
    grouped = grouped[grouped['Extension'] != ''].nlargest(10, 'Count')
    
    fig = go.Figure(data=[go.Pie(labels=grouped['Extension'], values=grouped['Count'], textinfo='label+percent', hole=.3)])
    fig.update_layout(
        title='Findings by File Extension (Top 10)', showlegend=True, margin=dict(t=40, b=20, l=20, r=20),
        plot_bgcolor='#1e1e1e', paper_bgcolor='#1e1e1e', font=dict(color='#e0e0e0'))
    return fig

# --- 4. APP LAYOUT & MAIN EXECUTION ---
def main():
    """
    Main entry point for the SecretSnipe unified dashboard application.
    
    This function initializes and configures the Dash web application, setting up
    the layout, callbacks, and data stores. It handles the complete dashboard
    lifecycle from data loading to server startup.
    
    Initialization Process:
        1. Load initial data from LMDB database
        2. Create filter options from available data
        3. Generate initial chart figures
        4. Pre-aggregate data for performance
        5. Configure the multi-tab dashboard layout
        6. Set up callback functions for interactivity
        
    Dashboard Layout:
        - Main header with SecretSnipe branding
        - Filter controls (severity, extension, labels)
        - Auto-refresh interval component
        - Data stores for client-side state management
        - Export functionality
        - Multi-tab interface:
            - Dashboard View: Charts and data table
            - Network View: Relationship visualization
            - Skipped Files: Files that were not scanned
            - Scanner Control: Process management interface
            
    Performance Features:
        - Pre-aggregated data for fast chart updates
        - Client-side filtering with JavaScript callbacks
        - Paginated data table with virtualization
        - Loading indicators for better UX
        - Configurable update intervals
        
    Error Handling:
        - Graceful handling of empty data scenarios
        - Fallback layouts for data loading failures
        - Comprehensive logging for troubleshooting
        
    Server Configuration:
        - Debug mode enabled for development
        - Local web server (not externally exposed)
        - Responsive design for different screen sizes
    """
    initial_df, initial_skipped_df = load_data_from_lmdb()
    if initial_df.empty and initial_skipped_df.empty:
        app.layout = html.Div([html.H1("Error loading LMDB data. Check logs.")], style={'color': 'red', 'textAlign': 'center'})
        app.run(debug=True)  # Updated for new Dash version
        return

    severity_options = [{'label': s, 'value': s} for s in sorted(initial_df['Severities'].unique()) if s] if not initial_df.empty else []
    extension_options = [{'label': e, 'value': e} for e in sorted(initial_df['Extension'].unique()) if e] if not initial_df.empty else []

    # Create initial figures from actual data
    initial_bar_chart = create_bar_chart(initial_df)
    initial_pie_chart = create_pie_chart(initial_df)
    initial_network_df = initial_df[initial_df['Severities'].isin(['Critical', 'High', 'Medium'])] if not initial_df.empty else initial_df
    initial_network_graph = create_network_graph(initial_network_df, show_labels=True)
    
    # Pre-aggregate data for performance
    pre_aggregated = create_pre_aggregated_data(initial_df)

    app.layout = html.Div(style={'backgroundColor': '#1e1e1e', 'color': '#e0e0e0', 'padding': '20px'}, children=[
        html.H1("Secret Scanning Hub", style={'textAlign': 'center'}),
        
        html.Div([
            dcc.Dropdown(id='severity-filter', options=severity_options, placeholder="Filter by Severity...", multi=True),
            dcc.Dropdown(id='extension-filter', options=extension_options, placeholder="Filter by Extension...", multi=True),
            dcc.Checklist(id='show-labels-check', options=[{'label': 'Show Labels', 'value': 'show'}], value=['show'],
                          labelStyle={'cursor': 'pointer'}, inputStyle={'marginRight': '5px'})
        ], style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr auto', 'gap': '10px', 'marginBottom': '20px'}),

        dcc.Interval(id='interval-component', interval=PERFORMANCE_CONFIG["update_interval_ms"], n_intervals=0),  # Configurable update interval
        dcc.Store(id='data-store', data=initial_df.to_dict('records')),  # Store data in browser
        dcc.Store(id='skipped-store', data=initial_skipped_df.to_dict('records')),  # Store skipped data
        dcc.Store(id='aggregated-store', data=pre_aggregated),  # Store pre-aggregated data
        
        html.Div([
            html.Button("Export to CSV", id="export-btn", n_clicks=0),
            dcc.Download(id="download-csv"),
            html.Div(id='last-update', style={'marginLeft': '20px', 'fontSize': '14px', 'color': '#888'})
        ], style={'marginBottom': '10px'}),

        dcc.Tabs(id="tabs-controller", value='tab-dashboard', children=[
            dcc.Tab(label='Dashboard View', value='tab-dashboard', children=[
        dcc.Loading(
            id="loading-visuals",
            type="circle",
            children=[
                html.Div([
                    dcc.Graph(id='bar-chart', figure=initial_bar_chart, style={'height': '45vh'}),
                    dcc.Graph(id='pie-chart', figure=initial_pie_chart, style={'height': '45vh'}),
                ], style={'display': 'grid', 'gridTemplateColumns': '60% 40%', 'gap': '10px', 'marginTop': '10px'}),
            ]
        ),
                html.H4("Detailed Findings", style={'marginTop': '20px'}),
                dash_table.DataTable(
                    id='data-table',
                    columns=[{'name': c, 'id': c} for c in ['FilePath', 'SecretTypes', 'SecretValues', 'Contexts', 'Severities', 'Extension']],
                    page_size=50,  # Increased for better performance with large datasets
                    page_current=0,
                    page_action='native',
                    filter_action='native', 
                    sort_action='native',
                    sort_mode='multi',
                    style_table={'overflowX': 'auto', 'maxHeight': '60vh', 'overflowY': 'auto'},
                    style_header={'backgroundColor': '#333', 'fontWeight': 'bold', 'position': 'sticky', 'top': 0},
                    style_cell={'backgroundColor': '#1e1e1e', 'color': '#e0e0e0', 'textAlign': 'left', 'whiteSpace': 'normal', 'height': 'auto', 'maxWidth': 0},
                    style_data_conditional=[
                        {'if': {'filter_query': '{Severities} = Critical'}, 'backgroundColor': '#8b0000', 'color': 'white'},
                        {'if': {'filter_query': '{Severities} = High'}, 'backgroundColor': '#6d2f2f', 'color': 'white'},
                        {'if': {'filter_query': '{Severities} = Medium'}, 'backgroundColor': '#75542b', 'color': 'white'},
                        {'if': {'filter_query': '{Severities} = Low'}, 'backgroundColor': '#2c4a6b', 'color': 'white'},
                    ],
                    virtualization=True,  # Enable virtualization for large datasets
                )
            ]),
            dcc.Tab(label='Network View', value='tab-network', children=[
                html.Div(style={'display': 'grid', 'gridTemplateColumns': '70% 30%', 'gap': '20px', 'marginTop': '10px'}, children=[
                    dcc.Loading(
                        id="loading-network",
                        type="circle",
                        children=[
                            dcc.Graph(id='network-graph', figure=initial_network_graph, style={'height': '80vh'})
                        ]
                    ),
                    html.Div(id='node-info-pane', style={'overflowY': 'auto', 'maxHeight': '80vh', 'whiteSpace': 'pre-wrap', 'wordBreak': 'break-word'})
                ])
            ]),
            dcc.Tab(label='Skipped Files', value='tab-skipped', children=[
                dash_table.DataTable(
                    id='skipped-table',
                    columns=[
                        {'name': 'FilePath', 'id': 'FilePath'},
                        {'name': 'Reason', 'id': 'Reason'}
                    ],
                    page_size=50,
                    page_current=0,
                    filter_action='native',
                    sort_action='native',
                    style_table={'overflowX': 'auto', 'maxHeight': '70vh', 'overflowY': 'auto'},
                    style_header={'backgroundColor': '#333', 'fontWeight': 'bold'},
                    style_cell={'backgroundColor': '#1e1e1e', 'color': '#e0e0e0', 'textAlign': 'left', 'whiteSpace': 'normal', 'height': 'auto'},
                )
            ]),
            dcc.Tab(label='Scanner Control', value='tab-control', children=[
                html.Div(style={'padding': '20px'}, children=[
                    html.H3("SecretSnipe Scanner Control Panel", style={'color': '#e0e0e0', 'marginBottom': '30px'}),
                    
                    # Status Display
                    html.Div(style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr', 'gap': '20px', 'marginBottom': '30px'}, children=[
                        html.Div(style={'backgroundColor': '#2d2d2d', 'padding': '15px', 'borderRadius': '8px'}, children=[
                            html.H4("Monitor Status", style={'color': '#e0e0e0', 'marginBottom': '10px'}),
                            html.Div(id='monitor-status', style={'fontSize': '18px', 'fontWeight': 'bold'}),
                        ]),
                        html.Div(style={'backgroundColor': '#2d2d2d', 'padding': '15px', 'borderRadius': '8px'}, children=[
                            html.H4("Dashboard Status", style={'color': '#e0e0e0', 'marginBottom': '10px'}),
                            html.Div(id='dashboard-status', style={'fontSize': '18px', 'fontWeight': 'bold'}),
                        ]),
                    ]),
                    
                    # Scanner Configuration
                    html.Div(style={'backgroundColor': '#2d2d2d', 'padding': '20px', 'borderRadius': '8px', 'marginBottom': '30px'}, children=[
                        html.H4("Scanner Configuration", style={'color': '#e0e0e0', 'marginBottom': '20px'}),
                        html.Div(style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr', 'gap': '20px'}, children=[
                            html.Div(children=[
                                html.Label("Target Directory:", style={'color': '#e0e0e0', 'marginBottom': '5px'}),
                                dcc.Input(
                                    id='target-directory',
                                    type='text',
                                    value='O:',
                                    style={'width': '100%', 'padding': '8px', 'backgroundColor': '#1e1e1e', 'color': '#e0e0e0', 'border': '1px solid #555'}
                                ),
                            ]),
                            html.Div(children=[
                                html.Label("Tools:", style={'color': '#e0e0e0', 'marginBottom': '5px'}),
                                dcc.Dropdown(
                                    id='tools-selection',
                                    options=[
                                        {'label': 'Trufflehog', 'value': 'trufflehog'},
                                        {'label': 'Gitleaks', 'value': 'gitleaks'},
                                        {'label': 'Custom Scanner', 'value': 'custom'}
                                    ],
                                    value=['trufflehog', 'gitleaks', 'custom'],
                                    multi=True,
                                    style={'backgroundColor': '#1e1e1e', 'color': '#e0e0e0'}
                                ),
                            ]),
                        ]),
                        html.Div(style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr', 'gap': '20px', 'marginTop': '20px'}, children=[
                            html.Div(children=[
                                html.Label("Max Processes:", style={'color': '#e0e0e0', 'marginBottom': '5px'}),
                                dcc.Input(
                                    id='max-processes',
                                    type='number',
                                    value=1,
                                    min=1,
                                    max=8,
                                    style={'width': '100%', 'padding': '8px', 'backgroundColor': '#1e1e1e', 'color': '#e0e0e0', 'border': '1px solid #555'}
                                ),
                            ]),
                            html.Div(children=[
                                dcc.Checklist(
                                    id='scan-options',
                                    options=[
                                        {'label': ' Enable Image Scanning (OCR)', 'value': 'scan-images'},
                                    ],
                                    value=[],
                                    style={'color': '#e0e0e0', 'marginTop': '25px'}
                                ),
                            ]),
                        ]),
                    ]),
                    
                    # Control Buttons
                    html.Div(style={'display': 'flex', 'gap': '15px', 'marginBottom': '30px'}, children=[
                        html.Button(
                            "Start Monitoring",
                            id='start-monitor-btn',
                            n_clicks=0,
                            style={
                                'padding': '12px 24px',
                                'fontSize': '16px',
                                'backgroundColor': '#28a745',
                                'color': 'white',
                                'border': 'none',
                                'borderRadius': '6px',
                                'cursor': 'pointer'
                            }
                        ),
                        html.Button(
                            "Stop Monitoring",
                            id='stop-monitor-btn',
                            n_clicks=0,
                            style={
                                'padding': '12px 24px',
                                'fontSize': '16px',
                                'backgroundColor': '#dc3545',
                                'color': 'white',
                                'border': 'none',
                                'borderRadius': '6px',
                                'cursor': 'pointer'
                            }
                        ),
                        html.Button(
                            "Run Single Scan",
                            id='single-scan-btn',
                            n_clicks=0,
                            style={
                                'padding': '12px 24px',
                                'fontSize': '16px',
                                'backgroundColor': '#007bff',
                                'color': 'white',
                                'border': 'none',
                                'borderRadius': '6px',
                                'cursor': 'pointer'
                            }
                        ),
                    ]),
                    
                    # Output/Log Display
                    html.Div(style={'backgroundColor': '#2d2d2d', 'padding': '20px', 'borderRadius': '8px'}, children=[
                        html.H4("Scanner Output", style={'color': '#e0e0e0', 'marginBottom': '15px'}),
                        html.Div(
                            id='scanner-output',
                            style={
                                'height': '300px',
                                'overflowY': 'auto',
                                'backgroundColor': '#1e1e1e',
                                'color': '#e0e0e0',
                                'fontFamily': 'monospace',
                                'padding': '10px',
                                'border': '1px solid #555',
                                'borderRadius': '4px',
                                'whiteSpace': 'pre-wrap'
                            }
                        ),
                    ]),
                    
                    # Store for tracking process IDs
                    dcc.Store(id='monitor-pid-store', data=None),
                    dcc.Store(id='dashboard-pid-store', data=None),
                ])
            ]),
        ]),
    ])

    @app.callback(
        [Output('bar-chart', 'figure'),
         Output('pie-chart', 'figure'),
         Output('network-graph', 'figure')],
        [Input('severity-filter', 'value'),
         Input('extension-filter', 'value'),
         Input('show-labels-check', 'value'),
         Input('data-store', 'data')],
        [State('bar-chart', 'figure'),
         State('pie-chart', 'figure'),
         State('network-graph', 'figure')]
    )
    def update_charts_on_change(selected_severities, selected_extensions, show_labels_value, data_dict,
                               current_bar, current_pie, current_network):
        """Update charts when filters or data change, using Patch for performance"""
        df = pd.DataFrame(data_dict) if data_dict else pd.DataFrame()
        
        selected_severities = selected_severities or []
        selected_extensions = selected_extensions or []
        
        filtered_df = df.copy()
        if selected_severities:
            filtered_df = filtered_df[filtered_df['Severities'].isin(selected_severities)]
        if selected_extensions:
            filtered_df = filtered_df[filtered_df['Extension'].isin(selected_extensions)]
        
        network_df = filtered_df if any([selected_severities, selected_extensions]) else df[df['Severities'].isin(['Critical', 'High', 'Medium'])]
        show_labels = 'show' in show_labels_value
        
        # Use Patch() for partial updates
        if current_bar:
            patched_bar = Patch()
            new_bar = create_bar_chart(filtered_df)
            patched_bar.data = new_bar.data
            patched_bar.layout = new_bar.layout
            bar_chart = patched_bar
        else:
            bar_chart = create_bar_chart(filtered_df)
            
        if current_pie:
            patched_pie = Patch()
            new_pie = create_pie_chart(filtered_df)
            patched_pie.data = new_pie.data
            patched_pie.layout = new_pie.layout
            pie_chart = patched_pie
        else:
            pie_chart = create_pie_chart(filtered_df)
            
        if current_network:
            patched_network = Patch()
            new_network = create_network_graph(network_df, show_labels)
            patched_network.data = new_network.data
            patched_network.layout = new_network.layout
            network_graph = patched_network
        else:
            network_graph = create_network_graph(network_df, show_labels)
        
        return bar_chart, pie_chart, network_graph

    @app.callback(
        [Output('data-store', 'data'),
         Output('aggregated-store', 'data'),
         Output('last-update', 'children')],
        Input('interval-component', 'n_intervals')
    )
    def reload_data(n_intervals):
        """Only reload data on interval, not on filter changes"""
        from datetime import datetime

        # Clear cache to force fresh data load
        cache.delete_memoized(load_data)
        cache.delete_memoized(load_skipped_data)
        cache.delete_memoized(get_total_findings_count)
        logging.info("Cache cleared - forcing fresh data load")

        try:
            df, skipped_df = load_data_from_lmdb()
            if df.empty:
                logging.warning("No data loaded from LMDB - checking for issues")
                # Try to check LMDB contents
                try:
                    env = get_lmdb_env_safe(write=False)
                    findings_db = env.open_db(b'findings')
                    with env.begin() as txn:
                        cursor = txn.cursor(db=findings_db)
                        sample_count = sum(1 for _ in cursor)
                    env.close()
                    logging.info(f"LMDB contains {sample_count} entries in findings database")
                except Exception as e:
                    logging.error(f"Could not check LMDB contents: {e}")

            df_dict = df.to_dict('records')
            pre_aggregated = create_pre_aggregated_data(df)
            last_update = f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (Loaded {len(df)} findings)"
            logging.info(f"Data reload complete: {len(df)} findings loaded")
            return df_dict, pre_aggregated, last_update
        except Exception as e:
            logging.error(f"Error during data reload: {e}")
            import traceback
            logging.error(f"Traceback: {traceback.format_exc()}")
            # Return empty data on error
            return [], {}, f"Error loading data: {str(e)}"

    @app.callback(
        Output('node-info-pane', 'children'),
        [Input('network-graph', 'clickData'),
         Input('data-store', 'data')]
    )
    def display_click_data(clickData, data_dict):
        if clickData is None or not data_dict:
            return dcc.Markdown("### Click a node for details")
        
        df = pd.DataFrame(data_dict)
        
        try:
            node_name = re.search(r'<b>(.*?)<\/b>', clickData['points'][0]['hovertext']).group(1)
        except:
            return dcc.Markdown("Could not identify node.")
        
        if node_name in df['FilePath'].unique():
            node_df = df[df['FilePath'] == node_name].drop_duplicates()
            secrets_list = [f"* **{row['SecretTypes']}** ({row['Severities']})\n  *Value: `{row['SecretValues']}`\n  *Context: `{row['Contexts']}`*" for _, row in node_df.iterrows()]
            return dcc.Markdown(f"### File: {node_name}\n#### Secrets ({len(secrets_list)}):\n{''.join(secrets_list)}")
        else:
            node_df = df[df['SecretTypes'] == node_name].drop_duplicates(subset=['FilePath'])
            files_list = [f"* `{row['FilePath']}` (Value: `{row['SecretValues']}`, Context: `{row['Contexts']}`)" for _, row in node_df.iterrows()]
            return dcc.Markdown(f"### Type: {node_name}\n#### Found In ({len(files_list)} files):\n{''.join(files_list)}")

    @app.callback(
        Output('skipped-table', 'data'),
        [Input('tabs-controller', 'value'),
         Input('interval-component', 'n_intervals')]
    )
    def update_skipped_table(selected_tab, n_intervals):
        if selected_tab != 'tab-skipped':
            return []
        
        # Clear cache to ensure fresh data
        cache.delete_memoized(load_skipped_data)
        logging.info("Skipped data cache cleared")
        
        # Reload skipped data on interval
        df = load_skipped_data()
        return df.to_dict('records')

    @app.callback(
        [Output('severity-filter', 'options'),
         Output('extension-filter', 'options')],
        Input('interval-component', 'n_intervals')
    )
    def update_dropdowns(n_intervals):
        # Clear cache to ensure fresh data for dropdown options
        cache.delete_memoized(load_data)
        logging.info("Data cache cleared for dropdown update")
        
        df = load_data()
        if df.empty:
            return [], []
        return (
            [{'label': s, 'value': s} for s in sorted(df['Severities'].unique()) if s],
            [{'label': e, 'value': e} for e in sorted(df['Extension'].unique()) if e]
        )

    @app.callback(
        Output("download-csv", "data"),
        Input("export-btn", "n_clicks"),
        State('data-store', 'data'),
        prevent_initial_call=True
    )
    def export_to_csv(n_clicks, data_dict):
        if not data_dict:
            return None
        
        df = pd.DataFrame(data_dict)
        return dcc.send_data_frame(df.to_csv, "secret_scan_findings.csv", index=False)

    # Scanner Control Callbacks
    def get_process_status(process_name):
        """Check if a process with given name is running"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if process_name in ' '.join(proc.info['cmdline'] or []):
                    return True, proc.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return False, None

    @app.callback(
        [Output('monitor-status', 'children'),
         Output('monitor-status', 'style'),
         Output('dashboard-status', 'children'),
         Output('dashboard-status', 'style')],
        Input('interval-component', 'n_intervals')
    )
    def update_status_display(n_intervals):
        # Check monitor status
        monitor_running, monitor_pid = get_process_status('continuous_monitor.py')
        if monitor_running:
            monitor_text = f"✅ Running (PID: {monitor_pid})"
            monitor_style = {'color': '#28a745', 'fontSize': '18px', 'fontWeight': 'bold'}
        else:
            monitor_text = "❌ Stopped"
            monitor_style = {'color': '#dc3545', 'fontSize': '18px', 'fontWeight': 'bold'}
        
        # Dashboard is always running since we're in it
        dashboard_text = "✅ Running (Current Session)"
        dashboard_style = {'color': '#28a745', 'fontSize': '18px', 'fontWeight': 'bold'}
        
        return monitor_text, monitor_style, dashboard_text, dashboard_style

    @app.callback(
        Output('scanner-output', 'children'),
        [Input('start-monitor-btn', 'n_clicks'),
         Input('stop-monitor-btn', 'n_clicks'),
         Input('single-scan-btn', 'n_clicks')],
        [State('target-directory', 'value'),
         State('tools-selection', 'value'),
         State('max-processes', 'value'),
         State('scan-options', 'value')]
    )
    def handle_scanner_controls(start_clicks, stop_clicks, scan_clicks, target_dir, tools, max_processes, scan_options):
        ctx = dash.callback_context
        if not ctx.triggered:
            return "Ready for commands..."
        
        button_id = ctx.triggered[0]['prop_id'].split('.')[0]
        output_lines = []
        
        try:
            if button_id == 'start-monitor-btn' and start_clicks > 0:
                # Stop any existing monitoring first
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        if 'continuous_monitor.py' in ' '.join(proc.info['cmdline'] or []):
                            proc.terminate()
                            output_lines.append(f"Stopped existing monitor (PID: {proc.info['pid']})")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Build command
                tools_str = ','.join(tools) if tools else 'custom'
                cmd = [
                    'python', 'start_monitoring.py', target_dir,
                    '--tools', tools_str,
                    '--max-processes', str(max_processes)
                ]
                
                if 'scan-images' in scan_options:
                    cmd.append('--scan-images')
                
                output_lines.append(f"Starting monitor with command: {' '.join(cmd)}")
                
                # Start the monitoring process
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=os.path.dirname(__file__)
                )
                
                output_lines.append(f"Monitor started with PID: {process.pid}")
                output_lines.append("Monitor is running in background...")
                
            elif button_id == 'stop-monitor-btn' and stop_clicks > 0:
                stopped_any = False
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        if 'continuous_monitor.py' in ' '.join(proc.info['cmdline'] or []):
                            proc.terminate()
                            output_lines.append(f"Stopped monitor (PID: {proc.info['pid']})")
                            stopped_any = True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                if not stopped_any:
                    output_lines.append("No running monitor found to stop.")
                
            elif button_id == 'single-scan-btn' and scan_clicks > 0:
                # Build command for single scan
                tools_str = ','.join(tools) if tools else 'custom'
                cmd = [
                    'python', 'run_secret_scanner.py', target_dir,
                    '--tools', tools_str,
                    '--max-processes', str(max_processes)
                ]
                
                if 'scan-images' in scan_options:
                    cmd.append('--scan-images')
                
                output_lines.append(f"Starting single scan: {' '.join(cmd)}")
                
                # Run single scan
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=os.path.dirname(__file__)
                )
                
                output_lines.append(f"Single scan started with PID: {process.pid}")
                output_lines.append("Scan is running in background...")
                
        except Exception as e:
            output_lines.append(f"Error: {str(e)}")
        
        return '\n'.join(output_lines)

    app.run(debug=False, host='127.0.0.1', port=8050)  # Production mode

if __name__ == '__main__':
    main()