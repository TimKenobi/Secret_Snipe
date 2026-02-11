#!/usr/bin/env python3
"""Test script to verify agent administration findings query"""
import os
import sys

# Ensure imports work
sys.path.insert(0, '/app')

import psycopg2
import psycopg2.extras

# Agent database settings
agent_db_host = os.environ.get('AGENT_DB_HOST', '10.150.110.24')
agent_db_port = int(os.environ.get('AGENT_DB_PORT', 5433))
agent_db_name = 'secretsnipe_agents'
agent_db_user = 'secretsnipe'
agent_db_pass = 'secretsnipe_secure_pass'

print(f"Connecting to agent DB at {agent_db_host}:{agent_db_port}")

try:
    conn = psycopg2.connect(
        host=agent_db_host,
        port=agent_db_port,
        database=agent_db_name,
        user=agent_db_user,
        password=agent_db_pass,
        cursor_factory=psycopg2.extras.RealDictCursor
    )
    print("Connected successfully!")
    
    cur = conn.cursor()
    
    # Test query - same as list_findings
    query = """
        SELECT 
            af.*,
            a.hostname as agent_hostname
        FROM agent_findings af
        LEFT JOIN agents a ON af.agent_id = a.agent_id
        ORDER BY af.found_at DESC
        LIMIT 500
    """
    
    cur.execute(query)
    results = cur.fetchall()
    
    print(f"\nFound {len(results)} findings:")
    for r in results[:5]:
        print(f"  - {r['secret_type']}: {r['file_path']} ({r['severity']}) - status: {r['status']}")
    
    if len(results) > 5:
        print(f"  ... and {len(results) - 5} more")
    
    cur.close()
    conn.close()
    print("\nQuery completed successfully!")
    
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
