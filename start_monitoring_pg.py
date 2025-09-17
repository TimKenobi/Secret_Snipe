"""
Start Continuous Monitoring Service

Convenience script to start the continuous monitoring service
with proper configuration and error handling.
"""

import argparse
import logging
import sys
import os
from pathlib import Path

def main():
    """Start the continuous monitoring service"""
    parser = argparse.ArgumentParser(description="Start Continuous Monitoring")
    parser.add_argument("directory", help="Directory to monitor")
    parser.add_argument("--project", default="continuous-monitor",
                       help="Project name for monitoring")
    parser.add_argument("--teams-webhook",
                       help="Teams webhook URL for weekly reports")
    parser.add_argument("--log-level", default="INFO",
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help="Logging level")

    args = parser.parse_args()

    # Set environment variables
    if args.teams_webhook:
        os.environ['TEAMS_WEBHOOK_URL'] = args.teams_webhook

    os.environ['LOG_LEVEL'] = args.log_level

    # Import and run continuous monitor
    try:
        from continuous_monitor_pg import main as monitor_main
        sys.argv = ['continuous_monitor_pg.py', args.directory,
                   '--project', args.project]
        if args.teams_webhook:
            sys.argv.extend(['--teams-webhook', args.teams_webhook])

        return monitor_main()

    except ImportError as e:
        print(f"Error importing continuous monitor: {e}")
        print("Make sure all dependencies are installed")
        return 1
    except KeyboardInterrupt:
        print("\nContinuous monitoring stopped by user")
        return 0
    except Exception as e:
        print(f"Error starting continuous monitoring: {e}")
        return 1

if __name__ == "__main__":
    exit(main())