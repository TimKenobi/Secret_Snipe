#!/usr/bin/env python3
"""
Cleanup script to remove credit card findings that fail Luhn validation.

This script:
1. Fetches all credit card findings from the database
2. Validates each one using the Luhn algorithm
3. Deletes findings that fail validation (false positives)
4. Reports statistics on what was cleaned up
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, '/app')

from database_manager import db_manager, init_database
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def luhn_checksum(card_number: str) -> bool:
    """
    Validate a credit card number using the Luhn algorithm (mod 10 checksum).
    
    Args:
        card_number: The card number string (may contain spaces/dashes)
        
    Returns:
        True if the card number passes Luhn validation, False otherwise
    """
    # Remove spaces, dashes, and any other non-digit characters
    digits = ''.join(c for c in card_number if c.isdigit())
    
    if not digits or len(digits) < 13 or len(digits) > 19:
        return False
    
    # Convert to list of integers, reversed
    digits_list = [int(d) for d in digits][::-1]
    
    # Apply Luhn algorithm
    checksum = 0
    for i, digit in enumerate(digits_list):
        if i % 2 == 1:  # Every second digit from right (index 1, 3, 5...)
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    
    return checksum % 10 == 0


def cleanup_invalid_credit_cards(dry_run: bool = False):
    """
    Clean up credit card findings that fail Luhn validation.
    
    Args:
        dry_run: If True, only report what would be deleted without actually deleting
    """
    logger.info("=" * 60)
    logger.info("Credit Card Luhn Validation Cleanup")
    logger.info("=" * 60)
    
    # Initialize database connection
    if not init_database():
        logger.error("Failed to initialize database connection")
        return
    
    # Fetch all credit card findings
    query = """
        SELECT id, secret_value, file_path 
        FROM findings 
        WHERE secret_type = 'Credit Card Number'
    """
    
    try:
        findings = db_manager.execute_query(query)
        
        if not findings:
            logger.info("No credit card findings found in database")
            return
        
        logger.info(f"Found {len(findings)} credit card findings to validate")
        
        valid_count = 0
        invalid_count = 0
        invalid_ids = []
        
        # Validate each finding
        for finding in findings:
            finding_id = finding['id']
            secret_value = finding['secret_value']
            file_path = finding['file_path']
            
            if luhn_checksum(secret_value):
                valid_count += 1
            else:
                invalid_count += 1
                invalid_ids.append(finding_id)
                if invalid_count <= 10:  # Show first 10 examples
                    # Mask the card number for logging
                    masked = secret_value[:6] + '...' + secret_value[-4:] if len(secret_value) > 10 else secret_value
                    logger.info(f"  INVALID: {masked} in {file_path[:80]}...")
        
        logger.info("-" * 60)
        logger.info(f"Validation Results:")
        logger.info(f"  ✓ Valid (pass Luhn):   {valid_count}")
        logger.info(f"  ✗ Invalid (fail Luhn): {invalid_count}")
        logger.info("-" * 60)
        
        if invalid_ids:
            if dry_run:
                logger.info(f"DRY RUN: Would delete {len(invalid_ids)} invalid findings")
            else:
                # Delete invalid findings in batches using execute_update
                batch_size = 500
                deleted_total = 0
                
                for i in range(0, len(invalid_ids), batch_size):
                    batch = invalid_ids[i:i + batch_size]
                    placeholders = ','.join(['%s'] * len(batch))
                    delete_query = f"DELETE FROM findings WHERE id IN ({placeholders})"
                    
                    rows_deleted = db_manager.execute_update(delete_query, tuple(batch))
                    deleted_total += rows_deleted
                    logger.info(f"  Deleted batch {i//batch_size + 1}: {rows_deleted} findings")
                
                logger.info(f"✅ Successfully deleted {deleted_total} invalid credit card findings")
        else:
            logger.info("✅ All credit card findings are valid - no cleanup needed")
        
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
        raise


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Clean up invalid credit card findings')
    parser.add_argument('--dry-run', action='store_true', 
                        help='Show what would be deleted without actually deleting')
    
    args = parser.parse_args()
    
    cleanup_invalid_credit_cards(dry_run=args.dry_run)
