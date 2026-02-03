#!/usr/bin/env python3
"""
Cleanup script to remove credit card findings that fail Luhn validation.

This script:
1. Fetches all credit card findings from the database
2. Validates each one using the Luhn algorithm
3. Applies context-based heuristics to detect false positives
4. Marks findings as false positives (instead of deleting)
5. Reports statistics on what was cleaned up
"""

import os
import sys
import re

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


def is_likely_not_credit_card(value: str, context: str) -> tuple:
    """
    Additional heuristics to detect false positive credit card numbers.
    """
    digits = ''.join(c for c in value if c.isdigit())
    context_lower = context.lower() if context else ''
    
    # Check if the context suggests this is NOT a credit card
    non_card_context = [
        'version', 'v.', 'build', 'revision', 'rev.', 'release',
        'timestamp', 'datetime', 'date', 'time', 
        'id:', 'id=', 'id ', 'identifier', 'uid', 'uuid',
        'phone', 'tel', 'fax', 'mobile',
        'order', 'invoice', 'ref', 'reference', 'tracking',
        'serial', 'sn:', 'part', 'model', 'sku',
        'ip:', 'address:', 'port', 'sequence', 'seq',
        'index', 'offset', 'position', 'count',
        'checksum', 'hash', 'digest', 'crc',
    ]
    
    for marker in non_card_context:
        if marker in context_lower:
            card_context = ['credit', 'card', 'payment', 'visa', 'mastercard', 
                           'amex', 'discover', 'pan', 'ccn', 'cardnum']
            has_card_context = any(cc in context_lower for cc in card_context)
            if not has_card_context:
                return True, f"Context suggests non-card data: '{marker}'"
    
    # Check for version number patterns
    if re.search(r'v?\d+\.\d+', context or '', re.IGNORECASE):
        return True, "Appears to be version number"
    
    # Check for timestamp-like patterns
    if digits[:4] in ['2024', '2025', '2026', '2023', '2022', '2021', '2020', '2019']:
        if len(digits) >= 14:
            return True, "Appears to be timestamp"
    
    # Check for zeros (placeholder patterns)
    zero_count = digits.count('0')
    if zero_count >= len(digits) * 0.7:
        return True, "Too many zeros (likely placeholder)"
    
    return False, ""


def cleanup_invalid_credit_cards(dry_run: bool = False):
    """
    Clean up credit card findings that fail validation.
    Marks them as false positives instead of deleting.
    
    Args:
        dry_run: If True, only report what would be marked as FP without actually doing it
    """
    logger.info("=" * 60)
    logger.info("Credit Card Validation Cleanup")
    logger.info("=" * 60)
    
    # Initialize database connection
    if not init_database():
        logger.error("Failed to initialize database connection")
        return
    
    # Fetch all credit card findings that are not already marked as FP
    query = """
        SELECT id, secret_value, context, file_path 
        FROM findings 
        WHERE secret_type = 'Credit Card Number'
          AND resolution_status != 'false_positive'
    """
    
    try:
        findings = db_manager.execute_query(query)
        
        if not findings:
            logger.info("No credit card findings found to validate")
            return
        
        logger.info(f"Found {len(findings)} credit card findings to validate")
        
        valid_count = 0
        luhn_fail_ids = []
        context_fail_ids = []
        
        # Validate each finding
        for finding in findings:
            finding_id = finding['id']
            secret_value = finding['secret_value']
            context = finding.get('context', '')
            file_path = finding['file_path']
            
            # First check Luhn
            if not luhn_checksum(secret_value):
                luhn_fail_ids.append((finding_id, "Failed Luhn checksum"))
                if len(luhn_fail_ids) <= 5:
                    masked = secret_value[:6] + '...' + secret_value[-4:] if len(secret_value) > 10 else secret_value
                    logger.info(f"  LUHN FAIL: {masked}")
            else:
                # Check context-based heuristics
                is_fp, reason = is_likely_not_credit_card(secret_value, context)
                if is_fp:
                    context_fail_ids.append((finding_id, reason))
                    if len(context_fail_ids) <= 5:
                        masked = secret_value[:6] + '...' + secret_value[-4:] if len(secret_value) > 10 else secret_value
                        logger.info(f"  CONTEXT FP: {masked} - {reason}")
                else:
                    valid_count += 1
        
        all_fp_ids = luhn_fail_ids + context_fail_ids
        
        logger.info("-" * 60)
        logger.info(f"Validation Results:")
        logger.info(f"  ✓ Valid findings:        {valid_count}")
        logger.info(f"  ✗ Failed Luhn:           {len(luhn_fail_ids)}")
        logger.info(f"  ✗ Context false positive: {len(context_fail_ids)}")
        logger.info(f"  Total to mark as FP:     {len(all_fp_ids)}")
        logger.info("-" * 60)
        
        if all_fp_ids:
            if dry_run:
                logger.info(f"DRY RUN: Would mark {len(all_fp_ids)} findings as false positives")
            else:
                # Mark as false positive in batches
                batch_size = 500
                marked_total = 0
                
                for i in range(0, len(all_fp_ids), batch_size):
                    batch = all_fp_ids[i:i + batch_size]
                    batch_ids = [fp[0] for fp in batch]
                    placeholders = ','.join(['%s'] * len(batch_ids))
                    
                    update_query = f"""
                        UPDATE findings 
                        SET resolution_status = 'false_positive',
                            fp_reason = 'Auto-detected: Failed validation',
                            fp_marked_by = 'cleanup_script',
                            fp_marked_at = NOW()
                        WHERE id IN ({placeholders})
                    """
                    
                    rows_updated = db_manager.execute_update(update_query, tuple(batch_ids))
                    marked_total += rows_updated
                    logger.info(f"  Marked batch {i//batch_size + 1}: {rows_updated} findings as FP")
                
                logger.info(f"✅ Successfully marked {marked_total} findings as false positives")
                
                # Refresh the materialized view
                try:
                    db_manager.execute_update("REFRESH MATERIALIZED VIEW CONCURRENTLY mv_findings_summary")
                    logger.info("✅ Refreshed materialized view")
                except Exception as e:
                    logger.warning(f"Could not refresh materialized view: {e}")
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
                        help='Show what would be marked as FP without actually doing it')
    
    args = parser.parse_args()
    
    cleanup_invalid_credit_cards(dry_run=args.dry_run)
