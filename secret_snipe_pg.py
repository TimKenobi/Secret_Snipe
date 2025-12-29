"""
SecretSnipe Core Scanner Module - PostgreSQL/Redis Version

This module provides the core secret scanning functionality for the SecretSnipe platform.
It handles file processing, text extraction, signature matching, and PostgreSQL/Redis database operations.

Key Features:
- Multi-format file support (PDF, Excel, Word, images, archives)
- Advanced text extraction with OCR capabilities
- High-performance regex matching with Hyperscan support
- PostgreSQL for structured data storage
- Redis for caching and session management
- Parallel processing for large-scale scanning
- Comprehensive signature validation and compilation

Supported File Types:
- Plain text files (.txt, .py, .js, .java, etc.)
- PDF documents with OCR fallback
- Microsoft Office files (.xlsx, .xls, .docx, .doc)
- Images with OCR (.jpg, .png, .bmp, .tiff)
- Archive files (.zip) with recursive extraction

Database Features:
- PostgreSQL for structured data with full ACID compliance
- Redis for high-performance caching and session management
- Automatic schema management and migrations
- Connection pooling for concurrent access
- Comprehensive audit logging

Dependencies:
- psycopg2-binary for PostgreSQL connectivity
- redis for Redis operations
- PyMuPDF (fitz) for PDF processing
- openpyxl/xlrd for Excel files
- python-docx for Word documents
- EasyOCR for image text extraction
- Hyperscan for high-performance regex (optional)
- xxhash for fast file hashing
"""

import argparse
import json
import logging
import re
from pathlib import Path
import fitz  # PyMuPDF
import openpyxl
import xlrd
from docx import Document
from zipfile import ZipFile, BadZipFile
from itertools import groupby
from PIL import Image
import easyocr
try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False
    logging.warning("pytesseract not available, will use EasyOCR for image OCR")
try:
    import hyperscan
except ImportError:
    hyperscan = None
    logging.warning("Hyperscan not available, falling back to standard regex")
from tqdm import tqdm
from functools import partial
from datetime import datetime
import os
import sys
import string
import time
import psutil
import cProfile
import tempfile
import subprocess
import hashlib
import xxhash
import gc
from joblib import Parallel, delayed
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import cpu_count
import io
import numpy as np

# New imports for PostgreSQL and Redis
from database_manager import (
    db_manager, project_manager, scan_session_manager,
    findings_manager, file_cache_manager, init_database
)
from redis_manager import redis_manager, cache_manager, scan_cache
from config import config

# --- 1. CONFIGURATION & LOGGING ---
Image.MAX_IMAGE_PIXELS = None
logging.basicConfig(
    level=getattr(logging, config.log_level),
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(config.log_file, mode='a'),
        logging.StreamHandler()
    ]
)

# Global variables
reader = None  # EasyOCR reader (lazy loaded)
ocr_image_count = 0  # Counter for OCR processed images (for memory management)
signatures = []  # Compiled signatures

def load_signatures():
    """Load and compile signatures from JSON file"""
    global signatures
    try:
        with open("signatures.json", "r") as f:
            raw_signatures = json.load(f)

        # Validate and compile signatures
        valid_signatures = []
        for i, sig in enumerate(raw_signatures):
            try:
                # Validate required fields
                if not all(key in sig for key in ['name', 'regex', 'severity']):
                    logging.warning(f"Signature {i} missing required fields, skipping")
                    continue

                # Compile regex with error handling
                sig["regex"] = re.compile(sig["regex"])
                valid_signatures.append(sig)
                logging.debug(f"Compiled signature: {sig['name']}")
            except re.error as e:
                logging.warning(f"Invalid regex in signature {i}: {e}")
                continue

        signatures = valid_signatures
        logging.info(f"Loaded {len(signatures)} signatures")
        return True

    except FileNotFoundError:
        logging.error("signatures.json not found")
        return False
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing signatures.json: {e}")
        return False

def get_ocr_reader():
    """Lazy load EasyOCR reader with memory management"""
    global reader, ocr_image_count
    
    # If OCR is disabled, return None immediately
    if not config.scanner.enable_ocr:
        return None
    
    # Reset OCR reader every N images to prevent memory accumulation
    max_ocr_images = int(os.getenv('OCR_RESET_AFTER_IMAGES', '50'))
    if reader is not None and ocr_image_count >= max_ocr_images:
        logging.info(f"Resetting OCR reader after {ocr_image_count} images to free memory")
        del reader
        reader = None
        ocr_image_count = 0
        gc.collect()
        
    if reader is None:
        try:
            # Ensure EasyOCR model directory exists and is writable
            easyocr_dir = os.path.expanduser("~/.EasyOCR")
            model_dir = os.path.join(easyocr_dir, "model")
            os.makedirs(model_dir, exist_ok=True)
            
            logging.info("Initializing EasyOCR reader...")
            # Initialize with proper model directory and error handling
            reader = easyocr.Reader(
                config.scanner.ocr_languages,
                model_storage_directory=model_dir,
                download_enabled=True
            )
            logging.info("EasyOCR reader initialized successfully")
        except Exception as e:
            logging.error(f"Failed to initialize EasyOCR: {e}")
            logging.warning("OCR functionality will be disabled for this scan")
            reader = False  # Use False instead of None to indicate permanent failure
    return reader if reader is not False else None

def extract_text_from_file(file_path):
    """Extract text from various file formats"""
    file_path = Path(file_path)
    file_extension = file_path.suffix.lower()

    try:
        if file_extension in ['.txt', '.py', '.js', '.ts', '.java', '.cpp', '.c', '.h',
                             '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
                             '.clj', '.hs', '.ml', '.md', '.json', '.xml', '.yaml',
                             '.yml', '.toml', '.ini', '.cfg', '.conf', '.properties',
                             '.sh', '.bat', '.ps1', '.sql', '.html', '.css', '.scss']:
            # Plain text files
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()

        elif file_extension in ['.pdf']:
            # PDF files
            text = ""
            with fitz.open(file_path) as doc:
                for page in doc:
                    text += page.get_text()
            return text

        elif file_extension in ['.xlsx', '.xls']:
            # Excel files
            text = ""
            if file_extension == '.xlsx':
                workbook = openpyxl.load_workbook(file_path, read_only=True)
            else:
                workbook = xlrd.open_workbook(file_path)

            for sheet_name in workbook.sheetnames:
                if file_extension == '.xlsx':
                    sheet = workbook[sheet_name]
                    for row in sheet.iter_rows(values_only=True):
                        text += ' '.join(str(cell) for cell in row if cell) + '\n'
                else:
                    sheet = workbook.sheet_by_name(sheet_name)
                    for row_idx in range(sheet.nrows):
                        row = sheet.row_values(row_idx)
                        text += ' '.join(str(cell) for cell in row if cell) + '\n'
            return text

        elif file_extension in ['.docx']:
            # Word documents
            doc = Document(file_path)
            text = ""
            for paragraph in doc.paragraphs:
                text += paragraph.text + '\n'
            return text

        elif file_extension in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif']:
            # Image files with OCR
            global ocr_image_count
            
            # Check which OCR engine to use (pytesseract is lower memory, easyocr is more accurate)
            use_easyocr = os.getenv('OCR_ENGINE', 'pytesseract').lower() == 'easyocr'
            
            # Skip OCR for very large images to prevent OOM
            # For pytesseract we can handle larger files since it uses external process
            if use_easyocr:
                max_ocr_size_mb = float(os.getenv('MAX_OCR_FILE_SIZE_MB', '0.5'))  # 500KB for EasyOCR
            else:
                max_ocr_size_mb = float(os.getenv('MAX_OCR_FILE_SIZE_MB', '5.0'))  # 5MB for pytesseract
            
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            if file_size_mb > max_ocr_size_mb:
                logging.info(f"Skipping OCR for large image {file_path} ({file_size_mb:.2f}MB > {max_ocr_size_mb}MB)")
                return ""
            
            # Try pytesseract first (low memory usage via external process)
            if PYTESSERACT_AVAILABLE and not use_easyocr:
                try:
                    # Use PIL to open image, pytesseract handles the rest externally
                    img = Image.open(file_path)
                    # Set timeout to prevent hanging on complex images
                    text = pytesseract.image_to_string(img, timeout=30)
                    img.close()
                    ocr_image_count += 1
                    return text.strip()
                except RuntimeError as e:
                    # Timeout or other runtime error
                    logging.warning(f"pytesseract timeout for {file_path}: {e}")
                    return ""
                except Exception as e:
                    logging.warning(f"pytesseract failed for {file_path}: {e}, trying EasyOCR fallback")
                    # Fall through to EasyOCR
            
            # Fallback to EasyOCR (more accurate but higher memory)
            reader = get_ocr_reader()
            if reader:
                try:
                    results = reader.readtext(str(file_path))
                    text = ' '.join([result[1] for result in results])
                    ocr_image_count += 1  # Increment counter for memory management
                    # Force cleanup
                    del results
                    gc.collect()
                    return text
                except Exception as e:
                    logging.error(f"OCR processing failed for {file_path}: {e}")
                    return ""
            else:
                logging.warning(f"OCR not available for {file_path}")
                return ""

        elif file_extension in ['.zip']:
            # ZIP archives
            text = ""
            try:
                with ZipFile(file_path, 'r') as zip_file:
                    for file_info in zip_file.filelist:
                        if not file_info.is_dir():
                            with zip_file.open(file_info) as f:
                                content = f.read().decode('utf-8', errors='ignore')
                                text += content + '\n'
            except BadZipFile:
                logging.warning(f"Invalid ZIP file: {file_path}")
            return text

        else:
            # Unknown file type
            logging.debug(f"Unsupported file type: {file_extension}")
            return ""

    except Exception as e:
        logging.warning(f"Error extracting text from {file_path}: {e}")
        return ""

def luhn_checksum(card_number: str) -> bool:
    """
    Validate a credit card number using the Luhn algorithm (mod 10 checksum).
    
    The Luhn algorithm:
    1. From the rightmost digit, double every second digit
    2. If doubling results in a number > 9, subtract 9
    3. Sum all the digits
    4. If the total modulo 10 equals 0, the number is valid
    
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


def is_in_comment(context, position):
    """Check if a match is within a comment"""
    # Simple comment detection - can be enhanced
    lines = context.split('\n')
    if len(lines) < 3:
        return False

    # Check surrounding lines for comment markers
    for line in lines:
        line = line.strip()
        if line.startswith('//') or line.startswith('#') or line.startswith('/*') or '*/' in line:
            return True

    return False

def scan_text_with_signatures(text, file_path_str):
    """Scan text for secrets using compiled signatures"""
    findings = []

    for sig in signatures:
        try:
            for match in sig["regex"].finditer(text):
                value = match.group(0)

                # Get context around the match
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]
                
                # For low-risk/context-based findings (like Confidentiality Markers),
                # provide more useful secret_value by including surrounding context
                if sig.get("low_risk", False) or sig["name"] in ["Confidentiality Marker", "Private IP Address"]:
                    # Get a snippet around the match for better context in the value
                    snippet_start = max(0, match.start() - 20)
                    snippet_end = min(len(text), match.end() + 20)
                    secret_display = text[snippet_start:snippet_end].strip()
                    # Clean up the display value (remove newlines, limit length)
                    secret_display = ' '.join(secret_display.split())[:100]
                    if len(secret_display) < len(value):
                        secret_display = value
                else:
                    secret_display = value

                # Validate the finding
                is_valid = True
                validation_reason = ""

                # Check for password exclusion patterns
                if any(excl in value.lower() for excl in ["password", "passwd", "pwd"]):
                    is_valid = False
                    validation_reason = "Excluded password pattern"

                # Check if it's in a comment
                if is_in_comment(context, match.start()):
                    is_valid = False
                    validation_reason = "In comment"

                # Validate credit card numbers with Luhn algorithm
                if is_valid and sig["name"] == "Credit Card Number":
                    if not luhn_checksum(value):
                        is_valid = False
                        validation_reason = "Failed Luhn checksum validation"
                        logging.debug(f"Credit card {value[:6]}...{value[-4:]} failed Luhn check")

                finding = {
                    "file_path": file_path_str,
                    "secret_type": sig["name"],
                    "secret_value": secret_display,
                    "context": context,
                    "severity": sig["severity"],
                    "line_number": text[:match.start()].count('\n') + 1,
                    "is_valid": is_valid,
                    "validation_reason": validation_reason,
                    "confidence_score": 0.9 if is_valid else 0.5
                }
                findings.append(finding)

                if is_valid:
                    logging.info(f"Valid finding: {sig['name']} in {file_path_str}")
                else:
                    logging.debug(f"Invalid finding: {sig['name']} in {file_path_str} - {validation_reason}")

        except Exception as e:
            logging.warning(f"Error scanning with signature {sig['name']}: {e}")

    return findings

def process_file(file_path, project_id, scan_session_id):
    """Process a single file for secrets"""
    file_path_str = str(file_path)
    
    logging.info(f"Starting processing of file: {file_path_str} (size: {os.path.getsize(file_path)} bytes)")

    try:
        # Check file size limit
        if os.path.getsize(file_path) > config.scanner.max_file_size_mb * 1024 * 1024:
            logging.warning(f"File too large: {file_path_str}")
            return []

        # Extract text from file
        text = extract_text_from_file(file_path)
        if not text:
            return []

        # Get file metadata for change detection
        try:
            file_stat = file_path.stat()
            file_modified_at = datetime.fromtimestamp(file_stat.st_mtime)
            file_size = file_stat.st_size
        except Exception:
            file_modified_at = None
            file_size = None

        # Scan text for secrets
        findings = scan_text_with_signatures(text, file_path_str)

        # Store findings in database
        stored_findings = []
        for finding in findings:
            finding_id = findings_manager.insert_finding(
                scan_session_id=scan_session_id,
                project_id=project_id,
                file_path=finding['file_path'],
                secret_type=finding['secret_type'],
                secret_value=finding['secret_value'],
                context=finding['context'],
                severity=finding['severity'],
                line_number=finding['line_number'],
                confidence_score=finding['confidence_score'],
                tool_source='custom',
                metadata={
                    'is_valid': finding['is_valid'],
                    'validation_reason': finding['validation_reason'],
                    'file_modified_at': str(file_modified_at) if file_modified_at else None,
                    'file_size': file_size
                }
            )
            if finding_id:
                stored_findings.append(finding_id)

        # Cache file processing
        file_hash = xxhash.xxh64(open(file_path, 'rb').read()).hexdigest()
        file_cache_manager.cache_file(file_path_str, file_hash, scan_session_id)

        return stored_findings

    except Exception as e:
        logging.error(f"Error processing file {file_path_str}: {e}")
        return []

def scan_directory(directory_path, project_name="default", max_workers=None):
    """Scan a directory for secrets using PostgreSQL and Redis

    Returns:
        int: Number of findings found, or -1 on error
    """

    # Initialize database connection
    if not init_database():
        logging.error("Failed to initialize database")
        return False

    # Create or get project
    project = project_manager.get_project_by_name(project_name)
    if not project:
        project_id = project_manager.create_project(
            name=project_name,
            local_path=str(directory_path),
            description=f"Scan of {directory_path}"
        )
    else:
        project_id = project['id']

    # Create scan session
    scan_session_id = scan_session_manager.create_session(
        project_id=project_id,
        scan_type='custom',
        scan_parameters={
            'directory': str(directory_path),
            'max_workers': max_workers or config.scanner.threads
        }
    )

    if not scan_session_id:
        logging.error("Failed to create scan session")
        return False

    # Update project last scan time
    project_manager.update_project_scan_time(project_id)

    # Pre-initialize OCR reader if OCR is enabled to avoid repeated initialization
    if config.scanner.enable_ocr:
        ocr_reader = get_ocr_reader()
        if ocr_reader:
            logging.info("OCR reader pre-initialized successfully")
        else:
            logging.warning("OCR initialization failed - OCR will be disabled for this scan")

    # Quick file count pass to show total progress (fast - just counting, not reading files)
    logging.info("Counting total files to scan...")
    total_files = 0
    try:
        for root, dirs, files in os.walk(directory_path):
            dirs[:] = [d for d in dirs if d not in config.scanner.excluded_paths]
            for file in files:
                file_extension = Path(file).suffix.lower()
                if (file_extension in config.scanner.supported_extensions and 
                    file_extension not in config.scanner.excluded_extensions):
                    total_files += 1
        logging.info(f"Found {total_files:,} files to scan")
    except Exception as e:
        logging.warning(f"Could not count files: {e}. Progress will show without total.")
        total_files = 0

    # Stream files and scan them directly without building a large list
    total_findings = 0
    files_processed = 0
    
    # Force single worker to avoid memory issues
    max_workers = 1
    
    # Stream scan files in very small batches to minimize memory usage
    batch_size = 1  # Process one file at a time to avoid memory issues
    current_batch = []
    
    logging.info(f"Streaming files in batches of {batch_size} with {max_workers} workers")
    logging.info("Starting file discovery and scanning...")
    
    # Use a simple counter instead of tqdm for progress to save memory
    batch_count = 0
    for root, dirs, files in os.walk(directory_path):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in config.scanner.excluded_paths]

        for file in files:
            file_path = Path(root) / file
            file_extension = file_path.suffix.lower()

            # Check if file type is supported and not excluded
            if (file_extension in config.scanner.supported_extensions and 
                file_extension not in config.scanner.excluded_extensions):
                
                current_batch.append(file_path)
                
                # Process batch when it's full
                if len(current_batch) >= batch_size:
                    batch_count += 1
                    logging.info(f"Processing batch {batch_count} ({len(current_batch)} files)")
                    # Log the files in this batch for debugging
                    for i, file_path in enumerate(current_batch):
                        logging.info(f"  Batch {batch_count} File {i+1}: {file_path} ({file_path.stat().st_size} bytes)")
                    
                    batch_findings = process_file_batch(current_batch, max_workers, None, project_id, scan_session_id)
                    total_findings += batch_findings
                    files_processed += len(current_batch)
                    current_batch = []
                    
                    # Update progress in Redis for real-time status display
                    try:
                        cache_manager.set(
                            'scan_progress',
                            'custom',
                            {
                                'files_processed': files_processed,
                                'total_files': total_files,
                                'total_findings': total_findings,
                                'batch_count': batch_count,
                                'status': 'running',
                                'last_update': time.time()
                            },
                            ttl_seconds=3600  # 1 hour expiry
                        )
                    except Exception:
                        pass  # Don't fail scan if Redis update fails
                    
                    # Force garbage collection after each batch
                    gc.collect()
                    logging.info(f"Batch {batch_count} complete. Total processed: {files_processed}, Total findings: {total_findings}")
    
    # Process remaining files in the last batch
    if current_batch:
        batch_count += 1
        logging.info(f"Processing final batch {batch_count} ({len(current_batch)} files)")
        batch_findings = process_file_batch(current_batch, max_workers, None, project_id, scan_session_id)
        total_findings += batch_findings
        files_processed += len(current_batch)
        gc.collect()

    logging.info(f"Scan complete. Processed {files_processed} files. Total findings: {total_findings}")
    return total_findings


def process_file_batch(batch_files, max_workers, pbar, project_id, scan_session_id):
    """Process a batch of files with ThreadPoolExecutor"""
    batch_findings = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit batch tasks
        logging.info(f"Submitting {len(batch_files)} files to ThreadPoolExecutor with {max_workers} workers")
        future_to_file = {executor.submit(process_file, file_path, project_id, scan_session_id): file_path for file_path in batch_files}
        
        # Process completed tasks
        completed_count = 0
        for future in as_completed(future_to_file):
            file_path = future_to_file[future]
            completed_count += 1
            logging.info(f"Processing result {completed_count}/{len(batch_files)}: {file_path}")
            try:
                findings = future.result()
                batch_findings += len(findings) if findings else 0
                logging.info(f"File {file_path} completed successfully with {len(findings) if findings else 0} findings")
            except Exception as exc:
                logging.error(f'File {file_path} generated an exception: {exc}')
            finally:
                if pbar:
                    pbar.update(1)
    
    return batch_findings

    # Use batch processing to avoid memory overload
    max_workers = max_workers or config.scanner.threads
    batch_size = min(1000, max_workers * 50)  # Process in batches of 1000 or 50x workers
    total_findings = 0
    
    logging.info(f"Processing files in batches of {batch_size} with {max_workers} workers")

    with tqdm(total=len(files_to_scan), desc="Scanning files") as pbar:
        # Process files in batches
        for i in range(0, len(files_to_scan), batch_size):
            batch = files_to_scan[i:i + batch_size]
            batch_findings = 0
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit current batch
                future_to_file = {
                    executor.submit(process_file, file_path, project_id, scan_session_id): file_path
                    for file_path in batch
                }

                # Process batch results as they complete
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        findings = future.result()
                        batch_findings += len(findings)
                    except Exception as e:
                        logging.error(f"Error processing {file_path}: {e}")
                    pbar.update(1)
            
            total_findings += batch_findings
            # Force garbage collection after each batch
            gc.collect()
            
            logging.info(f"Completed batch {i//batch_size + 1}/{(len(files_to_scan)-1)//batch_size + 1}: {batch_findings} findings")

    # Update scan session with final results
    scan_session_manager.update_session_status(
        session_id=scan_session_id,
        status='completed',
        total_files=len(files_to_scan),
        total_findings=total_findings
    )

    logging.info(f"Scan completed: {total_findings} findings in {len(files_to_scan)} files")
    return total_findings

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="SecretSnipe Scanner")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--project", default="default", help="Project name")
    parser.add_argument("--workers", type=int, help="Number of worker threads")
    parser.add_argument("--config", help="Configuration file path")

    args = parser.parse_args()

    # Load configuration
    if args.config:
        # Load custom config if specified
        pass

    # Load signatures
    if not load_signatures():
        logging.error("Failed to load signatures")
        return 1

    # Initialize Redis
    if not redis_manager or not redis_manager.ping():
        logging.warning("Redis not available - continuing without caching")

    # Scan directory
    success = scan_directory(
        directory_path=Path(args.directory),
        project_name=args.project,
        max_workers=args.workers
    )

    return 0 if success >= 0 else 1

if __name__ == "__main__":
    sys.exit(main())