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
    import hyperscan
except ImportError:
    hyperscan = None
    logging.warning("Hyperscan not available, falling back to standard regex")
from tqdm import tqdm
from functools import partial
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
    """Lazy load EasyOCR reader"""
    global reader
    if reader is None:
        try:
            logging.info("Initializing EasyOCR reader...")
            reader = easyocr.Reader(config.scanner.ocr_languages)
            logging.info("EasyOCR reader initialized successfully")
        except Exception as e:
            logging.error(f"Failed to initialize EasyOCR: {e}")
            reader = None
    return reader

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
            reader = get_ocr_reader()
            if reader:
                results = reader.readtext(str(file_path))
                return ' '.join([result[1] for result in results])
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

                finding = {
                    "file_path": file_path_str,
                    "secret_type": sig["name"],
                    "secret_value": value,
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

    try:
        # Check file size limit
        if os.path.getsize(file_path) > config.scanner.max_file_size_mb * 1024 * 1024:
            logging.warning(f"File too large: {file_path_str}")
            return []

        # Extract text from file
        text = extract_text_from_file(file_path)
        if not text:
            return []

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
                    'validation_reason': finding['validation_reason']
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
    """Scan a directory for secrets using PostgreSQL and Redis"""

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

    # Collect files to scan
    files_to_scan = []
    for root, dirs, files in os.walk(directory_path):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in config.scanner.excluded_paths]

        for file in files:
            file_path = Path(root) / file
            file_extension = file_path.suffix.lower()

            # Check if file type is supported
            if file_extension in config.scanner.supported_extensions:
                files_to_scan.append(file_path)

    logging.info(f"Found {len(files_to_scan)} files to scan")

    # Use parallel processing
    max_workers = max_workers or config.scanner.threads
    total_findings = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_file = {
            executor.submit(process_file, file_path, project_id, scan_session_id): file_path
            for file_path in files_to_scan
        }

        # Process results as they complete
        with tqdm(total=len(files_to_scan), desc="Scanning files") as pbar:
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    findings = future.result()
                    total_findings += len(findings)
                except Exception as e:
                    logging.error(f"Error processing {file_path}: {e}")
                pbar.update(1)

    # Update scan session with final results
    scan_session_manager.update_session_status(
        session_id=scan_session_id,
        status='completed',
        total_files=len(files_to_scan),
        total_findings=total_findings
    )

    logging.info(f"Scan completed: {total_findings} findings in {len(files_to_scan)} files")
    return True

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
    if not redis_manager.ping():
        logging.warning("Redis not available - continuing without caching")

    # Scan directory
    success = scan_directory(
        directory_path=Path(args.directory),
        project_name=args.project,
        max_workers=args.workers
    )

    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())