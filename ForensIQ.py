import os
import streamlit as st
import pandas as pd
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.documents import Document
from langchain_core.runnables import RunnableSequence, RunnablePassthrough, RunnableLambda
import datetime
import pynvml
import warnings
warnings.filterwarnings("ignore", category=FutureWarning, message=".*pynvml package is deprecated.*")
import chromadb
import requests
import subprocess
import json
import time
from pathlib import Path
import gc

# Import for folder picker
import shutil
import tempfile
import tkinter as tk
from tkinter import filedialog

# Add new imports for dashboard
import threading
from collections import deque
import plotly.graph_objects as go
import plotly.express as px

# --- FIX 1: Print developer info only once ---
_developer_info_printed = False

def print_developer_info():
    """Print developer info only once per session"""
    global _developer_info_printed
    if not _developer_info_printed:
        print("")
        print("Developed by Jacob Wilson")
        print("dfirvault@gmail.com")
        print("")
        _developer_info_printed = True

# Enhanced EVTX import with better error handling
PyEvtxParser = None
try:
    from evtx import PyEvtxParser
except ImportError as e:
    st.warning(f"⚠️ EVTX module not installed. .evtx support disabled. Install with: `pip install python-evtx`")

# Import for file type detection
try:
    import magic
except ImportError:
    magic = None
    st.info("💡 Install `python-magic` or `python-magic-bin` for better file type detection")

try:
    import chardet
except ImportError:
    chardet = None
    st.info("💡 Install `chardet` for better encoding detection")

def check_chromadb_compatibility():
    """Check if chromadb supports score_threshold parameter"""
    try:
        import chromadb
        # Try to create a mock query to check if score_threshold is supported
        # We'll check the version instead
        version = chromadb.__version__
        major, minor, patch = map(int, version.split('.')[:3])
        # score_threshold was likely added around version 0.4.18+
        return major > 0 or (major == 0 and minor >= 4)
    except:
        return False

# Store compatibility result
CHROMADB_SUPPORTS_SCORE_THRESHOLD = check_chromadb_compatibility()

# Config file path
CONFIG_FILE = 'config.txt'

# Enhanced supported extensions with common log file patterns
SUPPORTED_EXTENSIONS = {
    '.csv': 'CSV Log File',
    '.evtx': 'Windows Event Log',
    '.log': 'Text Log File',
    '.txt': 'Text File',
    '.json': 'JSON Log File',
    '.xml': 'XML Log File',
    '.syslog': 'System Log File',
    '.audit': 'Audit Log File',
    '.conf': 'Configuration File',
    '.cfg': 'Configuration File',
    '.ini': 'Configuration File',
    '.out': 'Output Log File',
    '.err': 'Error Log File',
    '': 'No Extension (Text File)'
}

# Common log file names without extensions
COMMON_LOG_FILES = {
    'messages', 'syslog', 'auth.log', 'secure', 'kern.log', 'debug',
    'maillog', 'cron', 'daemon.log', 'user.log', 'system.log',
    'application', 'access', 'error', 'events'
}

# --- UPDATED: Comprehensive DFIR Prompt for Detailed Analysis ---
DETAILED_DFIR_PROMPT = """You are a senior cybersecurity DFIR (Digital Forensics and Incident Response) analyst conducting a comprehensive investigation. Your analysis MUST be extremely detailed, thorough, and provide comprehensive explanations.

# ANALYSIS REQUIREMENTS:

## 1. EXECUTIVE SUMMARY (Detailed)
- Provide a 3-5 paragraph overview of findings
- State the overall security posture
- Highlight the most critical findings first
- Estimate the incident timeline and scope

## 2. DETAILED TECHNICAL ANALYSIS (Expand each section)
### Suspicious IP Addresses
For EACH IP address found:
- List ALL occurrences with timestamps
- Explain WHY it's suspicious (port scans, brute force, unusual geolocation, etc.)
- Provide context from logs (what was attempted/accessed)
- Risk assessment (High/Medium/Low)

### Suspicious User Accounts & Activities
For EACH user account:
- Document ALL activities with timestamps
- Identify privilege escalation attempts
- Note failed/successful logins
- Highlight unusual patterns (off-hours, multiple systems)

### Specific Threat Evidence (Detailed Findings)
#### RDP Tunneling/Port Forwarding
- Identify specific commands (plink.exe, netcat, etc.)
- Document source/destination IPs
- Note any encrypted/obfuscated traffic

#### Password Hash Attacks
- Identify NTLMv1 usage specifically
- Document hash extraction attempts
- Note pass-the-hash activities

#### Log Clearing Evidence
- Identify event IDs 1102, 104, 517
- Document clearing attempts with timestamps
- Note what logs were targeted

#### Unusual Process Execution
- List ALL unusual processes found
- Document parent-child relationships
- Note execution paths and arguments
- Flag living-off-the-land binaries (LOLBAS)

#### Lateral Movement
- Document ALL lateral movement attempts
- Identify techniques used (WMI, PSExec, RDP, etc.)
- Map the movement path between systems

## 3. COMPREHENSIVE TIMELINE
Create a minute-by-minute timeline including:
- Initial access
- Discovery/reconnaissance
- Lateral movement
- Privilege escalation
- Data exfiltration
- Persistence establishment
- Defense evasion attempts

## 4. THREAT INTELLIGENCE CORRELATION
- Map findings to MITRE ATT&CK techniques
- Provide TTPs (Tactics, Techniques, Procedures)
- Suggest likely threat actor groups
- Note any indicators matching known campaigns

## 5. INDICATORS OF COMPROMISE (IOCs) - Comprehensive List
### Host-based IOCs
- File paths and hashes (MD5, SHA256)
- Registry keys modified
- Scheduled tasks created
- Services installed

### Network-based IOCs
- ALL suspicious IPs with ASN and geolocation
- Domain names and URLs
- User agents and HTTP headers
- Protocol anomalies

### Behavioral IOCs
- Tactics, Techniques, and Procedures observed
- Tools and scripts used
- Persistence mechanisms
- Data staging locations

## 6. THREAT LEVEL ASSESSMENT (Detailed)
Rate 1-10 with detailed justification:
- Attack sophistication (1-10)
- Impact severity (1-10)
- Breach scope (1-10)
- Defensive gaps exploited (1-10)
- Overall threat score with explanation

## 7. ACTIONABLE RECOMMENDATIONS (Prioritized)
### IMMEDIATE Actions (0-24 hours)
1. [Specific containment step 1]
2. [Specific eradication step 2]
3. [Specific recovery step 3]

### SHORT-TERM Actions (1-7 days)
1. [Hardening recommendation 1]
2. [Monitoring improvement 2]
3. [Policy update 3]

### LONG-TERM Actions (30+ days)
1. [Architectural change 1]
2. [Security program enhancement 2]
3. [Training requirement 3]

## 8. INVESTIGATION NOTES
- Data sources analyzed and limitations
- Assumptions made
- Areas requiring further investigation
- Confidence level in findings (High/Medium/Low)

# FORMAT REQUIREMENTS:
- Use clear headings and subheadings
- Include tables for IOCs where appropriate
- Use bullet points for lists
- Bold key findings for emphasis
- Ensure report is scannable but comprehensive

# IMPORTANT: Your response should be MINIMUM 1500-2000 words. Provide exhaustive detail with specific log examples.

Context (Log Data for Analysis): {context}

Question: {question}

Now provide your comprehensive DFIR analysis:
"""
# --- END UPDATE ---

# Model classification definitions
MODEL_CATEGORIES = {
    "gpu_optimized": {
        "description": "⚡ GPU Optimized (Fastest)",
        "models": [
            "llama3.2:1b-instruct-q4_0", "llama3.2:1b-instruct-q8_0", "llama3.2:1b-instruct-f16",
            "llama3.2:3b-instruct-q4_0", "llama3.2:3b-instruct-q8_0", "llama3.2:3b-instruct-f16",
            "qwen2.5:0.5b-instruct-q4_0", "qwen2.5:0.5b-instruct-q8_0", "qwen2.5:0.5b-instruct-f16",
            "qwen2.5:1.5b-instruct-q4_0", "qwen2.5:1.5b-instruct-q8_0", "qwen2.5:1.5b-instruct-f16",
            "qwen2.5:3b-instruct-q4_0", "qwen2.5:3b-instruct-q8_0", "qwen2.5:3b-instruct-f16",
            "qwen2.5:7b-instruct-q4_0", "qwen2.5:7b-instruct-q8_0", "qwen2.5:7b-instruct-f16",
            "phi3:mini-instruct-q4_0", "phi3:mini-instruct-q8_0", "phi3:mini-instruct-f16",
            "phi3:medium-instruct-q4_0", "phi3:medium-instruct-q8_0", "phi3:medium-instruct-f16",
            "gemma2:2b-instruct-q4_0", "gemma2:2b-instruct-q8_0", "gemma2:2b-instruct-f16",
            "gemma2:9b-instruct-q4_0", "gemma2:9b-instruct-q8_0", "gemma2:9b-instruct-f16",
            "mistral:7b-instruct-q4_0", "mistral:7b-instruct-q8_0", "mistral:7b-instruct-f16",
            "mixtral:8x7b-instruct-q4_0", "mixtral:8x7b-instruct-q8_0"
        ],
        "priority": 1
    },
    "very_fast": {
        "description": "🚀 Very Fast (Basic Hardware)",
        "models": [
            "tinyllama:1.1b", "tinyllama:1.1b-chat", "tinyllama:1.1b-chat-q4_0",
            "qwen2.5:0.5b", "qwen2.5:0.5b-instruct",
            "llama3.2:1b", "llama3.2:1b-instruct",
            "phi2:2.7b", "phi2:2.7b-instruct",
            "stablelm2:1.6b", "stablelm2:1.6b-instruct"
        ],
        "priority": 2
    },
    "fast": {
        "description": "⚡ Fast (Good Balance)",
        "models": [
            "phi:2.7b", "phi:2.7b-instruct",
            "llama3.2:3b", "llama3.2:3b-instruct",
            "gemma2:2b", "gemma2:2b-instruct",
            "qwen2.5:3b", "qwen2.5:3b-instruct",
            "mistral:7b", "mistral:7b-instruct",
            "codellama:7b", "codellama:7b-instruct"
        ],
        "priority": 3
    },
    "detailed_analysis": {
        "description": "📊 Detailed Analysis (Best for Reports)",
        "models": [
            "llama3.1:70b-instruct-q4_0",
            "llama3.1:70b-instruct-q8_0",
            "llama3.1:70b-instruct-f16",
            "qwen2.5:72b-instruct-q4_0",
            "qwen2.5:72b-instruct-q8_0",
            "mixtral:8x22b-instruct-q4_0",
            "dolphin-llama3.1:70b",
            "wizardlm2:7b",  # Excellent at detailed explanations
            "ye ",  # Structured responses
            "command-r-plus:104b",  # Very detailed
            "llama3:70b-instruct",  # Good balance
            "mistral:large",  # Detailed reasoning
        ],
        "priority": 6,
        "recommended_for": "Comprehensive reports, detailed analysis, executive summaries"
    },
    "balanced": {
        "description": "🎯 Balanced (Better Quality)",
        "models": [
            "phi3:mini", "phi3:mini-instruct",
            "qwen2.5:7b", "qwen2.5:7b-instruct",
            "llama3.1:8b", "llama3.1:8b-instruct",
            "llama3:8b", "llama3:8b-instruct",
            "gemma2:9b", "gemma2:9b-instruct",
            "codegemma:7b", "codegemma:7b-instruct",
            "dolphin-mistral:7b", "dolphin-llama3:8b"
        ],
        "priority": 4
    },
    "quality": {
        "description": "🏆 High Quality (Larger Models)",
        "models": [
            "llama3.1:70b", "llama3.1:70b-instruct",
            "llama3:70b", "llama3:70b-instruct",
            "qwen2.5:72b", "qwen2.5:72b-instruct",
            "mixtral:8x7b", "mixtral:8x7b-instruct",
            "mixtral:8x22b", "mixtral:8x22b-instruct",
            "codellama:34b", "codellama:34b-instruct",
            "wizardcoder:34b", "wizardlm:70b"
        ],
        "priority": 5
    }
}

# --- NEW: Enhanced File Type Detection Functions ---
def is_binary_file(file_path):
    """Check if a file is binary"""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            if b'\0' in chunk:  # Binary files often contain null bytes
                return True
                
        # Additional check: try to decode as text
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            f.read(1024)
        return False
        
    except:
        return True

def detect_file_type(file_path):
    """Detect file type using content-based analysis"""
    try:
        # Method 1: Use python-magic for file type detection
        if magic:
            try:
                file_type = magic.from_file(file_path, mime=True)
                if 'text/' in file_type:
                    return 'text'
                elif 'csv' in file_type:
                    return 'csv'
                elif 'json' in file_type:
                    return 'json'
                elif 'xml' in file_type:
                    return 'xml'
            except:
                pass
        
        # Method 2: Read and analyze content more comprehensively
        with open(file_path, 'rb') as f:
            sample = f.read(8192)  # Read first 8KB for better detection
            
            # Try to detect encoding if chardet is available
            encoding = None
            if chardet:
                encoding = chardet.detect(sample)['encoding']
            
            # Decode if possible to check content
            try:
                if encoding:
                    text_sample = sample.decode(encoding, errors='ignore')
                else:
                    # Try common encodings
                    for enc in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1', 'ascii']:
                        try:
                            text_sample = sample.decode(enc, errors='ignore')
                            break
                        except:
                            continue
                    else:
                        text_sample = sample.decode('utf-8', errors='ignore')
                
                text_lower = text_sample.lower()
                
                # Expanded log patterns - be more inclusive
                log_patterns = [
                    # Common log levels and terms
                    'error', 'warn', 'info', 'debug', 'trace', 'fatal',
                    'failed', 'failure', 'success', 'denied', 'allowed',
                    'login', 'logout', 'auth', 'authentication', 'session',
                    'access', 'permission', 'security', 'audit',
                    'exception', 'stack', 'traceback', 'crash',
                    'start', 'stop', 'shutdown', 'restart',
                    
                    # Timestamp patterns (very common in logs)
                    r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
                    r'\d{2}:\d{2}:\d{2}',  # HH:MM:SS
                    r'\d{2}/\d{2}/\d{4}',  # MM/DD/YYYY
                    'jan', 'feb', 'mar', 'apr', 'may', 'jun',
                    'jul', 'aug', 'sep', 'oct', 'nov', 'dec',
                    
                    # Common log file headers/patterns
                    'kernel', 'systemd', 'daemon', 'cron', 'sshd',
                    'apache', 'nginx', 'iis', 'http', 'https',
                    'tcp', 'udp', 'port', 'ip=', 'host=',
                    
                    # Common log formats
                    'level=', 'timestamp=', 'message=', 'logger=',
                    'thread=', 'process=', 'file=', 'line='
                ]
                
                # Count how many log patterns we find
                pattern_count = sum(1 for pattern in log_patterns if pattern in text_lower)
                
                # If we find multiple log patterns, it's very likely a log file
                if pattern_count >= 3:
                    return 'text'
                
                # Check for structured formats
                if text_sample.count(',') > text_sample.count('\t') and text_sample.count(',') > 5:
                    return 'csv'
                
                if text_sample.strip().startswith('{') or text_sample.strip().startswith('['):
                    return 'json'
                    
                if text_sample.strip().startswith('<?xml') or '<root>' in text_lower:
                    return 'xml'
                    
                # If it's mostly text characters and not binary, treat as text
                text_ratio = sum(1 for byte in sample if 32 <= byte <= 126 or byte in [9, 10, 13]) / len(sample)
                if text_ratio > 0.7:  # 70% printable characters
                    return 'text'
                    
            except:
                pass
        
        # Default to text if we can't determine (be permissive)
        return 'text'
        
    except Exception as e:
        st.warning(f"Could not detect file type for {file_path}: {e}")
        return 'text'  # Default to text processing

def should_process_file(file_path):
    """Determine if a file should be processed based on multiple criteria"""
    file_path = Path(file_path)
    
    # Check extension
    if file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
        return True
    
    # Check common log file names (expanded list)
    common_log_patterns = {
        'messages', 'syslog', 'auth.log', 'secure', 'kern.log', 'debug',
        'maillog', 'cron', 'daemon.log', 'user.log', 'system.log',
        'application', 'access', 'error', 'events', 'firewall',
        'audit.log', 'httpd', 'nginx', 'apache', 'iis', 'mail',
        'boot.log', 'dmesg', 'lastlog', 'wtmp', 'btmp', 'utmp'
    }
    
    if file_path.suffix == '' and file_path.name.lower() in common_log_patterns:
        return True
    
    # Check file size (increase to 1GB limit as requested)
    try:
        file_size = file_path.stat().st_size
        if file_size > 1 * 1024 * 1024 * 1024:  # 1GB limit (increased from 500MB)
            st.warning(f"⚠️ File {file_path.name} is larger than 1GB ({file_size/(1024*1024*1024):.2f}GB). This may take a long time to process.")
            # Don't return False - just warn but still process
        if file_size == 0:  # Skip empty files
            return False
    except:
        return False
    
    # Final fallback: content-based detection - be more permissive
    if not is_binary_file(file_path):
        return True
    
    # For files that pass basic binary check, use content detection
    detected_type = detect_file_type(file_path)
    return detected_type in ['text', 'csv', 'json', 'xml']

# --- UPDATED: load_config() with JSON fix ---
def load_config():
    config = {}
    if not os.path.exists(CONFIG_FILE):
        config['ollama_host'] = '127.0.0.1'
        config['ollama_port'] = '11434'
        config['model'] = 'llama3.2:3b-instruct-q4_0'
        config['embedding_model'] = 'nomic-embed-text'
        config['last_run'] = 'Never'
        config['dfir_prompt'] = DETAILED_DFIR_PROMPT
        save_config(config)
        st.info(f"Config file created at {CONFIG_FILE}")
    else:
        # Read the file
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    
                    if key == 'dfir_prompt':
                        try:
                            # Use json.loads to unescape newlines and quotes
                            config[key] = json.loads(value)
                        except json.JSONDecodeError:
                            # Fallback for old/corrupted prompt
                            config[key] = value
                    else:
                        config[key] = value
        
        # Backward compatibility for old configs
        if 'embedding_model' not in config:
            config['embedding_model'] = 'nomic-embed-text'
        if 'dfir_prompt' not in config:
            config['dfir_prompt'] = DETAILED_DFIR_PROMPT

        # --- FIX for old, un-escaped prompts ---
        if 'You are a senior DFIR' in config['dfir_prompt'] and len(config['dfir_prompt']) < 100:
            st.warning("Old config.txt format detected. Resetting prompt to default.")
            config['dfir_prompt'] = DETAILED_DFIR_PROMPT
        # --- END FIX ---

        # Re-save to add missing keys and fix prompt format
        save_config(config)
            
    return config

# --- UPDATED: save_config() with JSON fix ---
def save_config(config):
    # We must use json.dumps to escape newlines and special chars
    prompt = config.pop('dfir_prompt', DETAILED_DFIR_PROMPT)
    prompt_to_save = json.dumps(prompt)
    
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        for key, value in config.items():
            f.write(f"{key}={value}\n")
        
        # Write the escaped prompt as a single line
        f.write(f"dfir_prompt={prompt_to_save}\n")
    
    # Add the raw, unescaped prompt back for runtime
    config['dfir_prompt'] = prompt

# --- NEW: Folder Picker Helper Function ---
def select_folder():
    """Opens a Tcl/Tk file dialog to select a folder."""
    try:
        root = tk.Tk()
        root.withdraw()  # Hide the main tkinter window
        root.attributes('-topmost', True)  # Bring the dialog to the front
        folder_path = filedialog.askdirectory(master=root)
        root.destroy()
        return folder_path
    except Exception as e:
        st.error(f"Error opening folder dialog: {e}")
        return None

# --- NEW: Streaming CSV processing function with increased size limit ---
def process_csv_in_streaming_chunks(file_path, chunk_size=50000):
    """Process CSV in streaming chunks with immediate filtering - supports up to 1GB files"""
    try:
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        st.write(f"📊 Processing CSV ({file_size_mb:.1f} MB) in streaming chunks...")
        
        # Use pandas read_csv with chunksize for streaming
        security_keywords = ['login', 'error', 'access', 'failed', 'security', 
                           'audit', 'authentication', 'denied', 'warning', 'alert']
        keyword_pattern = '|'.join(security_keywords)
        
        # Adjust chunk size based on file size
        if file_size_mb > 500:  # For very large files
            chunk_size = 10000  # Smaller chunks to manage memory
        
        # Read CSV in chunks
        chunk_iterator = pd.read_csv(
            file_path,
            delimiter=',',
            quoting=3,
            encoding='utf-8',
            on_bad_lines='skip',
            engine='python',
            chunksize=chunk_size,
            low_memory=True
        )
        
        total_filtered_rows = 0
        chunk_count = 0
        all_filtered_chunks = []
        
        for chunk in chunk_iterator:
            chunk_count += 1
            initial_rows = len(chunk)
            
            # Filter chunk for security-relevant data using vectorized operations
            if not chunk.empty:
                # Combine all columns into a single string for searching
                combined_text = chunk.astype(str).agg(' '.join, axis=1)
                
                # Use vectorized string contains for speed
                mask = combined_text.str.contains(keyword_pattern, case=False, na=False)
                filtered_chunk = chunk[mask]
                
                filtered_rows = len(filtered_chunk)
                total_filtered_rows += filtered_rows
                
                if filtered_rows > 0:
                    all_filtered_chunks.append(filtered_chunk)
                
                # Progress update (less frequent for large files)
                if chunk_count % 10 == 0 or chunk_count == 1:
                    st.write(f"🔄 Processed {chunk_count:,} chunks: {total_filtered_rows:,} relevant rows found")
        
        # Combine all filtered chunks
        if all_filtered_chunks:
            final_df = pd.concat(all_filtered_chunks, ignore_index=True)
            st.write(f"✅ Processed all chunks: {total_filtered_rows:,} total relevant rows from {chunk_count:,} chunks")
            return final_df
        else:
            st.write("ℹ️ No relevant data found in streaming processing")
            return pd.DataFrame()  # Return empty DataFrame
        
    except Exception as e:
        st.error(f"❌ Error streaming CSV: {str(e)}")
        return pd.DataFrame()  # Return empty DataFrame on error

# --- NEW: Streaming chunk generator ---
def chunk_logs_streaming(df, chunk_size=3000, chunk_overlap=300):
    """Stream chunks from DataFrame without loading everything into memory at once"""
    try:
        st.write("✂️ Streaming chunks from log data...")
        
        # Process in smaller batches
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap
        )
        
        # Process DataFrame in chunks
        rows_per_batch = 5000  # Process 5,000 rows at a time
        total_rows = len(df)
        all_chunks = []
        
        for i in range(0, total_rows, rows_per_batch):
            batch_end = min(i + rows_per_batch, total_rows)
            batch_df = df.iloc[i:batch_end]
            
            # Convert batch to string
            if 'file' in batch_df.columns:
                batch_text = batch_df.drop(columns=['file'], errors='ignore').to_string(index=False)
            else:
                batch_text = batch_df.to_string(index=False)
            
            # Split this batch
            batch_chunks = text_splitter.split_text(batch_text)
            all_chunks.extend(batch_chunks)
            
            # Yield chunks as they're available
            for chunk in batch_chunks:
                yield chunk
            
            # Update progress
            progress = min(100, int((batch_end / total_rows) * 100))
            if progress % 20 == 0:  # Update every 20% to avoid too many messages
                st.write(f"📊 Chunking progress: {progress}% ({batch_end:,}/{total_rows:,} rows)")
        
        st.write(f"✅ Created {len(all_chunks)} total chunks for analysis")
        
    except Exception as e:
        st.error(f"❌ Error streaming chunks: {str(e)}")
        yield from []

# --- NEW: Function to determine optimal batch size ---
def determine_optimal_batch_size(gpu_info, document_size_estimate=1000):
    """Determine optimal batch size based on GPU memory and document size"""
    try:
        import torch
        
        if gpu_info and gpu_info.get("available", False):
            vram_gb = gpu_info.get("vram_gb", 0)
            
            # Estimate memory per document (rough approximation)
            # Each embedding dimension typically 768-1024 floats (4 bytes each)
            embedding_dim = 1024  # Conservative estimate
            bytes_per_embedding = embedding_dim * 4  # 4 bytes per float32
            
            # Documents have text too, estimate 2x for overhead
            estimated_bytes_per_doc = bytes_per_embedding * 2
            
            # Conservative memory calculation: leave 2GB for system/other
            available_vram_bytes = (vram_gb - 2) * 1024**3 if vram_gb > 4 else vram_gb * 1024**3 * 0.5
            
            # Calculate max batch size
            max_batch_size = int(available_vram_bytes / estimated_bytes_per_doc)
            
            # Apply reasonable limits
            if vram_gb >= 16:
                optimal_batch = min(max_batch_size, 500)  # Up to 500 for large GPUs
            elif vram_gb >= 8:
                optimal_batch = min(max_batch_size, 250)  # Up to 250 for mid-range GPUs
            elif vram_gb >= 4:
                optimal_batch = min(max_batch_size, 100)  # Up to 100 for smaller GPUs
            else:
                optimal_batch = 50  # Conservative for low VRAM
            
            return optimal_batch
        
    except Exception as e:
        st.warning(f"⚠️ Could not determine optimal batch size: {e}")
    
    # Default batch sizes based on common scenarios
    return 200  # Increased default from 10

# --- NEW: GPU monitoring function ---
def monitor_gpu_utilization():
    """Monitor GPU utilization and memory usage"""
    try:
        import torch
        if torch.cuda.is_available():
            # Get current GPU stats
            device = torch.cuda.current_device()
            memory_allocated = torch.cuda.memory_allocated(device) / 1024**3
            memory_reserved = torch.cuda.memory_reserved(device) / 1024**3
            utilization = torch.cuda.utilization(device) if hasattr(torch.cuda, 'utilization') else 0
            
            # Get more detailed stats if pynvml is available
            try:
                pynvml.nvmlInit()
                handle = pynvml.nvmlDeviceGetHandleByIndex(device)
                utilization = pynvml.nvmlDeviceGetUtilizationRates(handle).gpu
                temperature = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
                pynvml.nvmlShutdown()
                
                return {
                    'memory_allocated_gb': memory_allocated,
                    'memory_reserved_gb': memory_reserved,
                    'utilization_percent': utilization,
                    'temperature_c': temperature,
                    'device_name': torch.cuda.get_device_name(device)
                }
            except:
                return {
                    'memory_allocated_gb': memory_allocated,
                    'memory_reserved_gb': memory_reserved,
                    'utilization_percent': utilization,
                    'device_name': torch.cuda.get_device_name(device)
                }
    except:
        pass
    
    return None

# --- NEW: Incremental vector store builder with GPU optimization ---
def build_vector_store_incrementally(chunks_generator, config, ollama_url, status_callback=None, batch_size=100):
    """Build vector store incrementally with resource limits to prevent file descriptor exhaustion"""
    persist_directory = tempfile.mkdtemp()
    st.write(f"🔧 Using temporary vector store directory: {Path(persist_directory).name}")
    
    chroma_client = None
    collection = None
    embeddings = None
    
    try:
        st.write(f"🔧 Building vector store incrementally (batch size: {batch_size})...")
        
        # Initialize embeddings
        embeddings = OllamaEmbeddings(
            model=config['embedding_model'],
            base_url=ollama_url
        )
        
        # Test embedding with a small sample
        _ = embeddings.embed_query("Test embedding")
        
        # Create Chroma client with explicit settings
        chroma_client = chromadb.PersistentClient(
            path=persist_directory,
            settings=chromadb.Settings(
                allow_reset=True,
                anonymized_telemetry=False,
                is_persistent=True,
            )
        )
        
        # Initialize collection with optimized settings
        collection_name = "log_analysis_streaming"
        try:
            # Try to delete existing collection first
            try:
                chroma_client.delete_collection(collection_name)
            except:
                pass
            
            collection = chroma_client.create_collection(
                name=collection_name,
                metadata={
                    "hnsw:space": "cosine",
                    "hnsw:construction_ef": 128,
                    "hnsw:M": 16,
                }
            )
        except Exception as e:
            st.warning(f"⚠️ Could not create collection: {e}")
            collection = chroma_client.get_collection(collection_name)
        
        chunk_counter = 0
        total_docs = 0
        all_docs = []
        all_texts = []
        
        # Monitor timing and resource usage
        import time
        start_time = time.time()
        batch_times = []
        
        # REMOVED: No more max_chunks limit! We process everything.
        processed_chunks = 0
        
        # Process chunks as they come
        for chunk_text in chunks_generator:
            if not chunk_text:
                continue
                
            # Safety check - keep track but don't limit
            processed_chunks += 1
            
            # Add document to list for batch processing
            all_docs.append(Document(page_content=chunk_text))
            all_texts.append(chunk_text)
            
            # Process in batches to improve GPU utilization and manage resources
            if len(all_docs) >= batch_size:
                batch_start = time.time()
                
                try:
                    # Get embeddings for the entire batch at once
                    batch_embeddings = embeddings.embed_documents(all_texts)
                    
                    # Add to collection in a single operation
                    batch_ids = [f"doc_{chunk_counter}_{i}" for i in range(len(all_docs))]
                    collection.add(
                        documents=all_texts,
                        embeddings=batch_embeddings,
                        ids=batch_ids
                    )
                    
                    total_docs += len(all_docs)
                    chunk_counter += 1
                    
                    # Calculate batch processing time
                    batch_time = time.time() - batch_start
                    batch_times.append(batch_time)
                    avg_batch_time = sum(batch_times) / len(batch_times) if batch_times else batch_time
                    
                    docs_per_second = len(all_docs) / batch_time if batch_time > 0 else 0
                    
                    st.write(f"📚 Batch {chunk_counter}: Added {len(all_docs)} documents "
                            f"({docs_per_second:.1f} docs/sec, avg: {avg_batch_time:.2f}s per batch) "
                            f"[Total: {total_docs}, Processed: {processed_chunks}]")
                    
                    # Call status callback if provided
                    if status_callback:
                        status_callback({
                            'progress': min(100, int((chunk_counter * batch_size) / max(1, chunk_counter * batch_size) * 100)),
                            'total_docs': total_docs,
                            'batch_size': len(all_docs),
                            'docs_per_second': docs_per_second,
                            'status': 'building'
                        })
                    
                    # Clear batch and free memory
                    all_docs.clear()
                    all_texts.clear()
                    
                    # Periodically close and reopen connection to free file descriptors
                    if chunk_counter % 10 == 0:
                        try:
                            # Force garbage collection
                            gc.collect()
                            # Small delay to allow system to clean up
                            time.sleep(0.1)
                        except:
                            pass
                    
                except Exception as batch_error:
                    st.error(f"❌ Error in batch {chunk_counter}: {batch_error}")
                    # Clear failed batch to continue
                    all_docs.clear()
                    all_texts.clear()
                    continue
        
        # Process any remaining documents
        if all_docs:
            batch_start = time.time()
            try:
                batch_embeddings = embeddings.embed_documents(all_texts)
                batch_ids = [f"doc_{chunk_counter}_{i}" for i in range(len(all_docs))]
                
                collection.add(
                    documents=all_texts,
                    embeddings=batch_embeddings,
                    ids=batch_ids
                )
                
                total_docs += len(all_docs)
                chunk_counter += 1
                
                batch_time = time.time() - batch_start
                docs_per_second = len(all_docs) / batch_time if batch_time > 0 else 0
                
                st.write(f"📚 Final batch: Added {len(all_docs)} documents "
                        f"({docs_per_second:.1f} docs/sec) [Total: {total_docs}, Processed: {processed_chunks}]")
            except Exception as final_batch_error:
                st.error(f"❌ Error in final batch: {final_batch_error}")
        
        total_time = time.time() - start_time
        overall_docs_per_second = total_docs / total_time if total_time > 0 else 0
        
        st.write(f"✅ Vector store complete: {total_docs} documents in {total_time:.1f}s "
                f"({overall_docs_per_second:.1f} docs/sec overall)")
        
        # Create the LangChain vectorstore wrapper
        vectorstore = Chroma(
            client=chroma_client,
            collection_name=collection_name,
            embedding_function=embeddings
        )
        
        if status_callback:
            status_callback({
                'progress': 100,
                'total_docs': total_docs,
                'vectorstore': vectorstore,
                'persist_dir': persist_directory,
                'overall_docs_per_second': overall_docs_per_second,
                'status': 'complete'
            })
        
        return {
            'progress': 100,
            'total_docs': total_docs,
            'vectorstore': vectorstore,
            'persist_dir': persist_directory,
            'overall_docs_per_second': overall_docs_per_second,
            'status': 'complete'
        }
        
    except Exception as e:
        st.error(f"❌ Error building incremental vector store: {str(e)}")
        
        # Clean up resources
        try:
            if collection:
                collection = None
            if chroma_client:
                chroma_client = None
            if embeddings:
                embeddings = None
        except:
            pass
        
        # Force garbage collection
        gc.collect()
        
        # Clean up directory
        if os.path.exists(persist_directory):
            try:
                # Wait before cleanup
                time.sleep(1)
                shutil.rmtree(persist_directory, ignore_errors=True)
            except:
                pass
        
        return {'status': 'error', 'error': str(e)}

# --- FIX 2: Enhanced cleanup function for ChromaDB files ---
def safe_chromadb_cleanup(vectorstore, persist_dir):
    """Safely cleanup ChromaDB resources and files"""
    try:
        # First try to properly close the vectorstore
        if vectorstore:
            try:
                # Try to close client connection if it exists
                if hasattr(vectorstore, '_client') and vectorstore._client:
                    try:
                        vectorstore._client.heartbeat()  # Test connection
                    except:
                        pass
                    vectorstore._client = None
                
                # Clear collection reference
                if hasattr(vectorstore, '_collection'):
                    vectorstore._collection = None
                
                # Clear embedding function
                if hasattr(vectorstore, '_embedding_function'):
                    vectorstore._embedding_function = None
                    
            except Exception as e:
                st.warning(f"⚠️ Could not properly close vectorstore: {e}")
        
        # Force garbage collection
        gc.collect()
        
        # Small delay to allow system to release resources
        time.sleep(0.5)
        
        # Now try to delete the directory
        if persist_dir and os.path.exists(persist_dir):
            # Function to force remove directory
            def remove_readonly(func, path, _):
                """Remove readonly attribute on Windows"""
                try:
                    os.chmod(path, 0o666)  # Make writable
                    func(path)
                except:
                    pass
            
            # Multiple attempts to delete
            for attempt in range(3):
                try:
                    shutil.rmtree(persist_dir, onerror=remove_readonly, ignore_errors=True)
                    if not os.path.exists(persist_dir):
                        return True
                    else:
                        time.sleep(0.5)  # Wait and retry
                except Exception as e:
                    if attempt == 2:
                        st.warning(f"⚠️ Could not delete directory after 3 attempts: {e}")
                    time.sleep(0.5)
        
        return True
        
    except Exception as e:
        st.warning(f"⚠️ Error during cleanup: {e}")
        return False

def increase_file_descriptor_limit():
    """Try to increase the file descriptor limit for the current process"""
    try:
        import resource
        # Get current limits
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        st.write(f"📁 Current file descriptor limits: Soft={soft}, Hard={hard}")
        
        # Try to increase the soft limit
        if hard > soft:
            try:
                # Try to increase to the hard limit
                new_soft = min(hard, 10000)  # Don't exceed hard limit, max 10000
                resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
                st.success(f"✅ Increased file descriptor limit to: Soft={new_soft}, Hard={hard}")
                return True
            except (ValueError, resource.error) as e:
                st.warning(f"⚠️ Could not increase file descriptor limit: {e}")
        
        # Check if current limit is reasonable
        if soft < 2048:
            st.warning(f"⚠️ Low file descriptor limit ({soft}). May encounter 'Too many open files' errors.")
            st.info("💡 To permanently increase limit, run: `ulimit -n 10000`")
            return False
        
        return True
        
    except ImportError:
        # resource module not available on Windows
        st.info("ℹ️ File descriptor limits not adjustable on this system")
        return True
    except Exception as e:
        st.warning(f"⚠️ Could not check file descriptor limits: {e}")
        return True

def get_available_models(ollama_url):
    """Get available models from Ollama API"""
    try:
        response = requests.get(f"{ollama_url}/api/tags", timeout=10)
        if response.status_code == 200:
            models_data = response.json()
            return [model['name'] for model in models_data.get('models', [])]
        return []
    except Exception as e:
        st.warning(f"Could not fetch available models from API: {e}")
        return get_available_models_fallback(ollama_url)

def get_available_models_fallback(ollama_url):
    """Fallback method using ollama list command"""
    try:
        result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            models = []
            lines = result.stdout.strip().split('\n')[1:]
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if parts:
                        models.append(parts[0])
            return models
        return []
    except Exception as e:
        st.error(f"Could not get models from ollama list: {e}")
        return []

def classify_model(model_name):
    """Classify a model into categories"""
    model_lower = model_name.lower()
    
    # Don't classify embedding models
    if "embed" in model_lower:
        return "embedding"

    for category, info in MODEL_CATEGORIES.items():
        for pattern in info["models"]:
            if pattern in model_lower:
                return category
    
    if any(size in model_lower for size in ['1.1b', '1b', '0.5b', '500m']):
        return "very_fast"
    elif any(size in model_lower for size in ['2.7b', '2b', '3b']):
        return "fast"
    elif any(size in model_lower for size in ['7b', '8b', '9b']):
        return "balanced"
    else:
        return "quality"

def get_recommended_models(available_models):
    """Get recommended models sorted by category priority"""
    recommended = {category: [] for category in MODEL_CATEGORIES.keys()}
    
    for model in available_models:
        category = classify_model(model)
        if category in recommended: # Only add models that are not 'embedding' etc.
            recommended[category].append(model)
    
    for category in recommended:
        recommended[category].sort()
    
    return recommended

def create_model_display_name(model_name):
    """Create a user-friendly display name for models"""
    category = classify_model(model_name)
    emoji = {
        "gpu_optimized": "⚡",
        "very_fast": "🚀",
        "fast": "⚡",
        "balanced": "🎯",
        "quality": "🏆",
        "detailed_analysis": "📊"
    }.get(category, "🔹")
    
    category_desc = MODEL_CATEGORIES.get(category, {}).get("description", category.title())
    return f"{emoji} {model_name} ({category_desc})"

def get_hardware_recommendation():
    """Get model recommendation based on available memory"""
    try:
        import psutil
        total_memory_gb = psutil.virtual_memory().total / (1024**3)
        
        if total_memory_gb <= 4:
            return "tinyllama:1.1b-chat", "4GB or less RAM - Use TinyLlama for best performance"
        elif total_memory_gb <= 8:
            return "llama3.2:1b-instruct", "4-8GB RAM - Good balance of speed and capability"
        elif total_memory_gb <= 16:
            return "phi:2.7b", "8-16GB RAM - Better quality with good speed"
        else:
            return "llama3.2:3b-instruct", "16GB+ RAM - Optimal balance"
    except:
        return "llama3.2:3b-instruct", "Unknown hardware - Defaulting to balanced choice"

def detect_gpu():
    """Detect if GPU is available and its capabilities"""
    try:
        import torch
        if torch.cuda.is_available():
            gpu_name = torch.cuda.get_device_name(0)
            vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024**3)
            recommended_model = "llama3.2:3b-instruct-q4_0"  # Default GPU recommendation
            return {
                "available": True,
                "name": gpu_name,
                "vram_gb": vram_gb,
                "recommended_model": recommended_model
            }
        else:
            return {"available": False, "name": "None", "vram_gb": 0, "recommended_model": "llama3.2:3b-instruct-q4_0"}
    except ImportError:
        return {"available": False, "name": "PyTorch not installed", "vram_gb": 0, "recommended_model": "llama3.2:3b-instruct-q4_0"}
    except Exception as e:
        return {"available": False, "name": f"Error: {str(e)}", "vram_gb": 0, "recommended_model": "llama3.2:3b-instruct-q4_0"}

def get_gpu_recommendation():
    """Get GPU-optimized model recommendations"""
    try:
        import torch
        if torch.cuda.is_available():
            gpu_name = torch.cuda.get_device_name(0)
            vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024**3)
            
            if vram_gb <= 4:
                return "llama3.2:1b-instruct-q4_0", f"4GB VRAM - Fastest on {gpu_name}"
            elif vram_gb <= 8:
                return "llama3.2:3b-instruct-q4_0", f"4-8GB VRAM - Optimal on {gpu_name}"
            else:
                return "phi3:mini-instruct-q4_0", f"8GB+ VRAM - Quality+Speed on {gpu_name}"
        else:
            return "llama3.2:3b-instruct-q4_0", "CPU fallback - Still fast"
    except:
        return "llama3.2:3b-instruct-q4_0", "GPU detection failed - Using fast default"

# --- UPDATED: refresh_ollama_connection with enhanced parameters for longer responses ---
def refresh_ollama_connection(config):
    """Refresh Ollama connection with enhanced parameters for longer responses"""
    ollama_url = f"http://{config['ollama_host']}:{config['ollama_port']}"
    try:
        available_models = get_available_models(ollama_url)
        recommended_models = get_recommended_models(available_models)
        
        # ENHANCED LLM with parameters for detailed responses
        llm = OllamaLLM(
            model=config['model'],
            base_url=ollama_url,
            temperature=0.7,  # Increased for more creative/detailed responses
            top_p=0.9,        # Nucleus sampling for diversity
            num_predict=16384,  # DOUBLED from 8192: Maximum tokens to generate
            repeat_penalty=1.1,  # Penalize repetition
            num_ctx=16384,    # DOUBLED context window size
            top_k=40,         # Consider more tokens for variety
            mirostat=2,       # Enable mirostat for better coherence in long responses
            mirostat_tau=5.0, # Target perplexity
            mirostat_eta=0.1, # Learning rate
            # streaming=True   # Optional: for streaming responses
        )
        
        return {
            "success": True,
            "available_models": available_models,
            "recommended_models": recommended_models,
            "llm": llm,
            "ollama_url": ollama_url
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "available_models": [],
            "recommended_models": {category: [] for category in MODEL_CATEGORIES.keys()},
            "llm": None,
            "ollama_url": ollama_url
        }

# --- UPDATED: Enhanced discover_log_files function ---
def discover_log_files(folder_path):
    """Recursively discover all log files in folder and subdirectories"""
    log_files = []
    total_size = 0
    processed_files = 0
    skipped_files = 0
    
    try:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = Path(root) / file
                
                # Skip files that are too large or shouldn't be processed
                if not should_process_file(file_path):
                    skipped_files += 1
                    continue
                
                try:
                    file_size = file_path.stat().st_size
                    
                    # Determine file type for processing
                    file_ext = file_path.suffix.lower()
                    if file_ext not in SUPPORTED_EXTENSIONS and file_ext != '':
                        # Use content detection for unknown extensions
                        detected_type = detect_file_type(file_path)
                        if detected_type == 'text':
                            file_ext = '.log'  # Treat as log file
                        elif detected_type == 'csv':
                            file_ext = '.csv'
                        elif detected_type == 'json':
                            file_ext = '.json'
                        elif detected_type == 'xml':
                            file_ext = '.xml'
                        else:
                            file_ext = '.log'  # Default to log
                    
                    log_files.append({
                        'path': str(file_path),
                        'name': file,
                        'extension': file_ext,
                        'size': file_size,
                        'relative_path': str(file_path.relative_to(folder_path)),
                        'detected_type': detect_file_type(file_path) if file_ext not in SUPPORTED_EXTENSIONS else 'known'
                    })
                    total_size += file_size
                    processed_files += 1
                    
                except Exception as e:
                    st.warning(f"Could not process file {file_path.name}: {e}")
                    skipped_files += 1
                    continue
        
        log_files.sort(key=lambda x: x['size'])
        
        # Log discovery statistics
        if processed_files > 0 or skipped_files > 0:
            st.info(f"📊 File Discovery: {processed_files} files queued, {skipped_files} files skipped")
        
        return log_files, total_size
        
    except Exception as e:
        st.error(f"Error discovering log files: {e}")
        return [], 0

def process_text_file(file_path):
    """Process generic text files for log content"""
    try:
        # Read file in chunks for large files (supports up to 1GB)
        log_lines = []
        batch_size = 10000
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            batch = []
            for i, line in enumerate(f):
                if any(pattern in line.lower() for pattern in ['error', 'warn', 'info', 'debug', 'exception', 'failed', 'login', 'access']):
                    batch.append(line.strip())
                
                if len(batch) >= batch_size:
                    log_lines.extend(batch)
                    batch = []
            
            if batch:
                log_lines.extend(batch)
        
        if log_lines:
            df = pd.DataFrame({
                'timestamp': [datetime.datetime.now().strftime("%Y-%m-d %H:%M:%S")] * len(log_lines),
                'message': log_lines,
                'file': [os.path.basename(file_path)] * len(log_lines)
            })
            return df
        else:
            return None
            
    except Exception as e:
        st.warning(f"Could not process text file {Path(file_path).name}: {e}")
        return None

def process_json_file(file_path):
    """Process JSON log files"""
    try:
        # Try to read JSON in chunks if it's a JSONL file
        lines = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            lines.append(data)
                        except json.JSONDecodeError:
                            # Skip invalid JSON lines
                            continue
        except:
            # Fallback to reading entire file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
                if isinstance(data, list):
                    lines = data
                else:
                    lines = [data]
        
        if lines:
            df = pd.DataFrame(lines)
            if not df.empty:
                # Filter for security-relevant data
                df = df[df.apply(lambda row: row.astype(str).str.contains(
                    'login|error|access|failed|security|audit|authentication|denied|warning|alert', 
                    case=False, na=False).any(), axis=1)]
                if not df.empty:
                    df['file'] = os.path.basename(file_path)
                    return df
        
        return None
        
    except Exception as e:
        st.warning(f"Could not process JSON file {Path(file_path).name}: {e}")
        return None

# --- UPDATED: Enhanced ingest_logs function with streaming ---
def ingest_logs(file_path, file_type=None, use_streaming=True):
    try:
        if file_type is None:
            file_type = Path(file_path).suffix.lower()
        
        file_name = os.path.basename(file_path)
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        
        # Handle files without extensions or unknown extensions
        if file_type == '' or file_type not in SUPPORTED_EXTENSIONS:
            st.write(f"🔍 Detecting file type for: {file_name}")
            detected_type = detect_file_type(file_path)
            
            if detected_type == 'csv':
                file_type = '.csv'
                st.write("📊 Detected as CSV file")
            elif detected_type == 'json':
                file_type = '.json'
                st.write("📋 Detected as JSON file")
            elif detected_type == 'xml':
                file_type = '.xml'
                st.write("📄 Detected as XML file")
            else:
                file_type = '.log'  # Default to text log processing
                st.write("📝 Detected as text log file")
        
        st.write(f"📄 Processing as {SUPPORTED_EXTENSIONS.get(file_type, 'Text File')} ({file_size_mb:.1f} MB)...")
        
        # Use streaming for large files (> 10MB) or when explicitly requested
        if file_size_mb > 10 and use_streaming and file_type == '.csv':
            st.write("📊 Using streaming CSV processing for large file...")
            
            # Get first chunk to return something immediately
            for df_chunk in process_csv_in_streaming_chunks(file_path):
                if not df_chunk.empty:
                    st.write(f"✅ First chunk ready with {len(df_chunk):,} rows")
                    return df_chunk
            
            st.write("ℹ️ No relevant data found in streaming processing")
            return None
        
        elif file_type == '.csv':
            st.write("📊 Processing CSV file...")
            
            if file_size_mb > 50 and use_streaming:
                st.write("📊 Using streaming CSV processing...")
                all_chunks = []
                total_rows = 0
                
                for df_chunk in process_csv_in_streaming_chunks(file_path):
                    if not df_chunk.empty:
                        all_chunks.append(df_chunk)
                        total_rows += len(df_chunk)
                        st.write(f"🔄 Processed chunk with {len(df_chunk):,} rows (Total: {total_rows:,})")
                
                if all_chunks:
                    df = pd.concat(all_chunks, ignore_index=True)
                    st.write(f"✅ Combined {len(all_chunks)} chunks into {len(df):,} total rows")
                    return df
                else:
                    st.write("ℹ️ No security-relevant data found")
                    return None
            else:
                # For smaller files
                df = pd.read_csv(
                    file_path,
                    delimiter=',',
                    quoting=3,
                    encoding='utf-8',
                    on_bad_lines='skip',
                    engine='python',
                    low_memory=True
                )
                
                st.write(f"📈 Loaded {len(df):,} rows from CSV")
                
                if not df.empty:
                    security_keywords = 'login|error|access|failed|security|audit|authentication|denied|warning|alert'
                    combined_text = df.astype(str).agg(' '.join, axis=1)
                    df = df[combined_text.str.contains(security_keywords, case=False, na=False)]
                    st.write(f"✅ Filtered to {len(df):,} security-relevant rows")
                    return df
                else:
                    return None
        
        elif file_type == '.evtx':
            if PyEvtxParser is None:
                raise ValueError(".evtx support is disabled. Please install: pip install python-evtx")
            
            st.write("🪵 Processing EVTX file...")
            parser = PyEvtxParser(file_path)
            events = []
            
            records = list(parser.records())
            record_count = len(records)
            
            st.write(f"📋 Found {record_count} event records in EVTX file")
            
            security_event_ids = [
                4624, 4625, 4648, 4672, 4720, 4722, 4723, 4724, 4725, 4726,
                4732, 4733, 4738, 4740, 4756, 4768, 4776, 4611, 4649, 4657
            ]
            
            for i, record in enumerate(records):
                event_data = record.get('Event', {})
                system_data = event_data.get('System', {})
                event_id = system_data.get('EventID', '')
                
                if event_id in security_event_ids:
                    events.append({
                        'timestamp': system_data.get('TimeCreated', {}).get('SystemTime', ''),
                        'host': system_data.get('Computer', ''),
                        'event_id': event_id,
                        'event_data': str(event_data.get('EventData', {})),
                        'message': f"EventID {event_id}: {event_data.get('EventData', {})}",
                        'file': file_name
                    })
            
            df = pd.DataFrame(events)
            st.write(f"✅ Extracted {len(df)} security-related Windows events")
            return df
            
        elif file_type == '.json':
            df = process_json_file(file_path)
            if df is not None:
                st.write(f"✅ Processed JSON file with {len(df)} security-relevant entries")
            else:
                st.write("ℹ️ No security-relevant data found in JSON file")
            return df
                
        elif file_type in ['.log', '.txt', '.syslog', '']:
            df = process_text_file(file_path)
            if df is not None:
                st.write(f"✅ Processed text file with {len(df)} security-relevant lines")
            else:
                st.write("ℹ️ No security-relevant data found in text file")
            return df
                
        elif file_type == '.xml':
            df = process_text_file(file_path)
            if df is not None:
                st.write(f"✅ Processed XML file with {len(df)} security-relevant entries")
            else:
                st.write("ℹ️ No security-relevant data found in XML file")
            return df
                
        else:
            st.warning(f"Unsupported file type: {file_type}")
            return None
        
    except Exception as e:
        st.error(f"❌ Error reading log file {file_name}: {str(e)}")
        return None

# --- NEW: Optimized chunk_logs function ---
def chunk_logs(df, use_streaming=True):
    try:
        if use_streaming and len(df) > 10000:
            st.write("✂️ Using streaming chunk generation...")
            chunks_generator = chunk_logs_streaming(df)
            chunks = list(chunks_generator)
        else:
            st.write("✂️ Chunking log data...")
            
            if 'file' in df.columns:
                df_to_string = df.drop(columns=['file'], errors='ignore')
            else:
                df_to_string = df
            
            text = df_to_string.to_string(index=False)
            
            data_size = len(text)
            if data_size > 1000000:
                chunk_size = 3000
                chunk_overlap = 300
            else:
                chunk_size = 2000
                chunk_overlap = 200
                
            st.write(f"📏 Data size: {data_size} characters, using chunk size: {chunk_size}")
            
            splitter = RecursiveCharacterTextSplitter(
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap
            )
            chunks = splitter.split_text(text)
        
        st.write(f"✅ Created {len(chunks)} chunks for analysis")
        return chunks
    except Exception as e:
        st.error(f"❌ Error chunking logs: {str(e)}")
        return []

# --- UPDATED: build_vector_store with better cleanup integration ---
def build_vector_store(chunks, config, ollama_url, use_streaming=True):
    """Build vector store with better file descriptor management"""
    persist_directory = tempfile.mkdtemp()
    st.write(f"🔧 Using temporary vector store directory: {Path(persist_directory).name}")
    
    vectorstore = None
    
    try:
        st.write("🔧 Building vector store...")
        
        if use_streaming and len(chunks) > 50:
            st.write("🌍 Using incremental vector store building...")
            
            # Determine optimal batch size based on GPU
            optimal_batch_size = determine_optimal_batch_size(st.session_state.gpu_info)
            
            # Create a generator from chunks
            def chunks_generator():
                for i, chunk in enumerate(chunks):
                    yield chunk
                    if i % 100 == 0 and i > 0:  # Update less frequently for better performance
                        st.write(f"📚 Generated {i+1}/{len(chunks)} chunks")
            
            # Build incrementally with optimized batch size
            result = build_vector_store_incrementally(
                chunks_generator(), 
                config, 
                ollama_url,
                batch_size=optimal_batch_size
            )
            
            if result['status'] == 'complete':
                return result['vectorstore'], result['persist_dir']
            else:
                raise Exception(f"Vector store build failed: {result.get('error')}")
        
        else:
            # Original non-streaming approach for small files
            embeddings = OllamaEmbeddings(
                model=config['embedding_model'],
                base_url=ollama_url
            )
            
            # Test embedding with timeout
            try:
                _ = embeddings.embed_query("Test embedding")
            except Exception as e:
                st.error(f"❌ Error testing embeddings: {e}")
                raise
            
            docs = [Document(page_content=chunk) for chunk in chunks]
            st.write(f"📚 Creating embeddings for {len(docs)} documents...")
            
            try:
                # For non-streaming, use larger batch size if we have GPU
                if st.session_state.gpu_info and st.session_state.gpu_info.get("available", False):
                    # Process in larger batches even for non-streaming
                    vectorstore = Chroma.from_documents(
                        docs,
                        embeddings,
                        collection_name="log_analysis",
                        persist_directory=persist_directory,
                        collection_metadata={"hnsw:batch_size": "100"}  # Suggest larger batches
                    )
                else:
                    vectorstore = Chroma.from_documents(
                        docs,
                        embeddings,
                        collection_name="log_analysis",
                        persist_directory=persist_directory
                    )
                
                st.write("✅ Vector store created successfully!")
                return vectorstore, persist_directory
                
            except Exception as e:
                st.error(f"❌ Error creating ChromaDB from documents: {str(e)}")
                raise
            
    except Exception as e:
        st.error(f"❌ Error initializing ChromaDB vector store: {str(e)}")
        
        # Use enhanced cleanup
        safe_chromadb_cleanup(vectorstore, persist_directory)
        
        return None, None

# --- NEW: Process chunks in batches (replaces truncation) ---
def process_chunks_in_batches(chunks, config, ollama_url, batch_size=None):
    """
    Process chunks in optimized batches to avoid memory issues
    Returns a generator that yields processed batches
    """
    if not batch_size:
        # Determine optimal batch size based on available memory
        if st.session_state.gpu_info and st.session_state.gpu_info.get("available", False):
            vram_gb = st.session_state.gpu_info['vram_gb']
            if vram_gb >= 16:
                batch_size = 200
            elif vram_gb >= 8:
                batch_size = 100
            elif vram_gb >= 4:
                batch_size = 50
            else:
                batch_size = 25
        else:
            # CPU mode - smaller batches
            batch_size = 50
    
    total_chunks = len(chunks)
    st.write(f"📊 Processing {total_chunks:,} chunks in batches of {batch_size}...")
    
    for i in range(0, total_chunks, batch_size):
        batch_end = min(i + batch_size, total_chunks)
        current_batch = chunks[i:batch_end]
        
        yield {
            'batch_number': (i // batch_size) + 1,
            'total_batches': (total_chunks + batch_size - 1) // batch_size,
            'chunks': current_batch,
            'start_index': i,
            'end_index': batch_end - 1,
            'progress_percent': min(100, int((batch_end / total_chunks) * 100))
        }

# --- NEW: Batch vector store building functions ---
def build_vector_store_batch(chunks, config, ollama_url, is_first_batch=True, persist_directory=None):
    """Build or add to vector store in batches"""
    try:
        if is_first_batch or persist_directory is None:
            # Create new vector store
            persist_directory = tempfile.mkdtemp()
            st.write(f"🔧 Creating vector store at: {Path(persist_directory).name}")
            
            embeddings = OllamaEmbeddings(
                model=config['embedding_model'],
                base_url=ollama_url
            )
            
            # Test embedding
            _ = embeddings.embed_query("Test embedding")
            
            docs = [Document(page_content=chunk) for chunk in chunks]
            
            vectorstore = Chroma.from_documents(
                docs,
                embeddings,
                collection_name="log_analysis_batch",
                persist_directory=persist_directory,
                collection_metadata={"hnsw:space": "cosine"}
            )
            
            return vectorstore, persist_directory
            
        else:
            # This shouldn't be called for first batch
            raise ValueError("build_vector_store_batch called for non-first batch")
            
    except Exception as e:
        st.error(f"❌ Error building initial vector store batch: {str(e)}")
        return None, None

def add_to_vector_store_batch(vectorstore, chunks, config, ollama_url, batch_number=1):
    """Add chunks to existing vector store"""
    try:
        if not vectorstore or not chunks:
            return False
        
        # Get embeddings for this batch
        embeddings = OllamaEmbeddings(
            model=config['embedding_model'],
            base_url=ollama_url
        )
        
        # Create documents
        docs = [Document(page_content=chunk) for chunk in chunks]
        
        # Get embeddings for all documents in batch
        batch_embeddings = embeddings.embed_documents([doc.page_content for doc in docs])
        
        # Generate unique IDs for this batch
        start_id = (batch_number - 1) * len(chunks)
        batch_ids = [f"doc_{start_id + i}" for i in range(len(docs))]
        
        # Add to collection
        vectorstore._collection.add(
            documents=[doc.page_content for doc in docs],
            embeddings=batch_embeddings,
            ids=batch_ids
        )
        
        st.write(f"✅ Added batch {batch_number} with {len(chunks)} documents")
        return True
        
    except Exception as e:
        st.error(f"❌ Error adding batch {batch_number} to vector store: {str(e)}")
        return False

# --- UPDATED: Analyze large datasets with enhanced retrieval for more context ---
def analyze_large_dataset(vectorstore, llm, user_prompt_template, max_docs_per_query=50):  # Increased from 20
    """Analyze large datasets with enhanced retrieval for more context"""
    try:
        if vectorstore is None:
            return None
       
        st.write("🤖 Starting comprehensive AI analysis with enhanced context...")
       
        # Validate prompt
        if "{context}" not in user_prompt_template or "{question}" not in user_prompt_template:
            raise ValueError("Prompt template must include {context} and {question} placeholders.")
       
        # Create enhanced retriever with more documents
        try:
            retriever = vectorstore.as_retriever(
                search_kwargs={"k": min(max_docs_per_query, 100)}   # or 50–75 if context gets too big
            )
        except Exception as e:
            st.warning(f"⚠️ Retriever creation issue: {e}. Using enhanced retriever.")
            retriever = vectorstore.as_retriever(
                search_kwargs={"k": min(max_docs_per_query, 75)}  # Increased
            )
       
        # Get MORE relevant documents for comprehensive analysis
        relevant_docs = retriever.invoke(
            "Analyze these logs COMPREHENSIVELY for ALL security incidents, anomalies, indicators of compromise, threats, risks, suspicious activities, errors, warnings, authentication events, network activities, and system changes. " +
            "Look for EVERYTHING relevant to security including: malicious activity, unauthorized access, data exfiltration, " +
            "privilege escalation, lateral movement, command and control communications, persistence mechanisms, " +
            "data theft, ransomware indicators, brute force attacks, vulnerability exploitation, configuration changes, " +
            "account modifications, service installations, scheduled tasks, registry changes, file modifications, " +
            "network connections, DNS queries, firewall events, antivirus alerts, and any abnormal system behavior."
        )
       
        if not relevant_docs:
            return "## No Relevant Security Data Found\n\nAfter thorough analysis of the provided log data, no clear indicators of compromise or malicious activity were detected."
       
        # ENHANCED: Process in larger sections for more comprehensive analysis
        if len(relevant_docs) > 20:
            st.write(f"📊 Found {len(relevant_docs)} relevant documents. Processing in comprehensive sections...")
           
            # Split into larger sections for better context
            sections = []
            section_size = 25  # Increased from 15 for more context per section
           
            for i in range(0, len(relevant_docs), section_size):
                section_docs = relevant_docs[i:i + section_size]
                section_text = "\n\n" + "="*60 + f"\nSECTION {i//section_size + 1} ({len(section_docs)} DOCUMENTS)\n" + "="*60 + "\n\n"
                section_text += "\n\n" + "-"*40 + " LOG CHUNK " + "-"*40 + "\n\n".join([doc.page_content for doc in section_docs])
                sections.append(section_text)
           
            # Analyze each section with a MORE detailed prompt
            section_reports = []
            for idx, section in enumerate(sections):
                st.write(f"📋 Analyzing section {idx + 1}/{len(sections)} comprehensively...")
               
                map_prompt_template = """
                You are a DFIR analyst conducting DEEP DIVE analysis of log data.
                
                Provide EXTREMELY DETAILED analysis including:
                1. EXHAUSTIVE listing of all security events with exact timestamps
                2. SPECIFIC log patterns, error messages, and warning texts
                3. TECHNICAL analysis with root cause explanations
                4. POTENTIAL impact assessment with evidence
                5. CORRELATION with other events in this section
                6. MITRE ATT&CK technique mapping
                7. CONFIDENCE level for each finding
                8. RECOMMENDED investigation steps
                
                Be exhaustive, specific, and cite exact log content with line numbers when possible.
                If no threats found, document ALL normal activity patterns for baseline.
                Minimum 500 words per section.
                
                Log Section:
                {context}
                """
               
                map_prompt = ChatPromptTemplate.from_template(map_prompt_template)
                map_chain = map_prompt | llm
               
                section_result = map_chain.invoke({"context": section})
                section_report = str(section_result.content) if hasattr(section_result, 'content') else str(section_result)
                section_reports.append(f"\n{'='*80}\nSECTION {idx + 1} COMPREHENSIVE ANALYSIS\n{'='*80}\n\n{section_report}")
           
            # Combine all section reports with enhanced formatting
            combined_context = "\n\n" + "📊 " + "="*70 + " COMBINED ANALYSIS " + "="*70 + "\n\n".join(section_reports)
           
        else:
            # Fewer docs - process all at once with MAXIMUM detail
            combined_context = "\n\n".join([
                f"\n{'='*50}\nLOG CHUNK {i+1} - COMPLETE CONTENT\n{'='*50}\n{doc.page_content}"
                for i, doc in enumerate(relevant_docs)
            ])
       
        # ENHANCED: Final reduction step with expanded prompt
        reduce_prompt = ChatPromptTemplate.from_template(user_prompt_template)
       
        chain = (
            {"context": RunnablePassthrough(), "question": RunnablePassthrough()}
            | reduce_prompt
            | llm
        )
       
        with st.spinner("🧠 Generating COMPREHENSIVE analysis report... This may take several minutes for detailed analysis."):
            result = chain.invoke({
                "context": combined_context,
                "question": "Provide an EXTREMELY DETAILED, THOROUGH, and COMPREHENSIVE security assessment based on ALL log data analyzed. Include specific findings with evidence, technical analysis, comprehensive IOCs, detailed timelines, MITRE ATT&CK mapping, and actionable recommendations. MINIMUM 2000 words."
            })
       
        # Format output with proper markdown
        if hasattr(result, 'content'):
            report_text = str(result.content)
        elif hasattr(result, 'text'):
            report_text = str(result.text)
        else:
            report_text = str(result) if result else 'No result returned from analysis.'
        
        # Add word count and formatting
        word_count = len(report_text.split())
        formatted_report = f"""
# COMPREHENSIVE DFIR ANALYSIS REPORT
**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Analysis Scope:** {len(relevant_docs)} document chunks analyzed
**Report Length:** {word_count:,} words

{report_text}

---
*Report generated by ForensIQ - DFIR Vault*
"""
        return formatted_report
       
    except Exception as e:
        st.error(f"❌ Error during comprehensive analysis: {str(e)}")
        return f"## Analysis Completed with Limitations\n\n**Error encountered:** {str(e)}\n\n**Partial analysis completed.**"

# --- UPDATED: analyze_logs function for backward compatibility ---
def analyze_logs(vectorstore, llm, user_prompt_template):
    """Wrapper for backward compatibility - uses the new analyze_large_dataset"""
    return analyze_large_dataset(vectorstore, llm, user_prompt_template, max_docs_per_query=30)

# --- NEW FUNCTION: Create concatenated reports ---
def create_concatenated_reports():
    """Create a concatenated view of all detailed reports"""
    if not st.session_state.processed_files:
        return ""
    
    concatenated = "=" * 80 + "\n"
    concatenated += "FORENSIQ - CONSOLIDATED DETAILED REPORTS\n"
    concatenated += f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    concatenated += f"Total Files Analyzed: {len(st.session_state.processed_files)}\n"
    concatenated += "=" * 80 + "\n\n"
    
    successful_reports = [f for f in st.session_state.processed_files if f.get('status') == 'success']
    
    for i, file_result in enumerate(successful_reports):
        concatenated += f"\n{'='*60}\n"
        concatenated += f"FILE {i+1}: {file_result.get('path', file_result.get('name', 'Unknown'))}\n"
        concatenated += f"Size: {file_result.get('size', 0) / (1024 * 1024):.2f} MB | "
        concatenated += f"Chunks: {file_result.get('chunks_processed', 'N/A')} | "
        concatenated += f"Rows: {file_result.get('rows_ingested', 'N/A')}\n"
        concatenated += f"{'='*60}\n\n"
        
        if file_result.get('report'):
            concatenated += file_result['report']
        else:
            concatenated += "No detailed report available for this file.\n"
        
        concatenated += "\n\n"
    
    return concatenated

# --- UPDATED FUNCTION: Enhanced Executive Summary Pass (Second Reduce) ---
def generate_executive_summary(processed_files_data, llm):
    """
    Takes concatenated detailed reports and generates a final executive summary
    with actionable intelligence linked to the source file.
    """
    st.info("📈 **Finalizing Report:** Consolidating individual analysis...")
    
    # 1. Create concatenated reports
    concatenated_reports = create_concatenated_reports()
    st.session_state.concatenated_reports = concatenated_reports
    
    if not concatenated_reports or "No detailed report available" in concatenated_reports:
        return "No threats or relevant security findings were identified in the successfully processed files."
    
    # Count successful reports
    success_count = len([f for f in processed_files_data if f.get('status') == 'success' and f.get('report')])
    st.write(f"Synthesizing findings from {success_count} detailed reports...")
    
    # 2. Enhanced Final Reduce Prompt with explicit file reference requirement
    final_reduce_prompt_template = """
    You are a Lead DFIR Analyst synthesizing comprehensive reports into an executive summary.
    
    **REQUIREMENTS:**
    1. Provide MINIMUM 1000-1500 words
    2. Include comprehensive technical details
    3. Link EVERY finding to specific source files
    4. Provide actionable intelligence
    5. Structure with clear headings
    6. Include tables for IOCs
    7. Provide confidence levels
    8. Suggest immediate, short-term, and long-term actions
    
    **SOURCE DATA:** Complete detailed reports from each file.
    
    **OUTPUT FORMAT:**
    
    # COMPREHENSIVE EXECUTIVE SUMMARY
    
    ## 1. EXECUTIVE OVERVIEW (3-5 paragraphs)
    [High-level summary with key findings]
    
    ## 2. CRITICAL FINDINGS (Detailed, File-Linked)
    [Table format with: Finding | Severity | Source File | Evidence | Confidence]
    
    ## 3. COMPREHENSIVE IOC CATALOG
    ### 3.1 Network IOCs
    [Table: IP | First Seen | Last Seen | Activity | Source File]
    
    ### 3.2 Host IOCs
    [Table: Indicator | Type | Path/Value | Source File]
    
    ### 3.3 Behavioral IOCs
    [Table: Behavior | TTP | MITRE ATT&CK | Source File]
    
    ## 4. TIMELINE CORRELATION
    [Detailed timeline across all files with specific timestamps]
    
    ## 5. THREAT ASSESSMENT MATRIX
    [Risk matrix with scores and justifications]
    
    ## 6. PRIORITIZED ACTION PLAN
    ### 6.1 Immediate Actions (0-24 hours)
    [Specific, actionable steps]
    
    ### 6.2 Short-term Actions (1-7 days)
    [Hardening and monitoring improvements]
    
    ### 6.3 Long-term Actions (30+ days)
    [Strategic improvements]
    
    ## 7. INVESTIGATION NOTES
    [Limitations, assumptions, further investigation needed]
    
    **Source Detailed Reports:**
    {context}
    """
    
    final_prompt = ChatPromptTemplate.from_template(final_reduce_prompt_template)
    
    # 3. Run the Final Chain with concatenated reports
    final_chain = (
        {"context": RunnablePassthrough()}
        | final_prompt
        | llm
    )
    
    with st.spinner("🧠 Generating comprehensive Executive Summary (this may take several minutes)..."):
        result = final_chain.invoke({"context": concatenated_reports})
        
    if hasattr(result, 'content'):
        return str(result.content)
    return str(result) if result else "Consolidation failed."

# --- NEW FUNCTION: Enhance response quality ---
def enhance_response_quality(response_text, min_words=1000):
    """
    Post-process response to ensure it meets minimum quality standards
    """
    if not response_text:
        return response_text
    
    words = len(response_text.split())
    
    # If response is too short, add guidance
    if words < min_words:
        enhancement_prompt = f"""
        The following analysis is too brief. Please expand it to be more comprehensive,
        detailed, and thorough. Add specific examples, technical details, and actionable
        recommendations. Target length: {min_words} words.
        
        Current analysis:
        {response_text}
        
        Expanded comprehensive analysis:
        """
        
        # You could use a quick LLM call here or just add a note
        return response_text + f"\n\n---\n**Note:** Analysis abbreviated. Consider using a larger model or adjusting parameters for more detail."
    
    return response_text

# --- FIXED: Monitor resources continuously with proper session state checking ---
def monitor_resources_continuously():
    """Continuously monitor system resources in a separate thread with safe session state access"""
    import psutil
    import time
    
    while True:
        try:
            # Safe check for monitoring_active flag
            monitoring_active = False
            try:
                # Use a try-except to safely access session state
                if 'monitoring_active' in st.session_state:
                    monitoring_active = st.session_state.monitoring_active
            except:
                # If we can't access session state, assume monitoring should stop
                break
            
            if not monitoring_active:
                break
            
            # Get CPU and RAM
            cpu_percent = psutil.cpu_percent(interval=0.5)
            memory = psutil.virtual_memory()
            ram_percent = memory.percent
            
            # Get GPU stats if available
            gpu_util = 0
            gpu_mem = 0
            
            try:
                gpu_stats = monitor_gpu_utilization()
                if gpu_stats:
                    gpu_util = gpu_stats.get('utilization_percent', 0)
                    gpu_mem = gpu_stats.get('memory_allocated_gb', 0)
            except:
                pass
            
            # Add to history with thread-safe approach
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            
            # Safely update session state
            try:
                if 'resource_history' in st.session_state:
                    st.session_state.resource_history['cpu'].append(cpu_percent)
                    st.session_state.resource_history['ram'].append(ram_percent)
                    st.session_state.resource_history['gpu_util'].append(gpu_util)
                    st.session_state.resource_history['gpu_mem'].append(gpu_mem)
                    st.session_state.resource_history['timestamps'].append(timestamp)
            except:
                # If we can't update session state, continue anyway
                pass
            
            # Sleep to avoid excessive CPU usage
            time.sleep(1)
            
        except Exception as e:
            # If monitoring fails, log and continue
            print(f"Monitoring thread error (non-fatal): {e}")
            time.sleep(1)
            continue

# --- NEW FUNCTION: Display resource dashboard ---
def display_resource_dashboard():
    """Display real-time resource utilization dashboard"""
    st.subheader("📊 System Resource Dashboard")
    
    if not st.session_state.resource_history['cpu']:
        st.info("No resource data available yet. Start analysis to monitor resources.")
        return
    
    # Create dashboard layout
    col1, col2, col3, col4 = st.columns(4)
    
    # Current values
    with col1:
        current_cpu = st.session_state.resource_history['cpu'][-1] if st.session_state.resource_history['cpu'] else 0
        st.metric("CPU Usage", f"{current_cpu:.1f}%")
    
    with col2:
        current_ram = st.session_state.resource_history['ram'][-1] if st.session_state.resource_history['ram'] else 0
        st.metric("RAM Usage", f"{current_ram:.1f}%")
    
    with col3:
        current_gpu_util = st.session_state.resource_history['gpu_util'][-1] if st.session_state.resource_history['gpu_util'] else 0
        st.metric("GPU Usage", f"{current_gpu_util:.1f}%")
    
    with col4:
        current_gpu_mem = st.session_state.resource_history['gpu_mem'][-1] if st.session_state.resource_history['gpu_mem'] else 0
        st.metric("GPU Memory", f"{current_gpu_mem:.1f} GB")
    
    # Create charts
    if len(st.session_state.resource_history['timestamps']) > 1:
        # Prepare data for plotting
        timestamps = list(st.session_state.resource_history['timestamps'])
        
        # Create time series chart
        fig = go.Figure()
        
        # Add CPU trace
        if st.session_state.resource_history['cpu']:
            fig.add_trace(go.Scatter(
                x=timestamps,
                y=list(st.session_state.resource_history['cpu']),
                mode='lines+markers',
                name='CPU %',
                line=dict(color='#1f77b4', width=2)
            ))
        
        # Add RAM trace
        if st.session_state.resource_history['ram']:
            fig.add_trace(go.Scatter(
                x=timestamps,
                y=list(st.session_state.resource_history['ram']),
                mode='lines+markers',
                name='RAM %',
                line=dict(color='#2ca02c', width=2)
            ))
        
        # Add GPU utilization trace if available
        if any(v > 0 for v in st.session_state.resource_history['gpu_util']):
            fig.add_trace(go.Scatter(
                x=timestamps,
                y=list(st.session_state.resource_history['gpu_util']),
                mode='lines+markers',
                name='GPU %',
                line=dict(color='#ff7f0e', width=2)
            ))
        
        fig.update_layout(
            title='Resource Utilization Over Time',
            xaxis_title='Time',
            yaxis_title='Percentage',
            hovermode='x unified',
            height=300,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Create bar chart for memory usage
        if any(v > 0 for v in st.session_state.resource_history['gpu_mem']):
            fig2 = go.Figure()
            
            # Only show the last 10 points for clarity
            recent_points = min(10, len(timestamps))
            recent_timestamps = timestamps[-recent_points:]
            recent_gpu_mem = list(st.session_state.resource_history['gpu_mem'])[-recent_points:]
            
            fig2.add_trace(go.Bar(
                x=recent_timestamps,
                y=recent_gpu_mem,
                name='GPU Memory (GB)',
                marker_color='#9467bd'
            ))
            
            fig2.update_layout(
                title='GPU Memory Usage (Recent)',
                xaxis_title='Time',
                yaxis_title='Memory (GB)',
                height=250,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            
            st.plotly_chart(fig2, use_container_width=True)
    
    # Control panel for monitoring
    with st.expander("📈 Monitoring Controls", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            if not st.session_state.monitoring_active:
                if st.button("▶️ Start Monitoring", use_container_width=True):
                    st.session_state.monitoring_active = True
                    # Start monitoring thread
                    thread = threading.Thread(target=monitor_resources_continuously)
                    thread.daemon = True
                    thread.start()
                    st.session_state.monitoring_thread = thread
                    st.rerun()
            else:
                if st.button("⏸️ Stop Monitoring", use_container_width=True):
                    st.session_state.monitoring_active = False
                    st.rerun()
        
        with col2:
            if st.button("🗑️ Clear History", use_container_width=True):
                st.session_state.resource_history = {
                    'cpu': deque(maxlen=100),
                    'ram': deque(maxlen=100),
                    'gpu_util': deque(maxlen=100),
                    'gpu_mem': deque(maxlen=100),
                    'timestamps': deque(maxlen=100)
                }
                st.rerun()
        
        # Display system info
        try:
            import psutil
            import platform
            
            st.write("---")
            st.write("**System Information:**")
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**OS:** {platform.system()} {platform.release()}")
                st.write(f"**CPU Cores:** {psutil.cpu_count()}")
                st.write(f"**Total RAM:** {psutil.virtual_memory().total / (1024**3):.1f} GB")
            
            with col2:
                if st.session_state.gpu_info and st.session_state.gpu_info.get("available", False):
                    st.write(f"**GPU:** {st.session_state.gpu_info['name']}")
                    st.write(f"**GPU VRAM:** {st.session_state.gpu_info['vram_gb']:.1f} GB")
                else:
                    st.write("**GPU:** Not available")
                    
        except:
            pass

# --- UPDATED: process_file_queue function with batch processing (NO TRUNCATION) ---
def process_file_queue(llm, config, ollama_url, analysis_prompt):
    """Process multiple files from the queue with batch processing (NO DATA LOSS)"""
    # Check and increase file descriptor limits at start
    if st.session_state.job_status == 'running' and len(st.session_state.file_queue) > 0:
        increase_file_descriptor_limit()
    
    # Start resource monitoring if not already active
    if not st.session_state.monitoring_active and st.session_state.job_status == 'running':
        st.session_state.monitoring_active = True
        thread = threading.Thread(target=monitor_resources_continuously)
        thread.daemon = True
        thread.start()
        st.session_state.monitoring_thread = thread
    
    if not st.session_state.file_queue:
        st.session_state.job_status = 'completed'
        st.success("🎉 File processing pipeline finished. Generating reports...")
        st.rerun()
        return

    current_file_info = st.session_state.file_queue.pop(0)
    file_path = current_file_info['path']
    file_extension = current_file_info['extension']

    st.write(f"📁 **Processing:** {current_file_info['relative_path']} ({current_file_info['size'] / (1024 * 1024):.2f} MB)")

    model_category = classify_model(config['model'])
    category_desc = MODEL_CATEGORIES.get(model_category, {}).get("description", "Unknown")
    st.write(f"🎯 **Using Model:** {config['model']} ({category_desc})")

    vectorstore = None
    persist_dir = None
    
    # Enhanced file result structure
    file_result = {
        'path': current_file_info['relative_path'],
        'name': current_file_info['name'],
        'size': current_file_info['size'],
        'extension': file_extension,
        'report': "Analysis skipped: No relevant data found or ingestion failed.",
        'status': 'skipped',
        'chunks_processed': 0,
        'analysis_timestamp': datetime.datetime.now().isoformat(),
        'model_used': config['model'],
        'embedding_model': config['embedding_model']
    }

    try:
        with st.status(f"🚀 Processing {current_file_info['name']}...", expanded=True) as status:
            status.write("📥 **Step 1:** Ingesting log file...")
            
            # Force garbage collection before starting
            gc.collect()
            
            # Determine if we should use streaming based on file size
            file_size_mb = current_file_info['size'] / (1024 * 1024)
            use_streaming = file_size_mb > 10
            
            df = ingest_logs(file_path, file_type=file_extension, use_streaming=use_streaming)

            if st.session_state.job_status != 'running':
                status.write("⏹️ Analysis stopped by user")
                st.session_state.file_queue.insert(0, current_file_info)
                return

            if df is not None and not df.empty:
                status.write(f"✅ **Step 1 Complete:** Ingested {len(df):,} rows")
                file_result['rows_ingested'] = len(df)

                status.write("✂️ **Step 2:** Chunking data...")
                # Use streaming chunking for large data
                use_chunk_streaming = len(df) > 10000
                chunks = chunk_logs(df, use_streaming=use_chunk_streaming)

                if st.session_state.job_status != 'running':
                    status.write("⏹️ Analysis stopped by user")
                    st.session_state.file_queue.insert(0, current_file_info)
                    return

                if chunks:
                    # --- KEY CHANGE: NO TRUNCATION - PROCESS ALL CHUNKS ---
                    status.write(f"✅ **Step 2 Complete:** Created {len(chunks):,} chunks (processing all)")
                    file_result['chunks_created'] = len(chunks)

                    status.write("🔧 **Step 3:** Building semantic search index in batches...")
                    
                    # Calculate optimal batch size based on available resources
                    optimal_batch_size = determine_optimal_batch_size(st.session_state.gpu_info)
                    if hasattr(st.session_state, 'optimal_batch_size'):
                        optimal_batch_size = st.session_state.optimal_batch_size
                    
                    status.write(f"⚡ **Batch Optimization:** Using batch size of {optimal_batch_size} for GPU efficiency")
                    
                    # Process chunks in batches without loading all at once
                    all_documents_processed = 0
                    total_batches = (len(chunks) + optimal_batch_size - 1) // optimal_batch_size
                    
                    # Create progress tracking
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    for batch_info in process_chunks_in_batches(chunks, config, ollama_url, optimal_batch_size):
                        if st.session_state.job_status != 'running':
                            break
                        
                        # Update progress
                        progress = batch_info['progress_percent'] / 100
                        progress_bar.progress(progress)
                        status_text.write(f"📦 Processing batch {batch_info['batch_number']}/{batch_info['total_batches']} "
                                         f"({batch_info['end_index'] + 1:,}/{len(chunks):,} chunks)")
                        
                        # Process this batch
                        try:
                            if vectorstore is None:
                                # First batch - create vectorstore
                                vectorstore, persist_dir = build_vector_store_batch(
                                    batch_info['chunks'], 
                                    config, 
                                    ollama_url, 
                                    is_first_batch=True
                                )
                            else:
                                # Subsequent batches - add to existing vectorstore
                                success = add_to_vector_store_batch(
                                    vectorstore,
                                    batch_info['chunks'],
                                    config,
                                    ollama_url,
                                    batch_number=batch_info['batch_number']
                                )
                                
                                if not success:
                                    st.warning(f"⚠️ Failed to add batch {batch_info['batch_number']}, continuing with next batch")
                            
                            all_documents_processed += len(batch_info['chunks'])
                            
                            # Update file result
                            file_result['chunks_processed'] = all_documents_processed
                            
                            # Force garbage collection between batches
                            gc.collect()
                            
                        except Exception as batch_error:
                            st.error(f"❌ Error in batch {batch_info['batch_number']}: {batch_error}")
                            # Continue with next batch instead of failing completely
                            continue
                    
                    # Clear progress indicators
                    progress_bar.empty()
                    status_text.empty()

                    if st.session_state.job_status != 'running':
                        status.write("⏹️ Analysis stopped by user")
                        st.session_state.file_queue.insert(0, current_file_info)
                        return

                    if vectorstore and all_documents_processed > 0:
                        status.write(f"✅ **Step 3 Complete:** Vector store ready with {all_documents_processed:,} documents")
                        file_result['chunks_processed'] = all_documents_processed

                        status.write("🤖 **Step 4:** AI analysis with DFIR expert...")
                        # Use the new analyze_large_dataset function
                        report = analyze_large_dataset(vectorstore, llm, analysis_prompt, max_docs_per_query=50)

                        # Enhance response quality
                        if report and hasattr(st.session_state, 'response_config'):
                            min_words_map = {
                                "Brief": 300,
                                "Standard": 800,
                                "Detailed": 1500,
                                "Comprehensive": 2500,
                                "Exhaustive": 4000
                            }
                            min_words = min_words_map.get(
                                st.session_state.response_config.get("detail_level", "Detailed"),
                                1500
                            )
                            report = enhance_response_quality(report, min_words)

                        if st.session_state.job_status != 'running':
                            status.write("⏹️ Analysis stopped by user")
                            st.session_state.file_queue.insert(0, current_file_info)
                            return

                        if report:
                            status.write("✅ **Step 4 Complete:** Analysis complete!")
                            
                            # Store enhanced report data
                            file_result['report'] = str(report) if not isinstance(report, str) else report
                            file_result['status'] = 'success'
                            file_result['analysis_complete'] = True
                            
                            # Store the report in current_report for single file analysis
                            if len(st.session_state.file_queue) == 0:  # Last file
                                st.session_state.current_report = file_result['report']  # Use file_result['report']
                        
                        # Enhanced cleanup of vector store
                        status.write("🧹 Releasing vector store resources...")
                        safe_chromadb_cleanup(vectorstore, persist_dir)
                        status.write("✅ Resources released")

                    else:
                        status.error("❌ Failed to build vector store or no documents processed")
                        # Cleanup and skip to next file
                        safe_chromadb_cleanup(vectorstore, persist_dir)
                        st.session_state.processed_files.append(file_result)
                        st.rerun()
                        return
                    
                    status.write("✅ File processing completed!")

                else:
                    status.write("ℹ️ No relevant data chunks created.")
            
            else:
                status.write("ℹ️ No relevant data found in this file.")

    except Exception as e:
        status.error(f"❌ Error processing {current_file_info['name']}: {str(e)}")
        file_result['report'] = f"Processing failed due to error: {str(e)}"
        file_result['status'] = 'error'
        file_result['error_message'] = str(e)
        
        # Force cleanup on error
        safe_chromadb_cleanup(vectorstore, persist_dir)

    finally:
        # Add the enhanced result to the processed list
        st.session_state.processed_files.append(file_result)
        
        # Force garbage collection between files
        gc.collect()

        # Continue with next file or complete
        if st.session_state.job_status == 'running':
            if st.session_state.file_queue:
                st.rerun() # Continue with next file
            else:
                st.session_state.job_status = 'completed'
                st.rerun()
        elif st.session_state.job_status == 'stopped':
            st.warning("Analysis stopped by user during file processing.")
            st.rerun()

def monitor_system_resources():
    """Monitor system resources to prevent exhaustion"""
    try:
        import psutil
        
        # Get system info
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Get open files for current process
        current_process = psutil.Process()
        open_files = len(current_process.open_files())
        
        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_available_gb': memory.available / (1024**3),
            'disk_free_gb': disk.free / (1024**3),
            'open_files': open_files,
            'threads': current_process.num_threads(),
        }
        
    except Exception as e:
        return None

# --- NEW FUNCTION: Streaming file processing with batch processing ---
def process_single_file_streaming(file_path, file_extension, llm, config, ollama_url, analysis_prompt):
    """Process a single file using streaming approach with GPU optimization"""
    vectorstore = None
    persist_dir = None
    
    # Enhanced file result structure
    file_result = {
        'path': os.path.basename(file_path),
        'name': os.path.basename(file_path),
        'size': os.path.getsize(file_path),
        'extension': file_extension,
        'report': "Analysis skipped: No relevant data found or ingestion failed.",
        'status': 'skipped',
        'chunks_processed': 0,
        'analysis_timestamp': datetime.datetime.now().isoformat(),
        'model_used': config['model'],
        'embedding_model': config['embedding_model']
    }
    
    # Start resource monitoring if not already active
    if not st.session_state.monitoring_active:
        st.session_state.monitoring_active = True
        thread = threading.Thread(target=monitor_resources_continuously)
        thread.daemon = True
        thread.start()
        st.session_state.monitoring_thread = thread
    
    try:
        with st.status("🚀 Starting streaming pipeline...", expanded=True) as status:
            # Show GPU info if available
            if st.session_state.gpu_info and st.session_state.gpu_info.get("available", False):
                gpu_name = st.session_state.gpu_info['name']
                vram_gb = st.session_state.gpu_info['vram_gb']
                status.write(f"🎮 **GPU:** {gpu_name} ({vram_gb:.1f}GB VRAM)")
            
            status.write("📥 **Step 1:** Ingesting log file...")
            
            # Ingest with streaming for large files
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            use_streaming = file_size_mb > 10
            
            df = ingest_logs(file_path, file_type=f".{file_extension}", use_streaming=use_streaming)

            if st.session_state.job_status != 'running':
                status.write("⏹️ Analysis stopped by user")
                return

            if df is not None and not df.empty:
                status.write(f"✅ **Step 1 Complete:** Ingested {len(df):,} rows")
                file_result['rows_ingested'] = len(df)

                status.write("✂️ **Step 2:** Chunking data...")
                # Use streaming chunking for large data
                use_chunk_streaming = len(df) > 10000
                chunks = chunk_logs(df, use_streaming=use_chunk_streaming)

                if st.session_state.job_status != 'running':
                    status.write("⏹️ Analysis stopped by user")
                    return

                if chunks:
                    status.write(f"✅ **Step 2 Complete:** Created {len(chunks):,} chunks")
                    file_result['chunks_created'] = len(chunks)

                    status.write("🔧 **Step 3:** Building semantic search index in batches...")
                    # Use streaming vector store for large chunk counts
                    use_vector_streaming = len(chunks) > 50
                    
                    # Determine optimal batch size based on GPU
                    optimal_batch_size = determine_optimal_batch_size(st.session_state.gpu_info)
                    if hasattr(st.session_state, 'optimal_batch_size'):
                        optimal_batch_size = st.session_state.optimal_batch_size
                    
                    status.write(f"⚡ **Batch Optimization:** Using batch size of {optimal_batch_size} for GPU efficiency")
                    
                    # Process chunks in batches
                    all_documents_processed = 0
                    total_batches = (len(chunks) + optimal_batch_size - 1) // optimal_batch_size
                    
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    for batch_info in process_chunks_in_batches(chunks, config, ollama_url, optimal_batch_size):
                        if st.session_state.job_status != 'running':
                            break
                        
                        progress = batch_info['progress_percent'] / 100
                        progress_bar.progress(progress)
                        status_text.write(f"📦 Processing batch {batch_info['batch_number']}/{batch_info['total_batches']} "
                                         f"({batch_info['end_index'] + 1:,}/{len(chunks):,} chunks)")
                        
                        try:
                            if vectorstore is None:
                                vectorstore, persist_dir = build_vector_store_batch(
                                    batch_info['chunks'], 
                                    config, 
                                    ollama_url, 
                                    is_first_batch=True
                                )
                            else:
                                success = add_to_vector_store_batch(
                                    vectorstore,
                                    batch_info['chunks'],
                                    config,
                                    ollama_url,
                                    batch_number=batch_info['batch_number']
                                )
                            
                            all_documents_processed += len(batch_info['chunks'])
                            file_result['chunks_processed'] = all_documents_processed
                            
                            gc.collect()
                            
                        except Exception as batch_error:
                            st.error(f"❌ Error in batch {batch_info['batch_number']}: {batch_error}")
                            continue
                    
                    progress_bar.empty()
                    status_text.empty()

                    if st.session_state.job_status != 'running':
                        status.write("⏹️ Analysis stopped by user")
                        return

                    # Monitor GPU after building
                    gpu_stats_after = monitor_gpu_utilization()
                    if gpu_stats_after:
                        status.write(f"📊 **GPU After:** {gpu_stats_after['utilization_percent']}% util, "
                                    f"{gpu_stats_after['memory_allocated_gb']:.1f}GB used")

                    if vectorstore and all_documents_processed > 0:
                        status.write(f"✅ **Step 3 Complete:** Vector store ready with {all_documents_processed:,} documents")

                        status.write("🤖 **Step 4:** AI analysis with DFIR expert...")
                        report = analyze_large_dataset(vectorstore, llm, analysis_prompt, max_docs_per_query=50)

                        # Enhance response quality
                        if report and hasattr(st.session_state, 'response_config'):
                            min_words_map = {
                                "Brief": 300,
                                "Standard": 800,
                                "Detailed": 1500,
                                "Comprehensive": 2500,
                                "Exhaustive": 4000
                            }
                            min_words = min_words_map.get(
                                st.session_state.response_config.get("detail_level", "Detailed"),
                                1500
                            )
                            report = enhance_response_quality(report, min_words)

                        if st.session_state.job_status != 'running':
                            status.write("⏹️ Analysis stopped by user")
                            return

                        if report:
                            status.write("✅ **Step 4 Complete:** Analysis complete!")
                            
                            # Store enhanced results
                            file_result['report'] = str(report) if not isinstance(report, str) else report
                            file_result['status'] = 'success'
                            file_result['analysis_complete'] = True
                            
                            # Store in session state - FIXED HERE
                            st.session_state.current_report = file_result['report']  # Use file_result['report']
                            st.session_state.final_summary_generated = True
                            st.session_state.job_status = 'completed'
                            st.session_state.processed_files.append(file_result)
                            
                        status.success("🎉 Streaming pipeline completed successfully!")

                else:
                    status.write("ℹ️ No relevant data chunks created.")
                    st.session_state.job_status = 'completed'
            
            else:
                status.write("ℹ️ No relevant data found in this file.")
                st.session_state.job_status = 'completed'
                
    except Exception as e:
        st.error(f"❌ Error during streaming analysis: {str(e)}")
        st.session_state.job_status = 'stopped'
    
    finally:
        # Cleanup
        if persist_dir and os.path.exists(persist_dir):
            try:
                # Use enhanced cleanup
                safe_chromadb_cleanup(vectorstore, persist_dir)
                st.info(f"🧹 Temporary vector store directory cleaned up.")
            except Exception as del_e:
                st.warning(f"⚠️ Could not delete directory: {del_e}")
        
        if st.session_state.job_status == 'stopped':
            st.rerun()

def main():
    # --- FIX 1: Call print_developer_info only once ---
    print_developer_info()
    
    # Set page config with increased file size limit
    st.set_page_config(
        page_title="ForensIQ",
        page_icon="🧠",
        layout="wide"
    )

    # Updated title and subtitle
    st.title("🧠 ForensIQ")
    st.write("AI-powered log analysis, brought to you by **[DFIR Vault](https://dfirvault.com)**.")

    # Initialize ALL session state variables FIRST (FIX for monitoring thread error)
    if 'job_status' not in st.session_state:
        st.session_state.job_status = 'idle'
    if 'current_report' not in st.session_state:
        st.session_state.current_report = None
    if 'current_file' not in st.session_state:
        st.session_state.current_file = None
    if 'file_queue' not in st.session_state:
        st.session_state.file_queue = []
    if 'processed_files' not in st.session_state:
        st.session_state.processed_files = []
    if 'connection_info' not in st.session_state:
        st.session_state.connection_info = None
    if 'config' not in st.session_state:
        st.session_state.config = load_config()
    if 'gpu_info' not in st.session_state:
        try:
            st.session_state.gpu_info = detect_gpu()
        except:
            st.session_state.gpu_info = {"available": False, "name": "Detection failed", "vram_gb": 0, "recommended_model": "llama3.2:3b-instruct-q4_0"}
    if 'selected_folders' not in st.session_state:
        st.session_state.selected_folders = []
    if 'selected_files' not in st.session_state:
        st.session_state.selected_files = []
    if 'final_summary_generated' not in st.session_state:
        st.session_state.final_summary_generated = False
    if 'concatenated_reports' not in st.session_state:
        st.session_state.concatenated_reports = ""
    if 'optimal_batch_size' not in st.session_state:
        st.session_state.optimal_batch_size = 200
    if 'streaming_thresholds' not in st.session_state:
        st.session_state.streaming_thresholds = {
            'csv_mb': 10,
            'chunk_rows': 10000,
            'vector_chunks': 50
        }
    if 'processing_limits' not in st.session_state:
        st.session_state.processing_limits = {
            'max_concurrent_files': 5,
            'max_chunks_per_file': 0  # Set to 0 to disable truncation
        }
    # --- CRITICAL FIX: Initialize monitoring states before any threads start ---
    if 'resource_history' not in st.session_state:
        st.session_state.resource_history = {
            'cpu': deque(maxlen=100),
            'ram': deque(maxlen=100),
            'gpu_util': deque(maxlen=100),
            'gpu_mem': deque(maxlen=100),
            'timestamps': deque(maxlen=100)
        }
    if 'monitoring_active' not in st.session_state:
        st.session_state.monitoring_active = False  # MUST BE INITIALIZED
    if 'concatenated_reports' not in st.session_state:
        st.session_state.concatenated_reports = ""
    if 'monitoring_thread' not in st.session_state:
        st.session_state.monitoring_thread = None
    if 'batch_settings' not in st.session_state:
        st.session_state.batch_settings = {
            'documents_per_batch': 200,
            'max_retrieved_docs': 50
        }
    if 'response_config' not in st.session_state:
        st.session_state.response_config = {
            "detail_level": "Detailed",
            "max_tokens": 16384
        }
    # --- END FIX ---

    config = st.session_state.config

    # Configuration section
    with st.expander("🔧 Configuration", expanded=True):
        col1, col2 = st.columns(2)
        with col1:
            new_host = st.text_input("Ollama Host", config['ollama_host'], key="host_input")
        with col2:
            new_port = st.text_input("Ollama Port", config['ollama_port'], key="port_input")

        new_embed_model = st.text_input(
            "Ollama Embedding Model",
            config.get('embedding_model', 'nomic-embed-text'),
            key="embed_model_input",
            help="The local Ollama model to use for embeddings, e.g., 'nomic-embed-text'"
        )

        config_changed = (
            new_host != config['ollama_host'] or
            new_port != config['ollama_port'] or
            new_embed_model != config.get('embedding_model', 'nomic-embed-text')
        )

        if config_changed:
            config['ollama_host'] = new_host
            config['ollama_port'] = new_port
            config['embedding_model'] = new_embed_model
            st.session_state.connection_info = None

        # GPU Information
        st.write("---")
        st.write("**🎮 GPU Information:**")
        if st.session_state.gpu_info and st.session_state.gpu_info.get("available", False):
            gpu_name = st.session_state.gpu_info['name']
            vram_gb = st.session_state.gpu_info['vram_gb']
            st.success(f"✅ GPU Detected: {gpu_name}")
            st.write(f"- **VRAM:** {vram_gb:.1f} GB")
            st.write(f"- **Recommended Model:** {st.session_state.gpu_info['recommended_model']}")
            
            # Calculate and display optimal batch size
            optimal_batch = determine_optimal_batch_size(st.session_state.gpu_info)
            st.write(f"- **Optimal Batch Size:** {optimal_batch} documents")
            st.session_state.optimal_batch_size = optimal_batch

            if st.button("🎯 Use Recommended GPU Model", use_container_width=True):
                config['model'] = st.session_state.gpu_info['recommended_model']
                save_config(config)
                st.session_state.config = config
                st.session_state.connection_info = None
                st.success(f"Model set to {config['model']} for GPU optimization!")
        else:
            st.warning("⚠️ No GPU detected - using CPU mode")
            st.info("💡 For faster analysis, ensure you have a compatible GPU and drivers installed")

        # Performance Optimization Settings
        st.write("---")
        st.subheader("⚡ Performance Optimization")
        
        # Batch size control
        if st.session_state.gpu_info and st.session_state.gpu_info.get("available", False):
            default_batch_size = st.session_state.optimal_batch_size
            batch_size = st.slider(
                "Embedding Batch Size",
                min_value=10,
                max_value=1000,
                value=default_batch_size,
                step=10,
                help="Larger batches improve GPU utilization but use more memory. Adjust based on your GPU VRAM."
            )
            st.session_state.optimal_batch_size = batch_size
            
            # Display recommended settings based on VRAM
            vram_gb = st.session_state.gpu_info['vram_gb']
            if vram_gb >= 16:
                recommended = "500-1000"
            elif vram_gb >= 8:
                recommended = "250-500"
            elif vram_gb >= 4:
                recommended = "100-250"
            else:
                recommended = "50-100"
            
            st.info(f"💡 Recommended range for {vram_gb:.1f}GB VRAM: {recommended} documents/batch")
            
            # Batch processing control
            st.write("**Batch Processing Control:**")
            col1, col2 = st.columns(2)
            
            with col1:
                batch_documents = st.number_input(
                    "Documents per Batch",
                    min_value=10,
                    max_value=500,
                    value=st.session_state.batch_settings['documents_per_batch'],
                    step=10,
                    help="Process this many documents at a time"
                )
                st.session_state.batch_settings['documents_per_batch'] = batch_documents
            
            with col2:
                max_retrieved = st.number_input(
                    "Max Retrieved Documents",
                    min_value=10,
                    max_value=200,
                    value=st.session_state.batch_settings['max_retrieved_docs'],
                    step=5,
                    help="Maximum documents to analyze at once (prevents context overflow)"
                )
                st.session_state.batch_settings['max_retrieved_docs'] = max_retrieved
            
            # Processing limits (modified to disable truncation)
            st.write("**🛡️ Processing Limits:**")
            col1, col2 = st.columns(2)
            with col1:
                max_concurrent_files = st.number_input(
                    "Max Files in Memory",
                    min_value=1,
                    max_value=50,
                    value=5,
                    help="Maximum number of files to keep in memory at once"
                )
                st.session_state.processing_limits['max_concurrent_files'] = max_concurrent_files
            with col2:
                # Inform user that truncation is disabled
                st.info("**Chunk Limit:** Disabled\n\nAll chunks will be processed")
                st.session_state.processing_limits['max_chunks_per_file'] = 0  # 0 = no limit
            
            st.info("💡 **Note:** Batch processing prevents 'Too many open files' errors without truncating data.")
        
        # Response Configuration
        st.write("---")
        st.subheader("📏 Response Configuration")

        col1, col2 = st.columns(2)
        with col1:
            response_length = st.selectbox(
                "Response Detail Level",
                ["Brief", "Standard", "Detailed", "Comprehensive", "Exhaustive"],
                index=2,  # Default to Detailed
                help="Controls the length and detail of AI responses"
            )
            st.session_state.response_config["detail_level"] = response_length

        with col2:
            max_tokens = st.slider(
                "Max Response Tokens",
                min_value=1024,
                max_value=32768,
                value=16384,
                step=1024,
                help="Maximum tokens in AI response (higher = longer responses)"
            )
            st.session_state.response_config["max_tokens"] = max_tokens
        
        # Display current response settings
        st.write("**Current Response Settings:**")
        st.write(f"- **Detail Level:** {response_length}")
        st.write(f"- **Max Tokens:** {max_tokens:,}")
        
        # Detail level descriptions
        detail_descriptions = {
            "Brief": "~300 words, quick overview",
            "Standard": "~800 words, balanced analysis",
            "Detailed": "~1500 words, comprehensive findings",
            "Comprehensive": "~2500 words, exhaustive analysis",
            "Exhaustive": "~4000 words, maximum detail"
        }
        st.info(f"💡 **{response_length}:** {detail_descriptions.get(response_length, '')}")
        
        # Refresh models button
        col1, col2 = st.columns([3, 1])
        with col2:
            if st.button("🔄 Refresh Models", use_container_width=True):
                st.session_state.connection_info = None
                try:
                    st.session_state.gpu_info = detect_gpu()
                    # Recalculate optimal batch size
                    st.session_state.optimal_batch_size = determine_optimal_batch_size(st.session_state.gpu_info)
                except:
                    st.session_state.gpu_info = {"available": False, "name": "Detection failed", "vram_gb": 0, "recommended_model": "llama3.2:3b-instruct-q4_0"}

        # Get connection info
        if st.session_state.connection_info is None:
            with st.spinner("🔍 Discovering models..."):
                st.session_state.connection_info = refresh_ollama_connection(config)

        connection_info = st.session_state.connection_info

        if connection_info and connection_info["success"]:
            st.success("✅ Ollama connection successful!")
            available_models = connection_info["available_models"]
            recommended_models = connection_info["recommended_models"]

            if not available_models:
                recommended_model, reason = get_hardware_recommendation()
                st.info(f"💡 **Hardware Recommendation:** {recommended_model} - {reason}")

            if available_models:
                model_options = []
                display_names = []

                llm_models = [m for m in available_models if "embed" not in m.lower()]

                for category in ["gpu_optimized", "very_fast", "fast", "balanced", "quality", "detailed_analysis"]:
                    if category in recommended_models and recommended_models[category]:
                        for model in recommended_models[category]:
                            if model in llm_models:
                                model_options.append(model)
                                display_names.append(create_model_display_name(model))

                for model in llm_models:
                    if model not in model_options:
                        model_options.append(model)
                        display_names.append(f"🔹 {model} (Other)")

                current_model = config.get('model')
                if current_model not in model_options:
                    for category in ["gpu_optimized", "very_fast", "fast", "balanced", "detailed_analysis"]:
                        if category in recommended_models and recommended_models[category]:
                            current_model = recommended_models[category][0]
                            break
                    if not current_model and model_options:
                        current_model = model_options[0]

                if current_model and model_options:
                    try:
                        current_index = model_options.index(current_model)
                    except ValueError:
                        current_index = 0

                    selected_display = st.selectbox(
                        "Select LLM Model",
                        options=display_names,
                        index=current_index,
                        key="model_select"
                    )

                    selected_index = display_names.index(selected_display)
                    config['model'] = model_options[selected_index]

                st.write("---")
                st.write("**📊 LLM Model Recommendations:**")

                for category in ["gpu_optimized", "very_fast", "fast", "balanced", "quality", "detailed_analysis"]:
                    if category in recommended_models and recommended_models[category]:
                        desc = MODEL_CATEGORIES.get(category, {}).get("description", category.title())
                        models_list = ", ".join(recommended_models[category][:3])
                        if len(recommended_models[category]) > 3:
                            models_list += f" ... (+{len(recommended_models[category]) - 3} more)"
                        st.write(f"- **{desc}:** {models_list}")

                if available_models:
                    st.write(f"**All Available Models:** {', '.join(available_models[:10])}")
                    if len(available_models) > 10:
                        st.write(f"*... and {len(available_models) - 10} more*")

            else:
                st.warning("⚠️ No models found in Ollama. Please install models.")
                st.info("💡 Try: `ollama pull llama3.2:3b-instruct-q4_0` for good performance")
                st.info("💡 Try: `ollama pull nomic-embed-text` for embeddings")

        elif connection_info:
            st.error(f"❌ Cannot connect to Ollama: {connection_info['error']}")
            st.info("💡 Please ensure:")
            st.info("1. Ollama is running: `ollama serve`")
            st.info("2. Host and port are correct")
            st.info("3. Firewall allows connections")
            st.info(f"4. Try: `ollama pull {config['model']}` to install the model")
        else:
            st.error("❌ Failed to initialize Ollama connection")
            st.info("💡 Please check your configuration and try refreshing")

        # Display current settings
        st.write("---")
        st.write(f"**Current Settings:**")
        st.write(f"- **Ollama URL:** http://{config['ollama_host']}:{config['ollama_port']}")
        if config.get('model'):
            model_category = classify_model(config['model'])
            category_desc = MODEL_CATEGORIES.get(model_category, {}).get("description", "Unknown")
            st.write(f"- **Selected LLM Model:** {config['model']} ({category_desc})")
        if config.get('embedding_model'):
            st.write(f"- **Embedding Model:** {config['embedding_model']}")
        if st.session_state.gpu_info and st.session_state.gpu_info.get("available", False):
            st.write(f"- **GPU:** {st.session_state.gpu_info['name']} ({st.session_state.gpu_info['vram_gb']:.1f}GB)")
            st.write(f"- **Batch Size:** {st.session_state.optimal_batch_size} documents")
        st.write(f"- **Response Detail:** {st.session_state.response_config.get('detail_level', 'Detailed')}")
        st.write(f"- **Max Tokens:** {st.session_state.response_config.get('max_tokens', 16384):,}")
        st.write(f"- **Last Run:** {config.get('last_run', 'Never')}")

        if st.button("💾 Save Configuration", use_container_width=True):
            save_config(config)
            st.session_state.config = config
            st.success("Configuration saved and refreshed!")

        # --- Prompt Editor ---
        st.write("---")
        st.subheader("🤖 DFIR Analysis Prompt")
        st.write("This is the 'Reduce' prompt used to combine summaries. **Must** include `{context}` and `{question}`.")

        current_prompt = st.text_area(
            "Analysis Prompt",
            value=config['dfir_prompt'],
            height=400,
            key="prompt_editor",
            help="The LLM prompt template. {context} and {question} are required."
        )

        if st.button("💾 Save Prompt to Config", use_container_width=True):
            if "{context}" not in st.session_state.prompt_editor or "{question}" not in st.session_state.prompt_editor:
                st.error("❌ Cannot save: Prompt must include `{context}` or `{question}` placeholders.")
            else:
                config['dfir_prompt'] = st.session_state.prompt_editor
                save_config(config)
                st.session_state.config = config
                st.success("✅ Prompt saved to config.txt!")

    config['last_run'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    config_copy = config.copy()
    config_copy.pop('dfir_prompt', None)
    save_config(config_copy)
    config['dfir_prompt'] = st.session_state.prompt_editor
    st.session_state.config = config

    # --- START OF FILE UPLOAD & ANALYSIS SECTION ---

    log_files = []
    total_discovered_size = 0
    st.subheader("📁 File Upload & Analysis")

    upload_option = st.radio(
        "Select upload type:",
        ["Single File", "Multiple Files", "Folder (Bulk Analysis)"],
        horizontal=True,
        key="upload_option_radio"
    )

    # Clear selection lists and analysis state when switching options
    if upload_option != "Folder (Bulk Analysis)" and st.session_state.selected_folders:
          st.session_state.selected_folders = []
    if upload_option != "Multiple Files" and st.session_state.selected_files:
          st.session_state.selected_files = []
    
    # Reset final summary state if starting a new upload type
    if st.session_state.job_status == 'idle':
        if st.session_state.processed_files:
            st.session_state.processed_files = []
        if st.session_state.final_summary_generated:
            st.session_state.final_summary_generated = False
        if st.session_state.current_report:
            st.session_state.current_report = None
            
    # File Uploaders for Single and Multiple files
    if upload_option == "Single File" or upload_option == "Multiple Files":
        uploaded_files = st.file_uploader(
            "Choose log file(s)",
            type=None,
            help="All files are accepted. The application will detect if it's a readable log file. Supports files up to 1GB.",
            accept_multiple_files=(upload_option == "Multiple Files"),
            key="file_uploader"
        )
        
        uploaded_files_list = uploaded_files if isinstance(uploaded_files, list) else ([uploaded_files] if uploaded_files else [])
        
        if uploaded_files_list:
            valid_files = []
            invalid_files = []
            
            for uploaded_file in uploaded_files_list:
                try:
                    content = uploaded_file.getvalue()
                    is_text_file = False
                    try:
                        content.decode('utf-8')
                        is_text_file = True
                    except UnicodeDecodeError:
                        for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
                            try:
                                content.decode(encoding)
                                is_text_file = True
                                break
                            except UnicodeDecodeError:
                                continue
                            
                    if is_text_file:
                        file_info = {
                            'path': None,
                            'name': uploaded_file.name,
                            'extension': uploaded_file.name.split('.')[-1].lower() if '.' in uploaded_file.name else '',
                            'size': len(content),
                            'relative_path': uploaded_file.name,
                            'file_object': uploaded_file
                        }
                        valid_files.append(file_info)
                    else:
                        invalid_files.append(uploaded_file.name)
                        
                except Exception as e:
                    invalid_files.append(f"{uploaded_file.name} (error: {e})")
            
            st.session_state.selected_files = valid_files
            
            # Display results
            if valid_files:
                st.success(f"✅ {len(valid_files)} files accepted as readable text")
                with st.expander("Accepted Files"):
                    for file_info in valid_files:
                        file_size_mb = file_info['size'] / 1024 / 1024
                        st.write(f"- {file_info['name']} ({file_size_mb:.2f} MB)")
            
            if invalid_files:
                st.warning(f"⚠️ {len(invalid_files)} files rejected (binary or unreadable)")
                for invalid_file in invalid_files:
                    st.write(f"- ❌ {invalid_file}")
                    
        else:
            st.session_state.selected_files = []

    else:  # Folder (Bulk Analysis)
        # --- MULTI-FOLDER SELECTION LOGIC ---
        st.write("Select one or more folders containing your log files:")

        col1, col2 = st.columns([3, 1])
        with col1:
            if st.button("➕ Add Folder...", use_container_width=True):
                selected = select_folder()
                if selected and selected not in st.session_state.selected_folders:
                    st.session_state.selected_folders.append(selected)
                    st.rerun()

        with col2:
              if st.button("🗑️ Clear Folders", use_container_width=True, disabled=not st.session_state.selected_folders):
                  st.session_state.selected_folders = []
                  st.rerun()

        # --- Display Selected Folders ---
        if st.session_state.selected_folders:
            st.write("**Selected Folders:**")
            for folder in st.session_state.selected_folders:
                st.info(f"`{folder}`")

            # --- Discover files from ALL selected folders ---
            st.write("---")
            with st.spinner("🔍 Discovering log files in selected folders..."):
                all_discovered_files = []
                total_discovered_size = 0
                for folder_path in st.session_state.selected_folders:
                    if os.path.exists(folder_path):
                        discovered, size = discover_log_files(folder_path)
                        for file_info in discovered:
                            relative_base = Path(folder_path).name
                            file_info['relative_path'] = str(Path(relative_base) / file_info['relative_path'])
                        all_discovered_files.extend(discovered)
                        total_discovered_size += size
                    else:
                        st.error(f"Selected path does not exist: `{folder_path}`")

                log_files = all_discovered_files

            if log_files:
                st.success(f"✅ Found **{len(log_files)}** log files ({total_discovered_size / 1024 / 1024:.2f} MB total) across all selected folders.")
                with st.expander("📋 View All Discovered Files"):
                    for file_info in log_files:
                        st.write(f"- {file_info['relative_path']} ({file_info['size'] / 1024:.2f} KB)")
            else:
                st.warning("⚠️ No supported log files found in the selected folder(s).")
        else:
            st.warning("No folders selected.")

    # --- START OF JOB CONTROL SECTION ---
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        has_files_to_process = (
            (len(st.session_state.selected_files) > 0 and upload_option != "Folder (Bulk Analysis)") or
            (len(log_files) > 0 and upload_option == "Folder (Bulk Analysis)") or
            (len(st.session_state.file_queue) > 0)
        )

        if st.session_state.job_status == 'idle' and has_files_to_process:
            if st.button("🚀 Start Analysis", use_container_width=True, type="primary"):

                analysis_prompt = st.session_state.prompt_editor
                if "{context}" not in analysis_prompt or "{question}" not in analysis_prompt:
                    st.error("❌ Cannot start: The analysis prompt in the config section is missing the required `{context}` or `{question}` placeholders. Please correct it.")
                    st.session_state.job_status = 'stopped'
                    st.rerun()
                    return

                st.session_state.current_analysis_prompt = analysis_prompt

                # Queue files based on the selected option
                if len(st.session_state.selected_files) > 0 and upload_option != "Folder (Bulk Analysis)":
                    file_queue = []
                    for file_info in st.session_state.selected_files:
                        file_queue.append(file_info)
                    
                    st.session_state.file_queue = file_queue
                    st.success(f"📋 Queued {len(file_queue)} files for analysis!")

                elif len(log_files) > 0 and upload_option == "Folder (Bulk Analysis)":
                    st.session_state.file_queue = log_files
                    st.success(f"📋 Queued {len(log_files)} files from selected folder(s) for analysis!")
                
                # Reset analysis results
                st.session_state.processed_files = []
                st.session_state.current_report = None
                st.session_state.final_summary_generated = False
                st.session_state.job_status = 'running'
                
                st.rerun()

        elif st.session_state.job_status == 'running':
            if st.button("⏹️ Stop Analysis", use_container_width=True, type="secondary"):
                st.session_state.job_status = 'stopped'
                st.rerun()

    with col2:
        if st.session_state.job_status in ['completed', 'stopped']:
            if st.button("🔄 New Analysis", use_container_width=True):
                st.session_state.job_status = 'idle'
                st.session_state.current_report = None
                st.session_state.current_file = None
                st.session_state.file_queue = []
                st.session_state.processed_files = []
                st.session_state.selected_folders = []
                st.session_state.selected_files = []
                st.session_state.final_summary_generated = False
                st.session_state.concatenated_reports = ""
                st.session_state.monitoring_active = False
                st.rerun()

    with col3:
        remaining = len(st.session_state.file_queue)
        if st.session_state.job_status == 'running' and remaining > 0:
            st.info(f"{remaining} files remaining")
        elif st.session_state.file_queue or st.session_state.processed_files:
            if st.button(f"🗑️ Clear Queue ({remaining})", use_container_width=True, type="secondary"):
                st.session_state.file_queue = []
                st.session_state.processed_files = []
                st.session_state.job_status = 'idle'
                st.session_state.current_report = None
                st.session_state.final_summary_generated = False
                st.session_state.concatenated_reports = ""
                st.session_state.monitoring_active = False
                st.rerun()

    # Display job status
    status_emoji = {
        'idle': '⏸️',
        'running': '🔄',
        'completed': '✅',
        'stopped': '⏹️'
    }

    st.write(f"**Job Status:** {status_emoji[st.session_state.job_status]} {st.session_state.job_status.upper()}")

    if st.session_state.file_queue or st.session_state.processed_files:
        total_processed = len(st.session_state.processed_files)
        total_queued = len(st.session_state.file_queue) + total_processed
        if total_queued > 0:
            st.write(f"**Files:** {total_processed} processed, {len(st.session_state.file_queue)} remaining")

    # --- System Resource Monitoring ---
    if st.session_state.job_status == 'running':
        resources = monitor_system_resources()
        if resources:
            with st.expander("📊 System Resources", expanded=False):
                # Display resource dashboard
                display_resource_dashboard()
                st.write("---")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("CPU", f"{resources['cpu_percent']:.1f}%")
                    st.metric("Memory", f"{resources['memory_percent']:.1f}%")
                with col2:
                    st.metric("Available RAM", f"{resources['memory_available_gb']:.1f} GB")
                    st.metric("Disk Free", f"{resources['disk_free_gb']:.1f} GB")
                with col3:
                    st.metric("Open Files", resources['open_files'])
                    st.metric("Threads", resources['threads'])
                    
                # Warning if resources are low
                if resources['open_files'] > 1000:
                    st.warning("⚠️ High number of open files. Consider reducing batch size.")
                if resources['memory_percent'] > 90:
                    st.error("🚨 High memory usage! Processing may fail.")
                if resources['memory_available_gb'] < 1:
                    st.error("🚨 Low available memory! Consider stopping processing.")
                
                # Show processing limits
                st.write("---")
                st.write("**Current Processing Limits:**")
                st.write(f"**Batch Size:** {st.session_state.batch_settings['documents_per_batch']} documents")
                st.write(f"**Max Retrieved:** {st.session_state.batch_settings['max_retrieved_docs']} documents")
                st.write(f"**Truncation:** DISABLED (all chunks processed)")
                
                # Show response configuration
                st.write("---")
                st.write("**Response Configuration:**")
                st.write(f"**Detail Level:** {st.session_state.response_config.get('detail_level', 'Detailed')}")
                st.write(f"**Max Tokens:** {st.session_state.response_config.get('max_tokens', 16384):,}")

    # Process files if job is running
    if (st.session_state.job_status == 'running' and len(st.session_state.file_queue) > 0):

        if st.session_state.connection_info is None or not st.session_state.connection_info["success"]:
            st.error("❌ No valid Ollama connection. Please check configuration.")
            st.session_state.job_status = 'stopped'
            return

        connection_info = st.session_state.connection_info
        llm = connection_info["llm"]
        ollama_url = connection_info["ollama_url"]

        analysis_prompt = st.session_state.current_analysis_prompt

        if llm is None:
            st.error("❌ LLM connection not available. Please refresh configuration.")
            st.session_state.job_status = 'stopped'
            return

        # Apply file descriptor limit increase at start of processing
        if len(st.session_state.file_queue) > 0:
            increase_file_descriptor_limit()

        current_file_info = st.session_state.file_queue[0]
        
        # Check if this is an uploaded file (has file_object) or a discovered file (has path)
        if 'file_object' in current_file_info and current_file_info['file_object'] is not None:
            # Handle uploaded file
            uploaded_file = st.session_state.file_queue.pop(0)
            file_extension = uploaded_file['extension']
            temp_file_path = None

            try:
                # Create a unique temporary file
                with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file_extension}") as tmp:
                    tmp.write(uploaded_file['file_object'].getbuffer())
                    temp_file_path = tmp.name

                file_size = uploaded_file['size'] / 1024 / 1024
                st.write(f"📁 **File:** {uploaded_file['name']} ({file_size:.2f} MB)")

                model_category = classify_model(config['model'])
                category_desc = MODEL_CATEGORIES.get(model_category, {}).get("description", "Unknown")
                st.write(f"🎯 **Using LLM:** {config['model']} ({category_desc})")
                st.write(f"🌍 **Using Embeddings:** {config['embedding_model']}")
                
                # Show GPU info if available
                if st.session_state.gpu_info and st.session_state.gpu_info.get("available", False):
                    st.write(f"⚡ **GPU Optimized:** Batch size = {st.session_state.optimal_batch_size} documents")
                
                # Show processing limits
                st.write(f"🛡️ **Processing:** Batch processing enabled (no truncation)")
                
                # Show response configuration
                response_config = st.session_state.response_config
                st.write(f"📏 **Response Detail:** {response_config.get('detail_level', 'Detailed')} ({response_config.get('max_tokens', 16384):,} tokens)")

                # Process the temporary file with streaming optimization
                process_single_file_streaming(temp_file_path, file_extension, llm, config, ollama_url, analysis_prompt)

            finally:
                # Clean up the temp file
                if temp_file_path and os.path.exists(temp_file_path):
                    try:
                        os.remove(temp_file_path)
                    except Exception as e:
                        st.warning(f"⚠️ Could not delete temp file: {e}")

        else:
            # Handle discovered file from folder selection
            process_file_queue(llm, config, ollama_url, analysis_prompt)

    # --- UPDATED: Enhanced Report Display Logic with Dashboard Features ---
    # MOVED OUTSIDE the processing if block - this is the critical fix!
    if st.session_state.job_status == 'completed' and st.session_state.processed_files:
        
        # Create tabs for different report views
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Executive Summary", "📋 Detailed Reports", "📦 Concatenated Reports", "📈 Statistics & Dashboard"])
        
        with tab1:
            # Display the Executive Summary
            if st.session_state.current_report:
                st.subheader("📊 FINAL DFIR EXECUTIVE SUMMARY")
                st.markdown("**Report Status:** ✅ Analysis completed")
                
                # Show report configuration used
                response_config = st.session_state.response_config
                st.info(f"**Report Configuration:** {response_config.get('detail_level', 'Detailed')} detail level, {response_config.get('max_tokens', 16384):,} max tokens")
                
                st.text_area("Detailed Security Assessment", st.session_state.current_report, height=600, key="executive_report")
                
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                exec_filename = f"dfir_executive_summary_{timestamp}.txt"
                st.download_button(
                    label="📥 Download Executive Summary",
                    data=st.session_state.current_report,
                    file_name=exec_filename,
                    mime="text/plain",
                    key="download_executive"
                )
            else:
                # Generate executive summary if not already generated
                if len(st.session_state.processed_files) > 0:
                    st.info("Generating executive summary...")
                    
                    # Get LLM connection info
                    connection_info = st.session_state.connection_info
                    if connection_info and connection_info.get("llm"):
                        llm = connection_info["llm"]
                        
                        # Generate final summary
                        with st.spinner("Generating comprehensive executive summary..."):
                            final_summary = generate_executive_summary(st.session_state.processed_files, llm)
                        
                        # Enhance response quality
                        if final_summary and hasattr(st.session_state, 'response_config'):
                            min_words_map = {
                                "Brief": 300,
                                "Standard": 800,
                                "Detailed": 1500,
                                "Comprehensive": 2500,
                                "Exhaustive": 4000
                            }
                            min_words = min_words_map.get(
                                st.session_state.response_config.get("detail_level", "Detailed"),
                                1500
                            )
                            final_summary = enhance_response_quality(final_summary, min_words)
                        
                        # Update session state with the final result
                        st.session_state.current_report = final_summary
                        st.session_state.final_summary_generated = True
                        
                        # Rerun to display the final summary
                        st.rerun()
                    else:
                        st.warning("LLM connection not available for generating executive summary")
                else:
                    st.info("No executive summary generated. Processing may have completed without generating a consolidated report.")
        
        with tab2:
            st.subheader("📋 DETAILED FILE REPORTS")
            
            # Filter for successful analyses
            successful_reports = [f for f in st.session_state.processed_files if f.get('status') == 'success']
            skipped_reports = [f for f in st.session_state.processed_files if f.get('status') == 'skipped']
            error_reports = [f for f in st.session_state.processed_files if f.get('status') == 'error']
            
            # Show statistics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Successful", len(successful_reports), delta=None)
            with col2:
                st.metric("Skipped", len(skipped_reports), delta=None)
            with col3:
                st.metric("Errors", len(error_reports), delta=None)
            
            # Create expandable sections for each file
            for i, file_result in enumerate(st.session_state.processed_files):
                file_status = file_result.get('status', 'unknown')
                file_name = file_result.get('name', file_result.get('path', f"File {i+1}"))
                file_size_mb = file_result.get('size', 0) / (1024 * 1024)
                
                # Color code based on status
                if file_status == 'success':
                    status_emoji = "✅"
                    status_color = "green"
                elif file_status == 'skipped':
                    status_emoji = "⏭️"
                    status_color = "orange"
                elif file_status == 'error':
                    status_emoji = "❌"
                    status_color = "red"
                else:
                    status_emoji = "❓"
                    status_color = "gray"
                
                # Create expander for each file
                with st.expander(f"{status_emoji} {file_name} ({file_size_mb:.2f} MB) - {file_status.upper()}", expanded=(i==0)):
                    
                    # File metadata
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.write(f"**Path:** {file_result.get('path', 'N/A')}")
                    with col2:
                        st.write(f"**Size:** {file_size_mb:.2f} MB")
                    with col3:
                        st.write(f"**Status:** {file_status}")
                    
                    # Additional metadata if available
                    if 'rows_ingested' in file_result:
                        st.write(f"**Rows Processed:** {file_result['rows_ingested']:,}")
                    if 'chunks_created' in file_result:
                        st.write(f"**Chunks Created:** {file_result['chunks_created']:,}")
                    if 'chunks_processed' in file_result:
                        st.write(f"**Chunks Processed:** {file_result['chunks_processed']:,}")
                    if 'analysis_timestamp' in file_result:
                        st.write(f"**Analyzed:** {file_result['analysis_timestamp']}")
                    if 'model_used' in file_result:
                        st.write(f"**Model:** {file_result['model_used']}")
                    
                    # Display the report content
                    if file_status == 'success' and file_result.get('report'):
                        st.write("---")
                        st.subheader("Analysis Report")
                        st.text_area(
                            f"Detailed Analysis for {file_name}",
                            file_result['report'],
                            height=400,
                            key=f"detailed_report_{i}"
                        )
                        
                        # Calculate word count
                        word_count = len(file_result['report'].split())
                        st.info(f"**Report Length:** {word_count:,} words")
                        
                        # Individual file download button
                        safe_filename = "".join(c for c in file_name if c.isalnum() or c in (' ', '.', '-', '_')).rstrip()
                        detailed_filename = f"dfir_detailed_{safe_filename}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                        
                        st.download_button(
                            label=f"📥 Download {file_name} Report",
                            data=file_result['report'],
                            file_name=detailed_filename,
                            mime="text/plain",
                            key=f"download_detailed_{i}"
                        )
                    
                    elif file_status == 'error' and 'error_message' in file_result:
                        st.error(f"**Error:** {file_result['error_message']}")
                    
                    elif file_status == 'skipped':
                        st.info(f"**Reason:** {file_result.get('report', 'File was skipped during processing')}")
        
        with tab3:
            st.subheader("📦 CONCATENATED DETAILED REPORTS")
            
            # Create concatenated reports if not already created
            if not st.session_state.concatenated_reports:
                st.session_state.concatenated_reports = create_concatenated_reports()
            
            if st.session_state.concatenated_reports:
                st.info("This is the complete concatenated view of all detailed reports that was fed into the LLM for the executive summary generation.")
                
                # Calculate total word count
                total_words = len(st.session_state.concatenated_reports.split())
                st.info(f"**Total Concatenated Content:** {total_words:,} words")
                
                st.text_area(
                    "All Detailed Reports Combined (Used for Executive Summary)",
                    st.session_state.concatenated_reports,
                    height=600,
                    key="concatenated_view_full"
                )
                
                # Download button for concatenated reports
                concat_filename = f"dfir_all_detailed_reports_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                st.download_button(
                    label="📥 Download All Detailed Reports (Concatenated)",
                    data=st.session_state.concatenated_reports,
                    file_name=concat_filename,
                    mime="text/plain",
                    key="download_all_detailed_concat"
                )
                
                # Show information about the executive summary generation
                if st.session_state.final_summary_generated:
                    st.success("✅ This concatenated report was successfully fed into the LLM to generate the comprehensive executive summary.")
                    st.info("💡 **Note:** The executive summary in Tab 1 is based on this complete context, ensuring all file-specific findings are considered in the final analysis.")
                else:
                    st.warning("⚠️ This concatenated report has not yet been used to generate an executive summary.")
            else:
                st.info("No detailed reports available to concatenate.")
        
        with tab4:
            st.subheader("📈 PROCESSING STATISTICS & DASHBOARD")
            
            # Display resource dashboard
            if st.session_state.resource_history and st.session_state.resource_history['cpu']:
                display_resource_dashboard()
            
            st.write("---")
            
            # Calculate statistics
            total_files = len(st.session_state.processed_files)
            successful = len([f for f in st.session_state.processed_files if f.get('status') == 'success'])
            skipped = len([f for f in st.session_state.processed_files if f.get('status') == 'skipped'])
            errors = len([f for f in st.session_state.processed_files if f.get('status') == 'error'])
            
            # File sizes
            total_size_mb = sum(f.get('size', 0) for f in st.session_state.processed_files) / (1024 * 1024)
            avg_size_mb = total_size_mb / total_files if total_files > 0 else 0
            
            # Rows processed
            total_rows = sum(f.get('rows_ingested', 0) for f in st.session_state.processed_files)
            total_chunks_created = sum(f.get('chunks_created', 0) for f in st.session_state.processed_files)
            total_chunks_processed = sum(f.get('chunks_processed', 0) for f in st.session_state.processed_files)
            
            # Report word counts
            report_words = []
            for file_result in st.session_state.processed_files:
                if file_result.get('status') == 'success' and file_result.get('report'):
                    report_words.append(len(file_result['report'].split()))
            
            avg_report_words = sum(report_words) / len(report_words) if report_words else 0
            total_report_words = sum(report_words)
            
            # Display metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Files", total_files)
                st.metric("Successful", successful, delta=f"{(successful/total_files*100 if total_files>0 else 0):.1f}%")
            with col2:
                st.metric("Total Size", f"{total_size_mb:.1f} MB")
                st.metric("Avg File Size", f"{avg_size_mb:.1f} MB")
            with col3:
                st.metric("Total Rows", f"{total_rows:,}")
                st.metric("Total Chunks", f"{total_chunks_processed:,}")
            with col4:
                st.metric("Total Report Words", f"{total_report_words:,}")
                st.metric("Avg Report Words", f"{avg_report_words:,.0f}")
            
            # Success rate chart
            st.write("---")
            st.subheader("Success Rate")
            
            if total_files > 0:
                import plotly.graph_objects as go
                
                labels = ['Successful', 'Skipped', 'Errors']
                values = [successful, skipped, errors]
                colors = ['#00cc96', '#ffa15a', '#ef553b']
                
                fig = go.Figure(data=[go.Pie(
                    labels=labels, 
                    values=values,
                    hole=.3,
                    marker=dict(colors=colors)
                )])
                
                fig.update_layout(
                    title="File Processing Results",
                    height=400
                )
                
                st.plotly_chart(fig, use_container_width=True)
            
            # File size distribution
            st.write("---")
            st.subheader("File Size Distribution")
            
            if successful_reports:
                file_sizes = [f.get('size', 0) / (1024 * 1024) for f in successful_reports]
                file_names = [f.get('name', f"File {i+1}") for i, f in enumerate(successful_reports)]
                
                # Create bar chart
                fig = go.Figure(data=[
                    go.Bar(
                        x=file_names,
                        y=file_sizes,
                        text=[f"{size:.1f} MB" for size in file_sizes],
                        textposition='auto',
                        marker_color='#636efa'
                    )
                ])
                
                fig.update_layout(
                    title="File Sizes (Successful Analyses)",
                    xaxis_title="File Name",
                    yaxis_title="Size (MB)",
                    height=400,
                    xaxis_tickangle=-45
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                # Report length distribution
                st.write("---")
                st.subheader("Report Length Distribution")
                
                if report_words:
                    fig2 = go.Figure(data=[
                        go.Histogram(
                            x=report_words,
                            nbinsx=20,
                            marker_color='#ef553b',
                            opacity=0.7
                        )
                    ])
                    
                    fig2.update_layout(
                        title="Distribution of Report Word Counts",
                        xaxis_title="Word Count",
                        yaxis_title="Number of Reports",
                        height=400
                    )
                    
                    st.plotly_chart(fig2, use_container_width=True)
                
                # Processing timeline
                st.write("---")
                st.subheader("Processing Timeline")
                
                if 'analysis_timestamp' in st.session_state.processed_files[0]:
                    timeline_data = []
                    for file_result in st.session_state.processed_files:
                        if 'analysis_timestamp' in file_result:
                            try:
                                timestamp = datetime.datetime.fromisoformat(file_result['analysis_timestamp'])
                                timeline_data.append({
                                    'file': file_result.get('name', 'Unknown'),
                                    'timestamp': timestamp,
                                    'status': file_result.get('status', 'unknown'),
                                    'size_mb': file_result.get('size', 0) / (1024 * 1024)
                                })
                            except:
                                continue
                    
                    if timeline_data:
                        # Sort by timestamp
                        timeline_data.sort(key=lambda x: x['timestamp'])
                        
                        # Create timeline visualization
                        timeline_html = """
                        <div style="margin: 20px 0; padding: 20px; background: #f5f5f5; border-radius: 10px;">
                            <h4 style="margin-top: 0;">Processing Timeline</h4>
                        """
                        
                        for item in timeline_data:
                            status_color = {
                                'success': '#28a745',
                                'skipped': '#ffc107',
                                'error': '#dc3545'
                            }.get(item['status'], '#6c757d')
                            
                            time_str = item['timestamp'].strftime("%H:%M:%S")
                            timeline_html += f"""
                            <div style="display: flex; align-items: center; margin: 10px 0; padding: 10px; background: white; border-radius: 5px; border-left: 5px solid {status_color};">
                                <div style="flex: 0 0 80px; font-weight: bold;">{time_str}</div>
                                <div style="flex: 1;">{item['file']}</div>
                                <div style="flex: 0 0 60px; text-align: right; font-weight: bold; color: {status_color};">{item['status'].upper()}</div>
                                <div style="flex: 0 0 80px; text-align: right;">{item['size_mb']:.1f} MB</div>
                            </div>
                            """
                        
                        timeline_html += "</div>"
                        st.markdown(timeline_html, unsafe_allow_html=True)
                
                # Model information
                st.write("---")
                st.subheader("Model Information")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.info(f"**LLM Model:** {config.get('model', 'Not specified')}")
                    if st.session_state.response_config:
                        st.info(f"**Detail Level:** {st.session_state.response_config.get('detail_level', 'Detailed')}")
                with col2:
                    st.info(f"**Embedding Model:** {config.get('embedding_model', 'Not specified')}")
                    if st.session_state.response_config:
                        st.info(f"**Max Tokens:** {st.session_state.response_config.get('max_tokens', 16384):,}")
                
                if st.session_state.gpu_info and st.session_state.gpu_info.get("available", False):
                    st.success(f"**GPU Used:** {st.session_state.gpu_info['name']} ({st.session_state.gpu_info['vram_gb']:.1f}GB VRAM)")
                    st.info(f"**Batch Size:** {st.session_state.optimal_batch_size} documents")
                
                # Processing summary
                st.write("---")
                st.subheader("Processing Summary")
                
                summary_text = f"""
                ## Processing Summary
                
                **Total Execution:** {total_files} files processed
                **Success Rate:** {(successful/total_files*100 if total_files>0 else 0):.1f}%
                **Total Data:** {total_size_mb:.1f} MB
                **Total Report Content:** {total_report_words:,} words
                **Analysis Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                
                **Configuration:**
                - LLM: {config.get('model', 'N/A')}
                - Embeddings: {config.get('embedding_model', 'N/A')}
                - Response Detail: {st.session_state.response_config.get('detail_level', 'Detailed')}
                - Max Tokens: {st.session_state.response_config.get('max_tokens', 16384):,}
                - Ollama: http://{config.get('ollama_host', 'N/A')}:{config.get('ollama_port', 'N/A')}
                
                **Performance:**
                - Average file size: {avg_size_mb:.1f} MB
                - Total rows processed: {total_rows:,}
                - Total chunks created: {total_chunks_created:,}
                - Total chunks processed: {total_chunks_processed:,}
                - Average report length: {avg_report_words:,.0f} words
                - Batch processing: ENABLED (no truncation)
                """
                
                st.markdown(summary_text)
                
                # Download statistics report
                stats_report = f"""FORENSIQ PROCESSING STATISTICS REPORT
    Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    SUMMARY
    =======
    Total Files Processed: {total_files}
    Successful Analyses: {successful} ({(successful/total_files*100 if total_files>0 else 0):.1f}%)
    Skipped Files: {skipped}
    Errors: {errors}

    Total Data Size: {total_size_mb:.1f} MB
    Average File Size: {avg_size_mb:.1f} MB
    Total Rows Processed: {total_rows:,}
    Total Chunks Created: {total_chunks_created:,}
    Total Chunks Processed: {total_chunks_processed:,}
    Total Report Words: {total_report_words:,}
    Average Report Words: {avg_report_words:,.0f}

    CONFIGURATION
    =============
    LLM Model: {config.get('model', 'N/A')}
    Embedding Model: {config.get('embedding_model', 'N/A')}
    Response Detail: {st.session_state.response_config.get('detail_level', 'Detailed')}
    Max Tokens: {st.session_state.response_config.get('max_tokens', 16384)}
    Ollama URL: http://{config.get('ollama_host', 'N/A')}:{config.get('ollama_port', 'N/A')}

    BATCH PROCESSING
    ================
    Batch Size: {st.session_state.batch_settings['documents_per_batch']} documents
    Max Retrieved: {st.session_state.batch_settings['max_retrieved_docs']} documents
    Truncation: DISABLED (all data processed)

    GPU INFORMATION
    ===============
    """
                
                if st.session_state.gpu_info and st.session_state.gpu_info.get("available", False):
                    stats_report += f"""GPU: {st.session_state.gpu_info['name']}
    VRAM: {st.session_state.gpu_info['vram_gb']:.1f} GB
    Optimal Batch Size: {st.session_state.optimal_batch_size} documents
    """
                else:
                    stats_report += "GPU: Not available (CPU mode)\n"
                
                stats_report += f"""
    DETAILED FILE RESULTS
    =====================
    """
                
                for i, file_result in enumerate(st.session_state.processed_files):
                    report_words = len(file_result.get('report', '').split()) if file_result.get('report') else 0
                    stats_report += f"""
    File {i+1}: {file_result.get('path', 'N/A')}
      Status: {file_result.get('status', 'unknown')}
      Size: {file_result.get('size', 0) / (1024 * 1024):.1f} MB
      Rows: {file_result.get('rows_ingested', 'N/A')}
      Chunks Created: {file_result.get('chunks_created', 'N/A')}
      Chunks Processed: {file_result.get('chunks_processed', 'N/A')}
      Report Words: {report_words:,}
      Timestamp: {file_result.get('analysis_timestamp', 'N/A')}
    """
                
                st.download_button(
                    label="📊 Download Statistics Report",
                    data=stats_report,
                    file_name=f"dfir_statistics_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    key="download_statistics"
                )
    # --- END UPDATED REPORT DISPLAY LOGIC ---

    # Footer
    st.write("---")
    st.markdown("<div style='text-align: center;'>Powered by <a href='https://dfirvault.com' target='_blank'>DFIR Vault</a></div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
