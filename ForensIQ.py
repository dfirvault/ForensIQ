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
import chromadb
import requests
import subprocess
import json
import time
from pathlib import Path

# Import for folder picker
import shutil
import tempfile
import tkinter as tk
from tkinter import filedialog

print("")
print("Developed by Jacob Wilson")
print("dfirvault@gmail.com")
print("")

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

# --- UPDATED: Default "Reduce" Prompt ---
DEFAULT_DFIR_PROMPT = """You are a senior DFIR (Digital Forensics and Incident Response) analyst with 15+ years of experience.

You will be given several summaries of threats found in different log chunks. Your job is to combine these summaries into one comprehensive, final report.

Provide a comprehensive security assessment with the following sections, based *only* on the context provided:

1.  **EXECUTIVE SUMMARY:** High-level overview of findings.
2.  **KEY FINDINGS:** Specific security events detected.
3.  **SEVERITY ASSESSMENT:** Critical/High/Medium/Low ratings with justification.
4.  **INDICATORS OF COMPROMISE:** Specific IOCs identified (IPs, hashes, filenames, user accounts).
5.  **RECOMMENDATIONS:** Concrete steps for investigation and remediation.
6.  **TIMELINE:** Chronological sequence of notable events (if detectable).

Be thorough, professional, and focus on actionable intelligence. If no clear threats are found, state so clearly.

Context (Summaries from Log Chunks): {context}

Question: {question}
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
    
    # Check file size (avoid processing huge non-log files)
    try:
        file_size = file_path.stat().st_size
        if file_size > 500 * 1024 * 1024:  # Increased to 500MB limit
            return False
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
        config['dfir_prompt'] = DEFAULT_DFIR_PROMPT
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
            config['dfir_prompt'] = DEFAULT_DFIR_PROMPT

        # --- FIX for old, un-escaped prompts ---
        # If the loaded prompt is just the *first line*, it's an old file.
        # Reset it to default. The user can re-save from the UI.
        if 'You are a senior DFIR' in config['dfir_prompt'] and len(config['dfir_prompt']) < 100:
            st.warning("Old config.txt format detected. Resetting prompt to default.")
            config['dfir_prompt'] = DEFAULT_DFIR_PROMPT
        # --- END FIX ---

        # Re-save to add missing keys and fix prompt format
        save_config(config)
            
    return config

# --- UPDATED: save_config() with JSON fix ---
def save_config(config):
    # We must use json.dumps to escape newlines and special chars
    # so the prompt is saved as a single, valid JSON string line.
    prompt = config.pop('dfir_prompt', DEFAULT_DFIR_PROMPT)
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

# --- NEW: File Picker Helper Function ---
def select_files():
    """Opens a Tcl/Tk file dialog to select multiple files."""
    try:
        root = tk.Tk()
        root.withdraw()  # Hide the main tkinter window
        root.attributes('-topmost', True)  # Bring the dialog to the front
        file_paths = filedialog.askopenfilenames(
            master=root,
            title="Select log files",
            filetypes=[("Log files", "*.csv *.evtx *.log *.txt *.json *.xml *.syslog"), ("All files", "*.*")]
        )
        root.destroy()
        return list(file_paths)
    except Exception as e:
        st.error(f"Error opening file dialog: {e}")
        return None

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
        "quality": "🏆"
    }.get(category, "🔹")
    
    category_desc = MODEL_CATEGORIES.get(category, {}).get("description", "Other")
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
            recommended_model = get_gpu_recommendation()[0]
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

def refresh_ollama_connection(config):
    """Refresh Ollama connection with current config"""
    ollama_url = f"http://{config['ollama_host']}:{config['ollama_port']}"
    try:
        available_models = get_available_models(ollama_url)
        recommended_models = get_recommended_models(available_models)
        
        llm = OllamaLLM(model=config['model'], base_url=ollama_url)
        
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
                    st.warning(f"Could not process file {file_path}: {e}")
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
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        log_lines = []
        for line in lines:
            if any(pattern in line.lower() for pattern in ['error', 'warn', 'info', 'debug', 'exception', 'failed', 'login', 'access']):
                log_lines.append(line.strip())
        
        if log_lines:
            df = pd.DataFrame({
                'timestamp': [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * len(log_lines),
                'message': log_lines,
                'file': [os.path.basename(file_path)] * len(log_lines)
            })
            return df
        else:
            return None
            
    except Exception as e:
        st.warning(f"Could not process text file {file_path}: {e}")
        return None

def process_json_file(file_path):
    """Process JSON log files"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        
        if isinstance(data, list):
            df = pd.DataFrame(data)
        else:
            df = pd.DataFrame([data])
        
        if not df.empty:
            df = df[df.apply(lambda row: row.astype(str).str.contains('login|error|access|failed|security|audit|authentication|denied|warning|alert', case=False, na=False).any(), axis=1)]
            if not df.empty:
                df['file'] = os.path.basename(file_path)
                return df
        
        return None
        
    except Exception as e:
        st.warning(f"Could not process JSON file {file_path}: {e}")
        return None

# --- UPDATED: Enhanced ingest_logs function ---
def ingest_logs(file_path, file_type=None):
    try:
        if file_type is None:
            file_type = Path(file_path).suffix.lower()
        
        # Handle files without extensions or unknown extensions
        if file_type == '' or file_type not in SUPPORTED_EXTENSIONS:
            st.write(f"🔍 Detecting file type for: {os.path.basename(file_path)}")
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
        
        st.write(f"📄 Processing as {SUPPORTED_EXTENSIONS.get(file_type, 'Text File')}...")
        
        if file_type == '.csv':
            st.write("📊 Processing CSV file...")
            df = pd.read_csv(
                file_path,
                delimiter=',',
                quoting=3,
                encoding='utf-8',
                on_bad_lines='skip',
                engine='python'
            )
            st.write(f"📈 Loaded {len(df)} rows from CSV")
            
            st.write("🔍 Filtering for security-related events...")
            initial_count = len(df)
            df = df[df.apply(lambda row: row.astype(str).str.contains('login|error|access|failed|security|audit|authentication|denied|warning|alert', case=False, na=False).any(), axis=1)]
            filtered_count = len(df)
            st.write(f"✅ Filtered to {filtered_count} security-relevant rows (from {initial_count} total)")
            
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
                        'file': os.path.basename(file_path)
                    })
            
            df = pd.DataFrame(events)
            st.write(f"✅ Extracted {len(df)} security-related Windows events")
            
        elif file_type == '.json':
            df = process_json_file(file_path)
            if df is not None:
                st.write(f"✅ Processed JSON file with {len(df)} security-relevant entries")
            else:
                st.write("ℹ️ No security-relevant data found in JSON file")
                
        elif file_type in ['.log', '.txt', '.syslog', '']:  # Added '' for no extension
            df = process_text_file(file_path)
            if df is not None:
                st.write(f"✅ Processed text file with {len(df)} security-relevant lines")
            else:
                st.write("ℹ️ No security-relevant data found in text file")
                
        elif file_type == '.xml':
            df = process_text_file(file_path)
            if df is not None:
                st.write(f"✅ Processed XML file with {len(df)} security-relevant entries")
            else:
                st.write("ℹ️ No security-relevant data found in XML file")
                
        else:
            st.warning(f"Unsupported file type: {file_type}")
            return None
        
        return df
    except Exception as e:
        st.error(f"❌ Error reading log file {file_path}: {str(e)}")
        return None

def chunk_logs(df):
    try:
        st.write("✂️ Chunking log data for processing...")
        
        text = df.to_string(index=False)
        
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

def build_vector_store(chunks, config, ollama_url):
    # --- NEW: Create a unique temporary directory ---
    persist_directory = tempfile.mkdtemp()
    st.write(f"🔧 Using temporary vector store directory: {persist_directory}")
    # --- END NEW ---

    try:
        st.write("🔧 Building vector store for semantic search...")

        st.write(f"🌍 Using local embedding model: {config['embedding_model']}")
        try:
            embeddings = OllamaEmbeddings(
                model=config['embedding_model'],
                base_url=ollama_url
            )
            _ = embeddings.embed_query("Test embedding")
        except Exception as e:
            st.error(f"❌ Error initializing Ollama embeddings: {e}")
            st.error(f"💡 Make sure you have the model installed locally. Try: `ollama pull {config['embedding_model']}`")
            # --- NEW: Clean up directory on embedding failure ---
            if os.path.exists(persist_directory):
                shutil.rmtree(persist_directory)
            # --- END NEW ---
            return None, None # Return None for both store and dir

        docs = [Document(page_content=chunk) for chunk in chunks]
        st.write(f"📚 Creating embeddings for {len(docs)} documents...")

        collection_name = "log_analysis" # Can use a fixed name now

        # --- UPDATED: Use persist_directory ---
        vectorstore = Chroma.from_documents(
            docs,
            embeddings,
            collection_name=collection_name,
            persist_directory=persist_directory # Use the temp dir
        )
        # --- END UPDATE ---

        st.write("✅ Vector store created successfully!")
        # --- UPDATED: Return directory path for cleanup ---
        return vectorstore, persist_directory

    except Exception as e:
        st.error(f"❌ Error initializing ChromaDB vector store: {str(e)}")
        # --- NEW: Clean up directory on general failure ---
        if os.path.exists(persist_directory):
            shutil.rmtree(persist_directory)
        # --- END NEW ---
        return None, None # Return None for both

# --- NEW, FASTER "MAP REDUCE" VERSION ---
def analyze_logs(vectorstore, llm, user_prompt_template):
    if vectorstore is None:
        return None
    try:
        st.write("🤖 Starting AI analysis with 'Map Reduce'...")

        # --- 1. VALIDATE PROMPT ---
        if "{context}" not in user_prompt_template or "{question}" not in user_prompt_template:
            st.error("❌ Prompt Error: The prompt template must include `{context}` and `{question}` placeholders.")
            return "Analysis failed: Prompt template is missing required placeholders."

        # --- 2. "MAP" STEP ---
        # This prompt will be sent to the LLM for EACH chunk in parallel.
        map_prompt_template = """
        You are a DFIR analyst. Your job is to find security incidents in a single log chunk.
        Analyze the log data below and list ONLY the key findings, potential IOCs, and any suspicious activity.
        If no threats are found, just say "No suspicious activity noted in this chunk."

        Log Data:
        {context}
        """
        map_prompt = ChatPromptTemplate.from_template(map_prompt_template)
        retriever = vectorstore.as_retriever(search_kwargs={"k": 5})

        # This is the "Map" chain.
        # It retrieves docs, then runs the `map_prompt | llm` on EACH doc in parallel.
        map_chain = (
            retriever
            | RunnableLambda(lambda docs: [{"context": doc.page_content} for doc in docs])
            | map_prompt.map() # .map() runs the prompt on each item in the list
            | llm.map()        # .map() runs the LLM on each prompt output
        )
        
        # --- 3. "REDUCE" STEP ---
        # This prompt combines the parallel summaries into the final report.
        # We re-use your main prompt from the config.
        reduce_prompt = ChatPromptTemplate.from_template(user_prompt_template)

        # This chain runs the "Map" step first, then...
        # 1. Takes the list of parallel summaries
        # 2. Joins them into a single string
        # 3. Passes them as "context" to your final "Reduce" prompt.
        chain = (
            map_chain
            | RunnableLambda(lambda summaries: "\n\n---\n\n".join([s.content if hasattr(s, 'content') else str(s) for s in summaries]))
            | {"context": RunnablePassthrough(), "question": RunnablePassthrough()}
            | reduce_prompt
            | llm
        )

        with st.spinner("🧠 AI analysis in progress... (Parallel Map Reduce)"):
            # We ask a general question, as the prompts are now hard-coded for this strategy
            result = chain.invoke("Analyze these logs thoroughly for any security incidents, anomalies, or signs of compromise.")
        
        # --- 4. FORMAT OUTPUT ---
        if hasattr(result, 'content'):
            return str(result.content)
        elif hasattr(result, 'text'):
            return str(result.text)
        elif isinstance(result, str):
            return result
        else:
            return str(result) if result else 'No result returned from analysis.'
            
    except Exception as e:
        st.error(f"❌ Error during analysis: {str(e)}")
        return f"Analysis failed for this file: {str(e)}"

def process_single_file(file_path, file_extension, llm, config, ollama_url, analysis_prompt):
    """Process a single file through the analysis pipeline"""
    vectorstore = None
    persist_dir = None # Initialize directory path
    try:
        with st.status("🚀 Processing pipeline started...", expanded=True) as status:
            status.write("📥 **Step 1:** Ingesting log file...")
            df = ingest_logs(file_path, file_type=f".{file_extension}")

            if st.session_state.job_status != 'running':
                status.write("⏹️ Analysis stopped by user")
                return

            if df is not None and not df.empty:
                status.write("✅ **Step 1 Complete:** Log ingestion successful")

                status.write("✂️ **Step 2:** Chunking data for analysis...")
                chunks = chunk_logs(df)

                if st.session_state.job_status != 'running':
                    status.write("⏹️ Analysis stopped by user")
                    return

                if chunks:
                    status.write("✅ **Step 2 Complete:** Data chunking successful")

                    status.write("🔧 **Step 3:** Building semantic search index...")
                    # --- UPDATED: Get persist_dir back ---
                    vectorstore, persist_dir = build_vector_store(chunks, config, ollama_url)

                    if st.session_state.job_status != 'running':
                        status.write("⏹️ Analysis stopped by user")
                        # No explicit cleanup here, finally block handles it
                        return

                    if vectorstore: # Check if build was successful
                        status.write("✅ **Step 3 Complete:** Vector store ready")

                        status.write("🤖 **Step 4:** AI analysis with DFIR expert...")
                        report = analyze_logs(vectorstore, llm, analysis_prompt)

                        if st.session_state.job_status != 'running':
                            status.write("⏹️ Analysis stopped by user")
                            # No explicit cleanup here, finally block handles it
                            return

                        if report:
                            status.write("✅ **Step 4 Complete:** Analysis complete!")
                            st.session_state.current_report = report
                            st.session_state.job_status = 'completed'
                            # No explicit cleanup here, finally block handles it before rerun
                            st.rerun()

                        # No explicit vectorstore deletion needed now
                        # st.info("🧹 Temporary data cleaned up") # Cleanup happens in finally

                st.success("🎉 Analysis pipeline completed successfully!")

            else:
                st.warning("⚠️ No relevant log data found or file is empty.")
                st.session_state.job_status = 'completed'
                st.rerun()

    except Exception as e:
        st.error(f"❌ Error during analysis: {str(e)}")
        st.session_state.job_status = 'stopped'
        # Rerun will happen after finally block

    finally:
        # --- NEW: Ensure temporary directory is always cleaned up ---
        if persist_dir and os.path.exists(persist_dir):
            try:
                shutil.rmtree(persist_dir)
                st.info(f"🧹 Temporary vector store directory '{persist_dir}' deleted.")
            except Exception as del_e:
                st.warning(f"⚠️ Could not delete temporary directory '{persist_dir}': {del_e}")
        # Need to rerun here if an error occurred to update UI state correctly
        if st.session_state.job_status == 'stopped':
             st.rerun()
        # --- END NEW ---

def process_file_queue(llm, config, ollama_url, analysis_prompt):
    """Process multiple files from the queue"""
    if not st.session_state.file_queue:
        st.session_state.job_status = 'completed'
        st.success("🎉 All files processed successfully!")
        st.rerun()
        return

    current_file_info = st.session_state.file_queue.pop(0)
    file_path = current_file_info['path']
    file_extension = current_file_info['extension']

    st.write(f"📁 **Processing:** {current_file_info['relative_path']} ({current_file_info['size'] / 1024:.2f} KB)")

    model_category = classify_model(config['model'])
    category_desc = MODEL_CATEGORIES.get(model_category, {}).get("description", "Unknown")
    st.write(f"🎯 **Using Model:** {config['model']} ({category_desc})")

    vectorstore = None
    persist_dir = None # Initialize directory path
    try:
        with st.status(f"🚀 Processing {current_file_info['name']}...", expanded=True) as status:
            status.write("📥 **Step 1:** Ingesting log file...")
            df = ingest_logs(file_path, file_type=file_extension)

            if st.session_state.job_status != 'running':
                status.write("⏹️ Analysis stopped by user")
                st.session_state.file_queue.insert(0, current_file_info)
                # No explicit cleanup here, finally block handles it
                st.rerun()
                return

            if df is not None and not df.empty:
                status.write("✅ **Step 1 Complete:** Log ingestion successful")

                status.write("✂️ **Step 2:** Chunking data for analysis...")
                chunks = chunk_logs(df)

                if st.session_state.job_status != 'running':
                    status.write("⏹️ Analysis stopped by user")
                    st.session_state.file_queue.insert(0, current_file_info)
                    # No explicit cleanup here, finally block handles it
                    st.rerun()
                    return

                if chunks:
                    status.write("✅ **Step 2 Complete:** Data chunking successful")

                    status.write("🔧 **Step 3:** Building semantic search index...")
                    # --- UPDATED: Get persist_dir back ---
                    vectorstore, persist_dir = build_vector_store(chunks, config, ollama_url)

                    if st.session_state.job_status != 'running':
                        status.write("⏹️ Analysis stopped by user")
                        st.session_state.file_queue.insert(0, current_file_info)
                        # No explicit cleanup here, finally block handles it
                        st.rerun()
                        return

                    if vectorstore: # Check if build succeeded
                        status.write("✅ **Step 3 Complete:** Vector store ready")

                        status.write("🤖 **Step 4:** AI analysis with DFIR expert...")
                        report = analyze_logs(vectorstore, llm, analysis_prompt)

                        if st.session_state.job_status != 'running':
                            status.write("⏹️ Analysis stopped by user")
                            st.session_state.file_queue.insert(0, current_file_info)
                             # No explicit cleanup here, finally block handles it
                            st.rerun()
                            return

                        if report:
                            status.write("✅ **Step 4 Complete:** Analysis complete!")

                            report_str = str(report) if not isinstance(report, str) else report
                            file_header = f"\n\n{'='*80}\nFILE: {current_file_info['relative_path']}\n{'='*80}\n"

                            if st.session_state.current_report:
                                st.session_state.current_report += file_header + report_str
                            else:
                                st.session_state.current_report = f"BULK ANALYSIS REPORT\nGenerated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nTotal Files: {len(st.session_state.processed_files) + len(st.session_state.file_queue) + 1}\n{file_header}{report_str}"

                            st.session_state.processed_files.append(current_file_info)

                        # No explicit vectorstore deletion needed now

                status.write("✅ File processing completed!")

            else:
                status.write("ℹ️ No relevant data found in this file.")
                st.session_state.processed_files.append(current_file_info) # Mark as processed even if empty

    except Exception as e:
        st.error(f"❌ Error processing {current_file_info['name']}: {str(e)}")
        st.session_state.processed_files.append(current_file_info) # Mark as processed even on error
        # Let the finally block handle cleanup before deciding next step

    finally:
        # --- NEW: Ensure temporary directory is always cleaned up ---
        if persist_dir and os.path.exists(persist_dir):
            try:
                shutil.rmtree(persist_dir)
                st.info(f"🧹 Temporary vector store directory '{persist_dir}' deleted.")
            except Exception as del_e:
                st.warning(f"⚠️ Could not delete temporary directory '{persist_dir}': {del_e}")
        # --- END NEW ---

        # Continue with next file or complete only AFTER cleanup
        if st.session_state.job_status == 'running': # Only proceed if not stopped
            if st.session_state.file_queue:
                st.rerun() # Continue with next file
            else:
                # All files processed - update status and show final report
                st.session_state.job_status = 'completed'
                st.success("🎉 All files processed successfully!")
                st.rerun() # Force UI to show the completed state and report
        elif st.session_state.job_status == 'stopped': # If stopped during processing
             st.warning("Analysis stopped by user during file processing.")
             st.rerun() # Update UI to reflect stopped state

def main():
    # Set page config. This MUST be the first Streamlit command.
    st.set_page_config(
        page_title="ForensIQ",
        page_icon="🧠",
        layout="wide"
    )

    # Updated title and subtitle
    st.title("🧠 ForensIQ")
    st.write("AI-powered log analysis, brought to you by **[DFIR Vault](https://dfirvault.com)**.")

    # Initialize session state
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
    # --- NEW: Initialize selected_folders list ---
    if 'selected_folders' not in st.session_state:
        st.session_state.selected_folders = []
    # --- NEW: Initialize selected_files list for multiple file selection ---
    if 'selected_files' not in st.session_state:
        st.session_state.selected_files = []
    # --- END NEW ---

    config = st.session_state.config

    # Configuration section (NO CHANGES IN THIS SECTION)
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
            st.success(f"✅ GPU Detected: {st.session_state.gpu_info['name']}")
            st.write(f"- **VRAM:** {st.session_state.gpu_info['vram_gb']:.1f} GB")
            st.write(f"- **Recommended Model:** {st.session_state.gpu_info['recommended_model']}")

            if st.button("🎯 Use Recommended GPU Model", use_container_width=True):
                config['model'] = st.session_state.gpu_info['recommended_model']
                save_config(config)
                st.session_state.config = config
                st.session_state.connection_info = None
                st.success(f"Model set to {config['model']} for GPU optimization!")
        else:
            st.warning("⚠️ No GPU detected - using CPU mode")
            st.info("💡 For faster analysis, ensure you have a compatible GPU and drivers installed")

        # Refresh models button
        col1, col2 = st.columns([3, 1])
        with col2:
            if st.button("🔄 Refresh Models", use_container_width=True):
                st.session_state.connection_info = None
                try:
                    st.session_state.gpu_info = detect_gpu()
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

                for category in ["gpu_optimized", "very_fast", "fast", "balanced", "quality"]:
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
                    for category in ["gpu_optimized", "very_fast", "fast", "balanced"]:
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

                for category in ["gpu_optimized", "very_fast", "fast", "balanced", "quality"]:
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
            height=350,
            key="prompt_editor",
            help="The LLM prompt template. {context} and {question} are required."
        )

        if st.button("💾 Save Prompt to Config", use_container_width=True):
            if "{context}" not in st.session_state.prompt_editor or "{question}" not in st.session_state.prompt_editor:
                st.error("❌ Cannot save: Prompt must include `{context}` and `{question}` placeholders.")
            else:
                config['dfir_prompt'] = st.session_state.prompt_editor
                save_config(config)
                st.session_state.config = config # Refresh session state config
                st.success("✅ Prompt saved to config.txt!")

    config['last_run'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Save config without prompt, as prompt is saved separately
    config_copy = config.copy()
    config_copy.pop('dfir_prompt', None)
    save_config(config_copy)
    config['dfir_prompt'] = st.session_state.prompt_editor # Ensure runtime config has latest
    st.session_state.config = config

    # --- START OF FILE UPLOAD & ANALYSIS SECTION ---

    log_files = [] # Initialize list for discovered files across all selected folders
    total_discovered_size = 0 # Initialize total size
    st.subheader("📁 File Upload & Analysis")

    upload_option = st.radio(
        "Select upload type:",
        ["Single File", "Multiple Files", "Folder (Bulk Analysis)"],
        horizontal=True,
        key="upload_option_radio" # Add key to reset state on change
    )

    # --- Clear selection lists when switching options ---
    if upload_option != "Folder (Bulk Analysis)" and st.session_state.selected_folders:
         st.session_state.selected_folders = []
    if upload_option != "Multiple Files" and st.session_state.selected_files:
         st.session_state.selected_files = []

    if upload_option == "Single File":
        # Allow all files but use our content detection to filter
        uploaded_file = st.file_uploader(
            "Choose a log file",
            type=None,  # Allow all files
            help="All files are accepted. The application will detect if it's a readable log file.",
            accept_multiple_files=False,
            key="single_file_uploader"
        )
        
        if uploaded_file:
            # Check if the file is readable text
            try:
                # Try to read the first few bytes to check if it's text
                content = uploaded_file.getvalue()
                try:
                    # Try to decode as UTF-8
                    content.decode('utf-8')
                    is_text_file = True
                except UnicodeDecodeError:
                    # Try other common encodings
                    for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
                        try:
                            content.decode(encoding)
                            is_text_file = True
                            break
                        except UnicodeDecodeError:
                            continue
                    else:
                        is_text_file = False
                
                if is_text_file:
                    file_info = {
                        'path': None,
                        'name': uploaded_file.name,
                        'extension': uploaded_file.name.split('.')[-1].lower() if '.' in uploaded_file.name else '',
                        'size': len(content),
                        'relative_path': uploaded_file.name,
                        'file_object': uploaded_file
                    }
                    st.session_state.selected_files = [file_info]
                    st.success(f"✅ {uploaded_file.name} - File accepted (readable text)")
                else:
                    st.error(f"❌ {uploaded_file.name} - File appears to be binary or unreadable")
                    st.session_state.selected_files = []
                    
            except Exception as e:
                st.error(f"❌ Error checking file: {e}")
                st.session_state.selected_files = []
        else:
            st.session_state.selected_files = []

    elif upload_option == "Multiple Files":
        # Allow all files but use our content detection to filter
        uploaded_files = st.file_uploader(
            "Choose log files",
            type=None,  # Allow all files
            help="All files are accepted. The application will detect if they're readable log files.",
            accept_multiple_files=True,
            key="multiple_file_uploader"
        )
        
        if uploaded_files:
            valid_files = []
            invalid_files = []
            
            for uploaded_file in uploaded_files:
                try:
                    content = uploaded_file.getvalue()
                    # Try to detect if it's a text file
                    try:
                        content.decode('utf-8')
                        is_text_file = True
                    except UnicodeDecodeError:
                        # Try other encodings
                        for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
                            try:
                                content.decode(encoding)
                                is_text_file = True
                                break
                            except UnicodeDecodeError:
                                continue
                        else:
                            is_text_file = False
                    
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
                st.write("**Accepted Files:**")
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
                    st.rerun() # Rerun to update the displayed list and file discovery

        with col2:
             if st.button("🗑️ Clear Folders", use_container_width=True, disabled=not st.session_state.selected_folders):
                 st.session_state.selected_folders = []
                 st.rerun() # Rerun to clear the list and file discovery

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
                        # --- Update relative paths to include base folder for clarity ---
                        for file_info in discovered:
                             relative_base = Path(folder_path).name # Get the last part of the folder path
                             file_info['relative_path'] = str(Path(relative_base) / file_info['relative_path'])
                        # --- End Update ---
                        all_discovered_files.extend(discovered)
                        total_discovered_size += size
                    else:
                         st.error(f"Selected path does not exist: `{folder_path}`")

                log_files = all_discovered_files # Assign combined list

            if log_files:
                st.success(f"✅ Found **{len(log_files)}** log files ({total_discovered_size / 1024 / 1024:.2f} MB total) across all selected folders.")
                with st.expander("📋 View All Discovered Files"):
                    for file_info in log_files:
                        st.write(f"- {file_info['relative_path']} ({file_info['size'] / 1024:.2f} KB)")
            else:
                st.warning("⚠️ No supported log files found in the selected folder(s).")
        else:
            st.warning("No folders selected.")

        uploaded_file = None # Not used in folder mode
        # --- END MULTI-FOLDER LOGIC ---

    # --- START OF JOB CONTROL SECTION ---
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        # Check uses combined log_files list from multi-folder discovery OR selected_files
        has_files_to_process = (
            (len(st.session_state.selected_files) > 0) or 
            (len(st.session_state.file_queue) > 0) or 
            (len(log_files) > 0)
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
                if len(st.session_state.selected_files) > 0 and not st.session_state.file_queue:
                    # Convert uploaded files to the same format as discovered files
                    file_queue = []
                    for file_info in st.session_state.selected_files:
                        queue_info = {
                            'path': None,  # Will be handled in processing
                            'name': file_info['name'],
                            'extension': file_info['extension'],
                            'size': file_info['size'],
                            'relative_path': file_info['relative_path'],
                            'file_object': file_info['file_object']
                        }
                        file_queue.append(queue_info)
                    
                    st.session_state.file_queue = file_queue
                    st.session_state.processed_files = []
                    st.success(f"📋 Queued {len(file_queue)} files for analysis!")

                elif len(log_files) > 0 and not st.session_state.file_queue:
                    st.session_state.file_queue = log_files
                    st.session_state.processed_files = []
                    st.success(f"📋 Queued {len(log_files)} files from selected folder(s) for analysis!")

                st.session_state.job_status = 'running'
                st.session_state.current_report = None
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
                st.session_state.selected_folders = [] # Clear selected folders
                st.session_state.selected_files = [] # Clear selected files
                st.rerun()

    with col3:
        if st.session_state.file_queue:
            remaining = len(st.session_state.file_queue)
            if st.button(f"🗑️ Clear Queue ({remaining})", use_container_width=True, type="secondary"):
                st.session_state.file_queue = []
                st.session_state.processed_files = []
                st.rerun()

    # Display job status
    status_emoji = {
        'idle': '⏸️',
        'running': '🔄',
        'completed': '✅',
        'stopped': '⏹️'
    }

    st.write(f"**Job Status:** {status_emoji[st.session_state.job_status]} {st.session_state.job_status.upper()}")

    if st.session_state.current_file:
        st.write(f"**Current File:** {st.session_state.current_file}")

    if st.session_state.file_queue or st.session_state.processed_files:
        total_processed = len(st.session_state.processed_files)
        total_queued = len(st.session_state.file_queue)
        st.write(f"**Queue Status:** {total_processed} processed, {total_queued} remaining")

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

        # Process the file queue (handles both uploaded files and discovered files)
        current_file_info = st.session_state.file_queue[0]  # Peek at next file
        
        # Check if this is an uploaded file (has file_object) or a discovered file (has path)
        if 'file_object' in current_file_info and current_file_info['file_object'] is not None:
            # Handle uploaded file (Single or Multiple Files option)
            uploaded_file = current_file_info['file_object']
            file_extension = current_file_info['extension']
            temp_file_path = None

            try:
                # Create a unique temporary file
                with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file_extension}") as tmp:
                    tmp.write(uploaded_file.getbuffer())
                    temp_file_path = tmp.name

                file_size = current_file_info['size'] / 1024 / 1024
                st.write(f"📁 **File:** {current_file_info['name']} ({file_size:.2f} MB)")

                model_category = classify_model(config['model'])
                category_desc = MODEL_CATEGORIES.get(model_category, {}).get("description", "Unknown")
                st.write(f"🎯 **Using LLM:** {config['model']} ({category_desc})")
                st.write(f"🌍 **Using Embeddings:** {config['embedding_model']}")

                # Process the temporary file
                process_single_file(temp_file_path, file_extension, llm, config, ollama_url, analysis_prompt)

            finally:
                # Clean up the temp file
                if temp_file_path and os.path.exists(temp_file_path):
                    os.remove(temp_file_path)

        else:
            # Handle discovered file from folder selection (has path)
            process_file_queue(llm, config, ollama_url, analysis_prompt)

    # Display previous report
    elif st.session_state.current_report and st.session_state.job_status in ['completed', 'stopped']:
        st.subheader("📊 DFIR Analysis Report")
        st.text_area("Detailed Security Assessment", st.session_state.current_report, height=500, key="previous_report")

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dfir_report_{timestamp}.txt"
        st.download_button(
            label="📥 Download Report",
            data=st.session_state.current_report,
            file_name=filename,
            mime="text/plain",
            key="download_previous"
        )

    # Footer
    st.write("---")
    st.markdown("<div style='text-align: center;'>Powered by <a href='https://dfirvault.com' target='_blank'>DFIR Vault</a></div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
