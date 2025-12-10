@echo off
setlocal ENABLEDELAYEDEXPANSION

echo Checking for config.txt...

REM --- Check for config.txt in the current directory ---
if exist "config.txt" (
    echo config.txt found.
    echo Starting Streamlit service...
    start "" streamlit run Forensiq.py
    goto :EOF
) else (
    echo config.txt NOT found.
    echo Installing required packages first...
    pip install --upgrade langchain langchain-community langchain-ollama langchain-huggingface sentence-transformers chromadb pandas streamlit psutil pynvmlpython-evtx

    echo Starting Streamlit service...
    start "" streamlit run Forensiq.py
    goto :EOF
)
