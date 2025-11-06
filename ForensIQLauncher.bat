@echo off
echo Installing required packages...
pip install --upgrade langchain langchain-community langchain-ollama langchain-huggingface sentence-transformers chromadb pandas streamlit python-evtx
start ""  streamlit run Forensiq.py