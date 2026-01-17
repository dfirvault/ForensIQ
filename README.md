![1513a619-6193-4a40-ae8d-f9019696df76 (1)](https://github.com/user-attachments/assets/182c042e-6379-49f1-b037-b3f10e545cca)

# ForensIQ

**ForensIQ** is a fast, accurate, and modern digital forensics automation tool designed for incident responders, DFIR analysts, and cybersecurity investigators. This redesigned version focuses on speed, accuracy, and improved usability while maintaining powerful forensic capabilities. This tool requires an Ollama service running locally or on a computer that your Windows computer can connect to. Installing Ollama is very simple and easy. For this tool, just input the IP of the device that runs your Ollama LLM (local or remote).

---

## 🚀 Features

- **Faster Analysis:** Optimized for speed to process large datasets efficiently.
- **Accurate Investigations:** Enhanced detection and parsing for forensic artifacts.
- **Multi-Format Support:** Handles multiple file types and system logs seamlessly.
- **Command-Line Friendly:** Fully scriptable for automation and integration into workflows.
- **Detailed Reporting:** Generates structured outputs for easy review and incident documentation.
- **Intuitive Logging:** Logs actions, errors, and results for audit and troubleshooting.
- **Extensible:** Modular design allows adding new parsing modules and data sources.

---

## 🛠 Installation

1. Clone the repository:

```bash
git clone https://github.com/dfirvault/ForensIQ.git
cd ForensIQ
```

2. Install dependencies:

```bash
pip install --upgrade langchain langchain-community langchain-ollama langchain-huggingface sentence-transformers chromadb pandas streamlit python-evtx
```

3. Run the tool:

```bash
python streamlit run Forensiq.py
```

or launch the batch script:
https://github.com/dfirvault/ForensIQ/blob/main/ForensIQLauncher.bat

![explorer_e4PD1Xq5rU](https://github.com/user-attachments/assets/7802c6d0-2def-4dd5-9e88-9e08ed7d134a)

---

4. Upload a log using the Web UI and start analysis!

![chrome_ue7DnzjCON](https://github.com/user-attachments/assets/f7c417fa-3311-4880-b342-432777ad77d1)

5. Adjust your model

Run the following once on your system using a standard cmd.exe prompt:

- setx OLLAMA_MAX_CONTEXT 16384
- setx OLLAMA_MAX_TOKENS 4096
- setx OLLAMA_NUM_GPU_LAYERS 28

Next, download the ModelFile that i have uploaded in Github.

- https://github.com/dfirvault/ForensIQ/blob/main/ModelFile

Then run the following command from the same directory as the ModelFile:

- ollama create qwen-long -f Modelfile

Now select qwen-long as the LLM model.

This will optimise the model for log analysis and ensure a large response it given back to you.

## ⚡ Usage

supports single or multiple files, or you can point it to a local folder where it will automatically identify and queue all available logs.

<img width="1823" height="360" alt="image" src="https://github.com/user-attachments/assets/8bd910ed-3abd-4a7c-8448-395c91bb77de" />


---

## 📝 Output

- **JSON Reports:** Structured forensic data.
- **CSV Summaries:** Quick overview of findings.
- **Logs:** Detailed logging for reproducibility and audits.

---

## 🔧 Requirements

- Python 3.11+
- `pip` package manager
- Supported only on Windows (Sorry *nix users)

---

## 📂 Supported Platforms

- Windows

---

## 🌐 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-name`).
3. Make your changes.
4. Submit a pull request.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 📬 Contact

For support or inquiries, please open an issue on GitHub or contact the maintainer at [dfirvault@gmail.com].
