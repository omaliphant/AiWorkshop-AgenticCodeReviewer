# Oz'AI Workshop - Code Reviewer and Documentation Agents

A lightweight, offline AI code review system using Ollama and Llama3.2:3b with three specialized agents for comprehensive code analysis.

## 🎯 Oz'AI Workshop Overview - 16 Sept 2025

This workshop demonstrates how to build practical AI tools for code review and documentation using local models. The system uses three focused agents:

- **Code Review Agent**: Security, performance, and style analysis
- **Documentation Agent**: Generates docstrings and usage examples  
- **Coordinator Agent**: Orchestrates the review process and creates reports

## 🚀 Quick Start

### Prerequisites

- Windows 10/11
- Python 3.8 or higher
- 4GB+ RAM available for the AI model
- Internet connection (for initial setup only)

### Step 1: Clone Repository

```bash
cd C:\
git clone <repository-url> C:\dev\ai-code-review
cd C:\dev\ai-code-review
```

### Step 2: Install Ollama

**Option A: Download Installer (Recommended)**
1. Visit [ollama.ai](https://ollama.ai/download)
2. Download the Windows installer
3. Run the installer and follow the prompts
4. Restart your terminal/command prompt

**Option B: PowerShell Install**
```powershell
# Run as Administrator
iwr -useb https://ollama.ai/install.ps1 | iex
```

### Step 3: Download AI Model

```bash
# This downloads ~2GB - ensure good internet connection
ollama pull llama3.2:3b
```

### Step 4: Install Python Dependencies

```bash
# Navigate to project directory
cd C:\dev\ai-code-review

# Install required packages
pip install requests
```

### Step 5: Test Installation

```bash
# Start Ollama (if not already running)
ollama serve

# In a new terminal, test the code reviewer
python ai_code_reviewer.py ai_code_reviewer.py
```

## 📖 Usage Examples

### Basic Code Review
```bash
python ai_code_reviewer.py my_script.py
```

### Save Report to File
```bash
python ai_code_reviewer.py my_script.py --output review_report.txt
```

### Custom Ollama URL
```bash
python ai_code_reviewer.py my_script.py --ollama-url http://localhost:11434
```

### Review Multiple Files
```bash
# Windows batch example
for %f in (*.py) do python ai_code_reviewer.py "%f" --output "review_%f.txt"
```

## 🔧 Configuration

### Ollama Settings

The system connects to Ollama at `http://localhost:11434` by default. To modify:

```bash
# Start Ollama on different port
ollama serve --port 8080

# Use with code reviewer
python ai_code_reviewer.py script.py --ollama-url http://localhost:8080
```

### Model Settings

To use a different model, edit the `OllamaClient` class in `ai_code_reviewer.py`:

```python
def __init__(self, base_url: str = "http://localhost:11434"):
    self.base_url = base_url
    self.model = "llama3.2:1b"  # Change model here
```

Available models:
- `llama3.2:1b` (faster, less accurate)
- `llama3.2:3b` (recommended balance)
- `codellama:7b` (better for code, requires more RAM)

## 🛠️ Troubleshooting

### Ollama Not Starting

**Problem**: `Error connecting to Ollama`

**Solutions**:
```bash
# Check if Ollama is running
ollama list

# Start Ollama manually
ollama serve

# Check Windows services
services.msc
# Look for "Ollama" service and start it
```

### Model Not Found

**Problem**: `model "llama3.2:3b" not found`

**Solutions**:
```bash
# List installed models
ollama list

# Pull the required model
ollama pull llama3.2:3b

# If download fails, try again with better connection
ollama pull llama3.2:3b --insecure
```

### Python Import Errors

**Problem**: `ModuleNotFoundError: No module named 'requests'`

**Solutions**:
```bash
# Check Python version
python --version

# Install pip if missing
python -m ensurepip --upgrade

# Install requests
pip install requests

# If multiple Python versions, use specific version
python3 -m pip install requests
```

### Memory Issues

**Problem**: System runs slowly or crashes

**Solutions**:
- Close other applications to free RAM
- Use smaller model: `ollama pull llama3.2:1b`
- Increase virtual memory in Windows settings
- Check available disk space (models require 2-4GB)

### Firewall/Antivirus Issues

**Problem**: Connection refused or blocked

**Solutions**:
- Add Ollama to Windows Firewall exceptions
- Add exception in antivirus software
- Temporarily disable real-time protection for testing
- Check Windows Defender SmartScreen settings

### Port Conflicts

**Problem**: Port 11434 already in use

**Solutions**:
```bash
# Find what's using the port
netstat -ano | findstr 11434

# Kill the process (replace PID)
taskkill /PID <process_id> /F

# Or use different port
ollama serve --port 8080
```

## 📁 Project Structure

```
C:\dev\ai-code-review\
├── ai_code_reviewer.py    # Main application
├── README.md              # This file
├── examples/              # Sample code files for testing
│   ├── bad_code.py       # Intentionally problematic code
│   ├── good_code.py      # Well-written example
│   └── mixed_code.py     # Realistic code with issues
└── reports/              # Generated review reports
```

## 🧪 Testing the Setup

Create a test file to verify everything works:

**test_file.py**:
```python
def calculate_total(items):
    total = 0
    for item in items:
        total = total + item
    return total

# Missing docstring, inefficient loop, no error handling
```

Run the reviewer:
```bash
python ai_code_reviewer.py test_file.py
```

Expected output should include suggestions for:
- Adding docstrings
- Using `sum()` function
- Adding error handling
- Type hints

## 🔐 Security Notes

- All processing happens locally - no code leaves your machine
- Ollama runs as a local service on your computer
- No API keys or external services required
- Review the generated reports before sharing with others

## 💡 Workshop Tips

### For Instructors
- Test the full setup on the target machines beforehand
- Have the Ollama installer ready for offline installation
- Prepare example "bad code" files for students to test
- Consider running Ollama from a shared network location if individual installs fail

### For Students
- Start the setup process early - downloading models takes time
- Keep Ollama running in the background during the workshop
- Experiment with different code files to see various types of feedback
- Try modifying the agent prompts to focus on specific issues

## 🤝 Contributing

Found an issue or want to improve the system? 

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is provided for educational purposes. Please ensure compliance with your organization's policies before using in production environments.

---

**Need Help?** 
- Check the troubleshooting section above
- Review Ollama documentation: [ollama.ai/docs](https://ollama.ai/docs)
- Ask during the workshop Q&A session