# Oz'AI Workshop - Code Reviewer and Documentation Agents
A lightweight, offline AI code review system using Ollama and Llama3.2:3b. This workshop demonstrates building practical AI tools with three specialized agents for comprehensive code analysis.

## 🎯 Oz'AI Workshop Overview - 16 Sept 2025
Learn to build AI-powered developer tools by creating a code review system with:

- **Code Review Agent**: Analyzes security, performance, and style issues
- **Documentation Agent**: Generates docstrings and usage examples  
- **Coordinator Agent**: Orchestrates the review process and creates reports

**Key Learning Goals:**
- AI agent design patterns
- Prompt engineering for specific tasks
- Local AI model integration
- Configuration-driven AI systems

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

### Step 5: Create Configuration and Test

```bash
# Create the agent configuration file
python ai_code_reviewer.py --create-config

# Test with the provided bad code example
python ai_code_reviewer.py bad_code_example.py
```

### Quick Examples (Windows Batch Files)

For easy testing, use the provided batch files:

```bash
# Run analysis on bad code example (demonstrates many issues)
run_bad_example.bat

# Run analysis on good code example (demonstrates best practices)
run_good_example.bat
```

These batch files will automatically:
- Run the code reviewer with appropriate parameters
- Save output to text files (`review_bad.txt` and `review_good.txt`)
- Display clear start/finish messages

## 📖 Usage Examples

### Basic Code Review
```bash
python ai_code_reviewer.py my_script.py
```

### Save Report to File
```bash
python ai_code_reviewer.py my_script.py --output review_report.txt
```

### Use Custom Configuration
```bash
python ai_code_reviewer.py my_script.py --config my_agents.json
```

### Custom Ollama URL
```bash
python ai_code_reviewer.py my_script.py --ollama-url http://localhost:8080
```

## 🔧 Configuration System

The system is driven by `agent_config.json` which controls all agent behavior:

### Sample Configuration Structure
```json
{
  "model": "llama3.2:3b",
  "model_options": {
    "temperature": 0.1,
    "top_p": 0.9
  },
  "agents": {
    "code_reviewer": {
      "name": "Code Review Agent",
      "enabled": true,
      "system_prompt": "Your custom review prompt here..."
    },
    "documentation_agent": {
      "name": "Documentation Agent", 
      "enabled": true,
      "system_prompt": "Your custom documentation prompt here..."
    }
  }
}
```

### Customizing Agent Behavior

1. **Edit System Prompts**: Modify how agents analyze code
2. **Adjust Model Settings**: Change temperature for more/less creative responses
3. **Enable/Disable Agents**: Turn off agents you don't need
4. **Create Multiple Configs**: Different configurations for different purposes

### Workshop Exercises

**Exercise 1: Security-Focused Review**
- Modify the code reviewer prompt to focus only on security issues
- Test with `bad_code_example.py`

**Exercise 2: Documentation Specialist**
- Enhance the documentation agent to include type hints
- Test with `good_code_example.py`

**Exercise 3: Custom Agent**
- Add a new agent section to the config
- Modify the code to use your new agent

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

### Configuration File Issues

**Problem**: `Configuration file 'agent_config.json' not found!`

**Solutions**:
```bash
# Create default configuration
python ai_code_reviewer.py --create-config

# Verify the file was created
dir agent_config.json

# Check JSON syntax if you edited it
python -m json.tool agent_config.json
```

### Model Not Found

**Problem**: `model "llama3.2:3b" not found`

**Solutions**:
```bash
# List installed models
ollama list

# Pull the required model
ollama pull llama3.2:3b

# If download fails, try again
ollama pull llama3.2:3b --insecure
```

### Python Import Errors

**Problem**: `ModuleNotFoundError: No module named 'requests'`

**Solutions**:
```bash
# Check Python version
python --version

# Install requests
pip install requests

# If multiple Python versions
python3 -m pip install requests
```

### Memory Issues

**Problem**: System runs slowly or crashes

**Solutions**:
- Close other applications to free RAM
- Use smaller model: `ollama pull llama3.2:1b`
- Edit `agent_config.json` to use `"model": "llama3.2:1b"`
- Check available disk space (models require 2-4GB)

### JSON Configuration Errors

**Problem**: `Error parsing agent_config.json`

**Solutions**:
```bash
# Validate JSON syntax
python -m json.tool agent_config.json

# Common issues:
# - Missing commas between sections
# - Unescaped quotes in prompts
# - Missing closing braces

# Recreate default if corrupted
python ai_code_reviewer.py --create-config
```

## 📁 Project Structure

```
C:\dev\ai-code-review\
├── ai_code_reviewer.py        # Main application (simple, workshop-friendly)
├── agent_config.json          # Agent configuration (created by --create-config)
├── README.md                  # This file
├── bad_code_example.py        # Intentionally problematic code for testing
├── good_code_example.py       # Well-written example code
├── run_bad_example.bat        # Quick test with bad code example
├── run_good_example.bat       # Quick test with good code example
└── reports/                   # Directory for saved reports (optional)
```

## 🧪 Testing Your Setup

### Quick Verification

1. **Test Configuration Creation**:
   ```bash
   python ai_code_reviewer.py --create-config
   ```

2. **Test Bad Code Review**:
   ```bash
   python ai_code_reviewer.py bad_code_example.py
   ```
   Expected: Multiple security, performance, and style issues detected

3. **Test Good Code Review**:
   ```bash
   python ai_code_reviewer.py good_code_example.py
   ```
   Expected: Minimal issues, focus on documentation suggestions

### Workshop Validation Checklist

- [ ] Ollama service running (`ollama list` works)
- [ ] Model downloaded (`llama3.2:3b` appears in model list)
- [ ] Python can import requests (`python -c "import requests"`)
- [ ] Configuration file created successfully
- [ ] Bad code example produces detailed review
- [ ] Good code example produces minimal issues

## 🎓 Workshop Activities

### Activity 1: Understanding Agent Prompts
1. Review the default `agent_config.json`
2. Run a code review and note the results
3. Modify the code reviewer prompt to be more strict
4. Compare the results

### Activity 2: Custom Documentation Agent
1. Edit the documentation agent prompt
2. Add requirements for type hints and examples
3. Test with both code examples
4. Observe the difference in output

### Activity 3: Model Parameter Tuning
1. Change `temperature` from `0.1` to `0.8`
2. Run the same review multiple times
3. Note the variation in responses
4. Experiment with different values

### Activity 4: Creating Specialized Agents
1. Create a new agent configuration for "Performance Review"
2. Modify the Python code to use your new agent
3. Test with the provided examples

## 💡 Workshop Tips

### For Instructors
- **Pre-setup**: Test the full installation on target machines
- **Have backups**: Keep working `agent_config.json` files ready
- **Internet dependency**: Download models before workshop if internet is limited
- **Time management**: Basic setup takes 15-20 minutes

### For Students
- **Start early**: Model downloads take time
- **Keep Ollama running**: Leave it running throughout the workshop
- **Experiment freely**: Configuration changes are easy to revert
- **Save configurations**: Create multiple config files for different experiments

### Advanced Extensions
- Add new agent types (security-only, performance-only)
- Integrate with Git hooks for automated reviews
- Create web interface using Flask/FastAPI
- Add support for other programming languages
- Implement batch processing for multiple files

## 🔐 Security Notes

- **Local processing**: All code analysis happens on your machine
- **No external calls**: Code never leaves your local environment
- **No API keys required**: Everything runs offline after initial setup
- **Safe to experiment**: No risk of exposing sensitive code

## 🤝 Workshop Extensions

Ready for more? Try these extensions:

1. **Multi-file Analysis**: Modify to process entire directories
2. **Git Integration**: Analyze only changed files in commits
3. **Custom Output Formats**: Add HTML, PDF, or Markdown reports
4. **Language Support**: Extend to JavaScript, Java, or other languages
5. **CI/CD Integration**: Create GitHub Actions workflow

## 📄 Learning Resources

- **Ollama Documentation**: [ollama.ai/docs](https://ollama.ai/docs)
- **Prompt Engineering Guide**: [Learn effective prompting techniques](https://www.promptingguide.ai/)
- **Agent Design Patterns**: Study the code structure for building AI agents
- **JSON Configuration**: Understanding config-driven applications

---

**Need Help During the Workshop?**
- Check this troubleshooting section first
- Ask your instructor for assistance
- Review the example files for reference patterns
- Remember: experimentation is encouraged!

**After the Workshop:**
- Save your custom configurations
- Try the advanced extensions
- Apply these patterns to your own AI projects
- Share your improvements with others!