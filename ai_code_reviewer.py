#!/usr/bin/env python3
"""
AI Code Review System using Ollama with Llama3.2:3b
Three focused agents: Code Reviewer, Documentation Generator, and Coordinator
Simple workshop version - all configuration comes from agent_config.json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

import requests


class OllamaClient:
    """Simple client for interacting with Ollama API"""
    
    def __init__(self, base_url: str, config: Dict):
        self.base_url = base_url
        self.model = config.get("model", "llama3.2:3b")
        self.model_options = config.get("model_options", {})
    
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Generate response from Ollama"""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "system": system_prompt,
                "stream": False,
                "options": self.model_options
            }
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            
            return response.json().get("response", "").strip()
        
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to Ollama: {e}")
            return ""


class CodeReviewAgent:
    """Agent focused on code quality, security, and best practices"""
    
    def __init__(self, ollama_client: OllamaClient, config: Dict):
        self.client = ollama_client
        agent_config = config["agents"]["code_reviewer"]
        self.enabled = agent_config.get("enabled", True)
        self.system_prompt = agent_config["system_prompt"]
    
    def review_code(self, code: str, filename: str = "") -> Dict:
        """Review code and return structured feedback"""
        if not self.enabled:
            return {
                "security_issues": [],
                "performance_issues": [],
                "style_issues": [],
                "logic_issues": ["Code review agent is disabled"],
                "severity": "low"
            }
        
        prompt = f"""Review this {'file: ' + filename if filename else 'code'}:

```
{code}
```

Focus on security, performance, style, and logic issues."""
        
        response = self.client.generate(prompt, self.system_prompt)
        
        try:
            # Try to parse JSON response
            return json.loads(response)
        except json.JSONDecodeError:
            # Fallback if JSON parsing fails
            return {
                "security_issues": [],
                "performance_issues": [],
                "style_issues": [],
                "logic_issues": [response] if response else ["No issues found"],
                "severity": "low"
            }


class DocumentationAgent:
    """Agent focused on generating documentation and docstrings"""
    
    def __init__(self, ollama_client: OllamaClient, config: Dict):
        self.client = ollama_client
        agent_config = config["agents"]["documentation_agent"]
        self.enabled = agent_config.get("enabled", True)
        self.system_prompt = agent_config["system_prompt"]
    
    def generate_docs(self, code: str, filename: str = "") -> Dict:
        """Generate documentation for the given code"""
        if not self.enabled:
            return {
                "docstrings": ["Documentation agent is disabled"],
                "module_description": "Documentation generation disabled",
                "usage_examples": []
            }
        
        prompt = f"""Generate documentation for this {'file: ' + filename if filename else 'code'}:

```
{code}
```

Focus on clear docstrings and usage examples."""
        
        response = self.client.generate(prompt, self.system_prompt)
        
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {
                "docstrings": [response] if response else ["No documentation suggestions"],
                "module_description": "Code module",
                "usage_examples": []
            }


class CoordinatorAgent:
    """Agent that coordinates the review process and generates final reports"""
    
    def __init__(self, ollama_client: OllamaClient, config: Dict):
        self.client = ollama_client
        self.config = config
        self.code_reviewer = CodeReviewAgent(ollama_client, config)
        self.doc_generator = DocumentationAgent(ollama_client, config)
    
    def process_code(self, code: str, filename: str = "") -> Dict:
        """Process code through both agents and coordinate results"""
        print(f"Reviewing code{'...' if not filename else f' in {filename}...'}")
        
        # Get review from code review agent
        print("  -> Running security and quality review...")
        review_results = self.code_reviewer.review_code(code, filename)
        
        # Get documentation from documentation agent
        print("  -> Generating documentation suggestions...")
        doc_results = self.doc_generator.generate_docs(code, filename)
        
        # Combine results
        return {
            "filename": filename,
            "code_review": review_results,
            "documentation": doc_results,
            "summary": self._generate_summary(review_results, doc_results)
        }
    
    def _generate_summary(self, review: Dict, docs: Dict) -> str:
        """Generate a human-readable summary"""
        severity = review.get("severity", "low")
        total_issues = (
            len(review.get("security_issues", [])) +
            len(review.get("performance_issues", [])) +
            len(review.get("style_issues", [])) +
            len(review.get("logic_issues", []))
        )
        
        doc_suggestions = len(docs.get("docstrings", []))
        
        summary = f"Overall Severity: {severity.upper()}\n"
        summary += f"Total Issues Found: {total_issues}\n"
        summary += f"Documentation Suggestions: {doc_suggestions}\n"
        
        if severity == "high":
            summary += "HIGH PRIORITY: Review recommended"
        elif severity == "medium":
            summary += "MEDIUM PRIORITY: Consider addressing"
        else:
            summary += "LOW PRIORITY: Code looks good"
        
        return summary


def format_report(results: Dict) -> str:
    """Format the results into a readable report"""
    report = []
    report.append("=" * 60)
    report.append(f"AI CODE REVIEW REPORT")
    if results["filename"]:
        report.append(f"File: {results['filename']}")
    report.append("=" * 60)
    
    # Summary
    report.append("\nSUMMARY")
    report.append("-" * 20)
    report.append(results["summary"])
    
    # Code Review Results
    review = results["code_review"]
    report.append("\nCODE REVIEW")
    report.append("-" * 20)
    
    for category, issues in [
        ("Security Issues", review.get("security_issues", [])),
        ("Performance Issues", review.get("performance_issues", [])),
        ("Style Issues", review.get("style_issues", [])),
        ("Logic Issues", review.get("logic_issues", []))
    ]:
        if issues:
            report.append(f"\n{category}:")
            for issue in issues:
                report.append(f"  • {issue}")
    
    # Documentation Suggestions
    docs = results["documentation"]
    report.append("\nDOCUMENTATION SUGGESTIONS")
    report.append("-" * 30)
    
    if docs.get("module_description"):
        report.append(f"\nModule Description: {docs['module_description']}")
    
    if docs.get("docstrings"):
        report.append("\nSuggested Docstrings:")
        for docstring in docs["docstrings"]:
            report.append(f"  • {docstring}")
    
    if docs.get("usage_examples"):
        report.append("\nUsage Examples:")
        for example in docs["usage_examples"]:
            report.append(f"  • {example}")
    
    report.append("\n" + "=" * 60)
    return "\n".join(report)


def load_config(config_file: str) -> Dict:
    """Load configuration from JSON file"""
    config_path = Path(config_file)
    
    if not config_path.exists():
        print(f"Configuration file '{config_file}' not found!")
        print(f"\nTo create a default configuration file, run:")
        print(f"   python {sys.argv[0]} --create-config")
        sys.exit(1)
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        print(f"Loaded configuration from {config_file}")
        return config
    except json.JSONDecodeError as e:
        print(f"Error parsing {config_file}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading {config_file}: {e}")
        sys.exit(1)


def create_default_config(config_file: str) -> None:
    """Create a basic default configuration file"""
    default_config = {
        "model": "llama3.2:3b",
        "model_options": {
            "temperature": 0.1,
            "top_p": 0.9
        },
        "agents": {
            "code_reviewer": {
                "name": "Code Review Agent",
                "enabled": True,
                "system_prompt": "You are a senior code reviewer. Review code for security, performance, style, and logic issues. Return JSON: {\"security_issues\": [], \"performance_issues\": [], \"style_issues\": [], \"logic_issues\": [], \"severity\": \"low|medium|high\"}"
            },
            "documentation_agent": {
                "name": "Documentation Agent", 
                "enabled": True,
                "system_prompt": "You are a documentation specialist. Generate clear documentation. Return JSON: {\"docstrings\": [], \"module_description\": \"\", \"usage_examples\": []}"
            }
        }
    }
    
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2)
        print(f"Created default configuration: {config_file}")
        print(f"Edit the file to customize agent prompts and behavior!")
    except Exception as e:
        print(f"Could not create config file: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="AI Code Review using Ollama")
    parser.add_argument("file", nargs='?', help="Python file to review")
    parser.add_argument("--output", help="Save report to file")
    parser.add_argument("--config", default="agent_config.json", help="Configuration file")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama API URL")
    parser.add_argument("--create-config", action="store_true", help="Create default config and exit")
    
    args = parser.parse_args()
    
    # Create config file and exit
    if args.create_config:
        create_default_config(args.config)
        return
    
    # Validate arguments
    if not args.file:
        print("No file specified. Use --help for usage information.")
        sys.exit(1)
    
    if not Path(args.file).exists():
        print(f"File not found: {args.file}")
        sys.exit(1)
    
    # Load code file
    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            code = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    # Load configuration
    config = load_config(args.config)
    
    # Start review process
    print("Starting AI Code Review...")
    print(f"Connecting to Ollama at {args.ollama_url}")
    print(f"Using model: {config.get('model', 'llama3.2:3b')}")
    
    # Initialize components
    ollama = OllamaClient(args.ollama_url, config)
    coordinator = CoordinatorAgent(ollama, config)
    
    # Process the code
    results = coordinator.process_code(code, Path(args.file).name)
    
    # Generate and output report
    report = format_report(results)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print("\n" + report)
    
    print("\nCode review complete!")


if __name__ == "__main__":
    main()