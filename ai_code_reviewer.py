#!/usr/bin/env python3
"""
AI Code Review System using Ollama with Llama3.2:3b
Three focused agents: Code Reviewer, Documentation Generator, and Coordinator
"""

import json
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional
import requests


class OllamaClient:
    """Simple client for interacting with Ollama API"""
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.model = "llama3.2:3b"
    
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Generate response from Ollama"""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "system": system_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "top_p": 0.9
                }
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
    
    def __init__(self, ollama_client: OllamaClient):
        self.client = ollama_client
        self.system_prompt = """You are a senior code reviewer focused on security, performance, and best practices.
Review code for:
- Security vulnerabilities
- Performance issues
- Code style violations
- Logic errors
- Potential bugs

Return ONLY a JSON object with this structure:
{
    "security_issues": ["list of security concerns"],
    "performance_issues": ["list of performance problems"], 
    "style_issues": ["list of style violations"],
    "logic_issues": ["list of logic problems"],
    "severity": "low|medium|high"
}"""
    
    def review_code(self, code: str, filename: str = "") -> Dict:
        """Review code and return structured feedback"""
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
    
    def __init__(self, ollama_client: OllamaClient):
        self.client = ollama_client
        self.system_prompt = """You are a technical documentation specialist.
Generate clear, concise documentation for code including:
- Function/class docstrings
- Parameter descriptions
- Return value descriptions
- Usage examples

Return ONLY a JSON object with this structure:
{
    "docstrings": ["list of suggested docstrings for functions/classes"],
    "module_description": "brief description of what this module does",
    "usage_examples": ["list of usage examples"]
}"""
    
    def generate_docs(self, code: str, filename: str = "") -> Dict:
        """Generate documentation for the given code"""
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
    
    def __init__(self, ollama_client: OllamaClient):
        self.client = ollama_client
        self.code_reviewer = CodeReviewAgent(ollama_client)
        self.doc_generator = DocumentationAgent(ollama_client)
    
    def process_code(self, code: str, filename: str = "") -> Dict:
        """Process code through both agents and coordinate results"""
        print(f"🔍 Reviewing code{'...' if not filename else f' in {filename}...'}")
        
        # Get review from code review agent
        print("  → Running security and quality review...")
        review_results = self.code_reviewer.review_code(code, filename)
        
        # Get documentation from documentation agent
        print("  → Generating documentation suggestions...")
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
            summary += "⚠️  High priority issues detected - review recommended"
        elif severity == "medium":
            summary += "⚡ Medium priority issues found - consider addressing"
        else:
            summary += "✅ Low priority issues only - code looks good"
        
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
    report.append("\n📊 SUMMARY")
    report.append("-" * 20)
    report.append(results["summary"])
    
    # Code Review Results
    review = results["code_review"]
    report.append("\n🔍 CODE REVIEW")
    report.append("-" * 20)
    
    for category, issues in [
        ("🔒 Security Issues", review.get("security_issues", [])),
        ("⚡ Performance Issues", review.get("performance_issues", [])),
        ("🎨 Style Issues", review.get("style_issues", [])),
        ("🧠 Logic Issues", review.get("logic_issues", []))
    ]:
        if issues:
            report.append(f"\n{category}:")
            for issue in issues:
                report.append(f"  • {issue}")
    
    # Documentation Suggestions
    docs = results["documentation"]
    report.append("\n📝 DOCUMENTATION SUGGESTIONS")
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


def main():
    parser = argparse.ArgumentParser(description="AI Code Review using Ollama")
    parser.add_argument("file", help="Python file to review")
    parser.add_argument("--output", help="Output file for report (optional)")
    parser.add_argument("--ollama-url", default="http://localhost:11434", 
                       help="Ollama API URL")
    
    args = parser.parse_args()
    
    # Check if file exists
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File {args.file} not found")
        sys.exit(1)
    
    # Read code file
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    # Initialize Ollama client and coordinator
    print("🚀 Starting AI Code Review...")
    print(f"📡 Connecting to Ollama at {args.ollama_url}")
    
    ollama = OllamaClient(args.ollama_url)
    coordinator = CoordinatorAgent(ollama)
    
    # Process the code
    results = coordinator.process_code(code, file_path.name)
    
    # Generate report
    report = format_report(results)
    
    # Output results
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"📄 Report saved to {args.output}")
    else:
        print("\n" + report)
    
    print("\n✅ Code review complete!")


if __name__ == "__main__":
    main()