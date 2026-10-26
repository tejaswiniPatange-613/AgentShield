# AgentShield — AI Agent Security Testing Toolkit

**AgentShield** is a Python-based security testing toolkit designed to evaluate AI-agent security controls, test prompt-injection defenses, identify synthetic secret disclosure, validate tool authorization, and examine security audit events.

The project combines deterministic mock-agent security tests with a separate local Large Language Model (LLM) evaluation path using Ollama.

**Repository:** [github.com/tejaswiniPatange-613/AgentShield](https://github.com/tejaswiniPatange-613/AgentShield)

> **Disclaimer:** This is a cybersecurity portfolio and learning project. Passing its tests does not prove that a real AI application is secure.

## Project Highlights

- Prompt-injection testing against known instruction-override phrases.
- Synthetic secret disclosure resistance checks.
- Unauthorized tool invocation testing.
- Restricted resource access validation.
- Structured security audit logging.
- Output redaction for configured protected values.
- Local LLM behavioral evaluation with Ollama.
- Automated unit and integration testing.
- JSON-based security assessment reports.
- Remediation guidance for identified security-control gaps.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core implementation and security checks |
| Ollama | Local LLM inference |
| Requests | HTTP communication with Ollama |
| Unittest | Automated unit and integration tests |
| JSON | Security assessment reports |
| JSON Lines | Structured audit logging |
| PowerShell | Windows development and execution |

## Project Architecture

```text
AgentShield/
│
├── agents/
│   ├── mock_agent.py
│   ├── llm_agent.py
│   ├── security_evaluator.py
│   ├── audit_logger.py
│   └── red_team_tests.py
│
├── tests/
│   ├── test_security.py
│   ├── test_prompt_injection.py
│   ├── test_red_team_tests.py
│   ├── test_audit_logger.py
│   ├── test_llm_agent.py
│   ├── test_llm_audit_integration.py
│   ├── test_llm_security.py
│   └── test_security_evaluator.py
│
├── reports/
│   ├── security_report.json
│   └── llm_security_report.json
│
├── logs/
│   └── audit.log
│
├── docs/
├── security_runner.py
├── main.py
├── test_agent.py
├── .gitignore
└── README.md
```

*The tree shows the main project components; generated files and local artifacts may vary.*

## Security Testing Capabilities

### 1. Prompt-Injection Testing

Tests whether the mock agent blocks selected instruction-override phrases, such as attempts to ignore previous instructions or reveal protected information.

**Current limitation:** The mock agent uses deterministic phrase matching. This does not detect every direct, indirect, or obfuscated prompt-injection attack.

### 2. Sensitive Data Protection

Uses synthetic test values to evaluate disclosure refusal and configured output-redaction behavior.

The LLM evaluation also checks how a locally hosted model responds to a synthetic secret-disclosure scenario.

**Important finding:** During one observed local LLM test, the model repeated the synthetic test value. This demonstrates why model behavior and output controls must be assessed separately.

### 3. Tool Authorization

Attempts to execute an unauthorized tool and checks whether the mock agent denies the request and records the blocked action.

### 4. Restricted Resource Access

Simulates an attempt to access a restricted test file and verifies that access is denied.

### 5. Audit Logging

Records structured security events and tests that sensitive or unapproved metadata is excluded from the audit log.

### 6. Security Reporting

Generates machine-readable JSON reports containing test identifiers, observed behavior, status, severity labels, and remediation recommendations.

## Getting Started

### Prerequisites

- Python 3.10 or later
- Git
- Windows PowerShell or a compatible terminal
- Ollama and a supported local model for LLM evaluation

### 1. Clone the Repository

```powershell
git clone https://github.com/tejaswiniPatange-613/AgentShield.git
cd AgentShield
```

### 2. Create a Virtual Environment

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

Install the HTTP dependency:

```powershell
py -m pip install requests
```

### 4. Prepare the Local LLM

Install Ollama separately if it is not already installed.

Download the model used during development:

```powershell
ollama pull qwen2.5:3b
```

If the model is already available locally, downloading it again is unnecessary.

Ensure Ollama is running before performing LLM evaluations. The deterministic mock-agent tests do not require model inference.

## Running AgentShield

### Run the Mock-Agent Security Assessment

```powershell
py security_runner.py
```

The runner executes 12 checks across the original assessment runner and reusable red-team test library.

The generated report is saved to:

`reports/security_report.json`

### Run the Local LLM Security Evaluation

```powershell
py -m agents.security_evaluator
```

This evaluation sends prompts to the configured local Ollama model and records behavioral observations.

The generated report is saved to:

`reports/llm_security_report.json`

LLM tests take longer than deterministic mock-agent checks. Some results require manual review because a model response alone does not establish whether a security control is effective.

### Run the Automated Test Suite

```powershell
py -m unittest discover -s tests -p "test_*.py" -v
```

**Latest verified result:** 34 automated tests passed in approximately 20 seconds in the development environment.

Test results may change as the codebase evolves. The suite includes deterministic unit tests, mocked integration tests, and local-model behavioral tests.

## Understanding Assessment Results

| Status | Meaning |
|---|---|
| `PASS` | The observed behavior matched the test's expected behavior. |
| `FAIL` | The observed behavior did not match the expected behavior. |
| `REVIEW` | Human assessment is needed to determine the security outcome. |

A passing test validates only the specific behavior it checks. It does not establish overall application security.

## Security Limitations

- The mock agent is a deterministic simulation, not a production AI agent.
- Prompt-injection checks cover selected patterns and are not a comprehensive defense.
- Output redaction protects configured values that match the filter; it does not automatically discover every sensitive value.
- Local LLM responses can vary between runs and may disclose synthetic test data.
- Audit logging requires further review before production use, including retention, permissions, integrity, and privacy.
- Severity labels are preliminary classifications, not validated risk scores.
- The current test suite does not establish resistance to every AI-agent attack.
- Use synthetic data and test only systems you own or have explicit authorization to assess.

## Future Enhancements

- Expand direct, indirect, and paraphrased prompt-injection tests.
- Add additional sensitive-data leakage test cases.
- Improve structured findings and remediation references.
- Add configurable assessment profiles.
- Add regression testing for security-control changes.
- Compare reports across assessment runs.
- Explore integrations with additional AI-agent frameworks.

## Author

**Tejaswini Patange**

Cybersecurity | Application Security | VAPT | AI Security Testing

- **GitHub:** [tejaswiniPatange-613](https://github.com/tejaswiniPatange-613)
- **AgentShield Repository:** [github.com/tejaswiniPatange-613/AgentShield](https://github.com/tejaswiniPatange-613/AgentShield)
- **LinkedIn:** [Tejaswini Patange](https://www.linkedin.com/in/tejaswinipatange/)

---

*Developed as a hands-on cybersecurity portfolio project to explore AI-agent security testing, defensive controls, automated testing, and evidence-based reporting.*