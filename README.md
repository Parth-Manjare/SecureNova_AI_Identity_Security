# SecureNova AI Identity Security

A five-project capstone on threat modelling, identity and access management, adversarial testing, blue-team safeguards, and policy/compliance.

## Portfolio structure

The current repository folders map to the five portfolio sections requested in the capstone brief:

| Required section | Existing repository folder | Scope |
|---|---|---|
| `01-threat-model` | `Project1_Threat_Modelling/` | System architecture and data-flow diagram; trust boundaries; STRIDE matrix; attack trees; risk register; MITRE ATLAS mapping. |
| `02-iam-design` | `Project2_Auth0_Implementation/` | Auth0 applications and API; OAuth/OIDC login flow; scopes and permission checks; JWT validation; MFA and attack protection; SSO demonstration. |
| `03-red-team` | `Project3_Red_Team_AI_Identity_Attacks/` | Indirect prompt injection; agent identity spoofing; system-prompt extraction; RAG poisoning; simulated MCP tool abuse; CVSS 3.1 and ATLAS mapping. |
| `04-blue-team` | `Project4_Blue_Team_Guardrails_Hardening_Detection/` | NeMo Guardrails input screening; JWT-shaped output redaction; Ed25519 message signing and verification; further token/anomaly controls tracked as open. |
| `05-policy` | `Project5_Policy_Compliance_Summary/` | AI Identity Security Policy; two-tab compliance workbook; risk priority matrix; final capstone presentation and demo script. |

> The mapping above preserves the current on-disk Project1–Project5 folder names. If the reviewer requires the literal `01-threat-model` etc. names as top-level GitHub folders, rename/restructure only after updating any scripts that reference the current folder names.

## Project 1 — Threat modelling

**Purpose:** identify assets, trust boundaries, threats and mitigations before implementation.

**Primary artifacts:**
- `Project1_Threat_Modelling/01_Architecture/Data_Flow_Diagram/SecureNova_Architecture.png`
- `Project1_Threat_Modelling/02_STRIDE_Analysis/STRIDE_Matrix.xlsx`
- `Project1_Threat_Modelling/03_Attack_Trees/`
- `Project1_Threat_Modelling/04_Risk_Register/Risk_Register.xlsx`
- `Project1_Threat_Modelling/05_MITRE_ATLAS/MITRE_Mapping.xlsx`

## Project 2 — IAM design and Auth0 implementation

**Purpose:** establish application identity, authentication, token validation and permission enforcement.

**Code artifacts:**
- `Project2_Auth0_Implementation/app/auth.py` — login, callback, session and authentication routes.
- `Project2_Auth0_Implementation/app/config.py` — environment-backed Auth0 configuration.
- `Project2_Auth0_Implementation/app/security.py` — JWT/JWKS validation and permission enforcement.
- `Project2_Auth0_Implementation/app/routes.py` — protected API routes and authorization probes.
- `Project2_Auth0_Implementation/sso_demo.py` — second interactive client for SSO demonstration.
- `Project2_Auth0_Implementation/app/credential_rotation_test.py` — short-lived M2M access-token expiry test.

**Local run (PowerShell):**
```powershell
cd Project2_Auth0_Implementation
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Create `.env` locally from `.env.example`; never commit `.env` or real client secrets.

## Project 3 — Red-team AI identity attacks

**Purpose:** reproduce prompt, identity, context and tool-trust failures with synthetic data.

**Code artifacts:**
- `src/indirect_prompt_injection_test.py` — three document payloads and synthetic JWT disclosure test.
- `src/agent_identity_spoofing_test.py` — two-agent forged orchestrator message and local simulated action.
- `src/system_prompt_extraction_test.py` — five prompt extraction techniques and simulated role-claim analysis.
- `src/analyze_task3_results.py` — corrected post-processing of Task 3 logs.
- `src/rag_mcp_abuse_test.py` — local lexical RAG retrieval and mock MCP tool dispatcher.

**Prerequisites:** Ollama running with `qwen2.5:7b-instruct`; Python standard library for the test runners. Run scripts from repository root:
```powershell
python .\Project3_Red_Team_AI_Identity_Attacks\src\indirect_prompt_injection_test.py
python .\Project3_Red_Team_AI_Identity_Attacks\src\agent_identity_spoofing_test.py
python .\Project3_Red_Team_AI_Identity_Attacks\src\system_prompt_extraction_test.py
python .\Project3_Red_Team_AI_Identity_Attacks\src\rag_mcp_abuse_test.py
```

All credentials and privileged actions are synthetic/local simulations; they are not production compromises.

## Project 4 — Blue-team guardrails and detection

**Purpose:** add preventive and integrity controls to reduce the Project 3 attack paths.

**Code artifacts:**
- `start_project4.ps1` — starts/checks Ollama, validates the model and activates the dedicated virtual environment.
- `src/run_input_output_guardrails.py` — NeMo Guardrails initialization, deterministic input signature checks and JWT-shaped output redaction.
- `guardrails/config.yml` — local Ollama/NeMo model configuration.
- `src/crypto_agent_identity.py` — Ed25519 key-pair creation, message signing, verification and tamper rejection.

**Local run:**
```powershell
. .\Project4_Blue_Team_Guardrails_Hardening_Detection\start_project4.ps1
python .\Project4_Blue_Team_Guardrails_Hardening_Detection\src\run_input_output_guardrails.py
python .\Project4_Blue_Team_Guardrails_Hardening_Detection\src\crypto_agent_identity.py
```

**Status:** input/output guardrail and Ed25519 tests were demonstrated locally. Auth0 300-second TTL/refresh-token rotation/risk Action, anomaly detection, and complete before/after attack replay are tracked as open unless separately completed and evidenced.

## Project 5 — Policy, compliance and summary

**Artifacts:**
- `AI_Identity_Security_Policy.docx` and `.pdf` — identity lifecycle, credential governance, incident response.
- `Compliance_Mapping_Workbook.xlsx` — NIST AI RMF and OWASP LLM Top 10 mappings with evidence and three gaps.
- `Capstone_Final_Presentation.pptx` and `.pdf` — 20-minute CTO review and 5-minute live demo plan.
- `Evidence_Checklist.md` — eight required screenshots.

## Security and evidence hygiene

Never commit `.env`, API keys, Auth0 client secrets, real JWTs, private PEM keys, `.venv`, raw logs, or unredacted tokens. Keep generated evidence and submission PDFs in the submission location unless the rubric specifically asks for them in GitHub. Rotate secrets that have been exposed in screenshots or logs.

The GitHub contributor graph must show genuine work. Do not fabricate commit dates or activity. Capture the actual Insights/Contributors graph if the repository history supports the required five project days.

## References

- NIST AI RMF 1.0: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
- NIST AI RMF Playbook: https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook
- OWASP GenAI LLM Top 10 (2025): https://genai.owasp.org/llm-top-10/
- OWASP GenAI LLM Top 10 (2026) source: https://github.com/GenAI-Security-Project/GenAI-LLM-Top10
- FIRST CVSS 3.1 specification: https://www.first.org/cvss/v3-1/specification-document
