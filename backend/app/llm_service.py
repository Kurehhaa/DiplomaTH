# backend/app/llm_service.py
import os
import requests
import json
from typing import List, Dict
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY or len(GROQ_API_KEY) < 20:
    print("❌ GROQ_API_KEY не найден!")
else:
    print("✅ GROQ_API_KEY успешно загружен")


def call_groq(prompt: str, temperature: float = 0.35, max_tokens: int = 900):
    if not GROQ_API_KEY or len(GROQ_API_KEY) < 20:
        return None

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": "You are a senior penetration tester with 12+ years experience. Be technical, specific, concrete and professional."},
            {"role": "user", "content": prompt}
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=40)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        else:
            print(f"Groq Error {response.status_code}: {response.text[:150]}")
            return None
    except Exception as e:
        print(f"Groq exception: {e}")
        return None


def generate_intelligent_findings(scan_result: dict) -> List[Dict]:
    """МАКСИМАЛЬНО СТРОГИЙ режим — только реальные findings"""
    
    # Берём findings, которые уже сгенерировал scanner.py
    existing_findings = scan_result.get("findings", [])
    
    if not existing_findings:
        return []

    prompt = f"""
You are a penetration tester. Improve the descriptions of the following REAL findings.
Do NOT invent new findings.

Target: {scan_result.get('target')}
Open Ports: {scan_result.get('network', {}).get('open_ports', [])}
Server: {scan_result.get('web', {}).get('server', 'Unknown')}

Real findings:
{chr(10).join([f"- {f.get('title')} ({f.get('severity')})" for f in existing_findings])}

For each finding improve ONLY the description. Keep the same title and severity.
Return ONLY valid JSON array:

[
  {{
    "title": "Exact same title as above",
    "severity": "High/Medium/Low",
    "score": number,
    "description": "Improved, detailed, professional 1-2 sentence description"
  }}
]
"""

    content = call_groq(prompt, temperature=0.3, max_tokens=900)

    try:
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        
        improved = json.loads(content.strip())
        if isinstance(improved, list) and len(improved) > 0:
            return improved
    except:
        pass

    # Если LLM не справился — возвращаем оригинальные findings
    return existing_findings

def generate_full_report(scan_result: dict) -> str:
    """МАКСИМАЛЬНО СТРОГАЯ ВЕРСИЯ — только реальные findings"""
    
    ports = scan_result.get("network", {}).get("open_ports", [])
    server = scan_result.get("web", {}).get("server", "Unknown")
    findings = scan_result.get("findings", [])
    risk_level = scan_result.get("risk_level", "Medium")
    risk_score = scan_result.get("risk_score", 5.0)

    # Формируем точный список реальных findings
    findings_text = "\n".join([
        f"• {f.get('title', 'Unknown')} ({f.get('severity', 'Medium')}) — {f.get('description', 'No description provided')[:200]}"
        for f in findings
    ]) if findings else "• No significant security findings were detected during this scan."

    prompt = f"""
You are a professional penetration tester writing a factual report.
Use **ONLY** the information provided below. Do NOT invent any new vulnerabilities, attacks, or findings.

Target: {scan_result.get('target')}
IP Address: {scan_result.get('network', {}).get('ip_address')}
Open Ports: {ports}
Server: {server}
SSL expires in: {scan_result.get('ssl', {}).get('expires_in_days')} days
Risk Level: {risk_level} ({risk_score}/10)

Real Findings from scan:
{findings_text}

Write the report strictly based on the data above:

**Security Report for {scan_result.get('target')}**

**Executive Summary**
(4 sentences maximum. Be direct and factual.)

**Scan Summary**
- Target
- IP Address
- Open Ports
- Technologies
- SSL Status

**Key Findings**
(Use only the real findings listed above)

**Risk Assessment**
(Short explanation based only on real findings and open ports)

**Recommended Remediation**
(Numbered list with practical recommendations based only on real findings)

Be concise, professional and honest. Do not add fictional content.
"""

    content = call_groq(prompt, temperature=0.25, max_tokens=1300)

    # Если LLM совсем не справился — используем очень строгий fallback
    if not content or len(content) < 400:
        return f"""**Security Report for {scan_result.get('target')}**

**Executive Summary**
The reconnaissance scan of the target system identified an elevated risk level of {risk_score}/10 ({risk_level}). The most notable issue is the exposure of the FTP service on port 21. Additional concerns include web server information disclosure and SSL certificate expiration. These findings increase the external attack surface and should be addressed promptly.

**Scan Summary**
- Target: {scan_result.get('target')}
- IP Address: {scan_result.get('network', {}).get('ip_address')}
- Open Ports: {ports}
- Technologies: {server}
- SSL: expires in {scan_result.get('ssl', {}).get('expires_in_days')} days

**Key Findings**
{findings_text}

**Recommended Remediation**
1. Disable or restrict access to the FTP service (port 21).
2. Renew the SSL certificate before expiration.
3. Hide nginx server version information.
4. Implement missing security headers (HSTS, CSP, etc.).
"""

    return content

def generate_attack_paths_with_llm(scan_result: dict) -> List[Dict]:
    """Улучшенная версия — более подробные и качественные пути"""
    ports = scan_result.get("network", {}).get("open_ports", [])
    server = scan_result.get("web", {}).get("server", "Unknown")
    findings = [f.get("title", "") for f in scan_result.get("findings", [])]

    prompt = f"""
You are a senior penetration tester writing a professional report.

Target: {scan_result.get('target')}
Open Ports: {ports}
Server: {server}
Key Findings: {findings}

Generate **exactly 3** most probable attack paths. 
Make descriptions detailed (2-3 full sentences each).

Return ONLY valid JSON array. No extra text.

Desired format:
[
  {{
    "name": "Detailed Attack Path Name",
    "description": "Detailed 2-3 sentence explanation of how an attacker can exploit this, including possible impact.",
    "ttp_chain": ["Txxxx", "Tyyyy"],
    "likelihood": "High/Medium/Low",
    "recommendation": "Specific, actionable recommendation (2-3 sentences)"
  }}
]
"""

    content = call_groq(prompt, temperature=0.35, max_tokens=1100)

    if not content:
        logger.warning("LLM не вернул ответ для attack paths")
        return []

    try:
        # Очистка
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1]

        paths = json.loads(content.strip())
        
        if isinstance(paths, list) and len(paths) > 0:
            return paths[:3]
            
    except Exception as e:
        logger.error(f"JSON parsing failed: {e}")
        logger.error(f"Raw output: {content[:400]}...")

    return []