import json
import requests
import os

API_KEY = os.getenv("OPENAI_API_KEY")

def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except:
        return ""

data = {
    "trivy": read_file("sca/reports/trivy-report.json"),
    "grype": read_file("sca/reports/grype-report.json"),
    "osv": read_file("sca/reports/osv-report.json"),
    "fossa": read_file("sca/reports/fossa-report.json")
}

prompt = f"""
You are a security expert.

Analyze the following DevSecOps scan reports and provide:
1. Summary of vulnerabilities
2. Critical issues
3. Risk level
4. Recommended fixes
5. Final verdict (Safe / Not Safe)

DATA:
{json.dumps(data)[:8000]}
"""

response = requests.post(
    "https://api.openai.com/v1/chat/completions",
    headers={
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    },
    json={
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}]
    }
)

result = response.json()["choices"][0]["message"]["content"]

with open("sca/reports/ai-report.txt", "w") as f:
    f.write(result)
