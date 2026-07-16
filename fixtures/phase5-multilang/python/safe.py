import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.post("/safe")
@login_required
def safe_command():
    requested = request.form.get("tool")
    safe = allowlist(requested)
    subprocess.run(["tool", safe], check=True)
