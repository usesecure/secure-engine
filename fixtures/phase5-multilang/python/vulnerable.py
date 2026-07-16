import subprocess
import requests
import pickle
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

app = FastAPI()

@app.get("/run")
def run_command(request: Request):
    command = request.query_params.get("command")
    subprocess.run(command, shell=True)
    cursor.execute(command)
    open(command)
    requests.get(command)
    RedirectResponse(command)
    eval(command)
    pickle.loads(command)
