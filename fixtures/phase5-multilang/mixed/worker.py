from fastapi import FastAPI
from helper import execute_command

app = FastAPI()

@app.get("/cross-file")
def run_cross_file(value: str):
    execute_command(value)
