import subprocess

def execute_command(value: str):
    subprocess.run(value, shell=True)
