from http.client import HTTPResponse
import os
import psutil 
import subprocess
import asyncio

async def save_file(file, path):
    with open(path, "wb") as f:
        f.write(await file.read())


async def get_env_variable(name: str):
    return os.getenv(name)



async def execute_command(command):
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return process.pid
    except Exception as e:
        print(e)
        return None
    

async def wait_for_process_completion(pid):
    try:
        while True:
            process = psutil.Process(pid)
            if process.is_running():
                await asyncio.sleep(1)  # Sleep for 1 second before checking again
            else:
                return process.returncode
    except psutil.NoSuchProcess:
        return None  # Process with given PID does not exist
    


async def stop_process(pid: int):
    try:
        process = psutil.Process(pid)
        if process.is_running():
            process.terminate()
    except psutil.NoSuchProcess:
        print(f"No such process with pid {pid}")
    except Exception as e:
        print(e)