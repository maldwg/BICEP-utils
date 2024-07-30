from http.client import HTTPResponse
import os
import psutil 
import subprocess
import asyncio
import httpx

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



async def tell_core_analysis_has_finished(ids):
    if ids.ensemble_id == None:
        endpoint = f"/ids/analysis/finished/{ids.container_id}"
    else:
        endpoint = f"/ensemble/{ids.ensemble_id}/analysis/finished/{ids.container_id}"
    
    # tell the core to stop/set status to idle again
    core_url = await get_env_variable("CORE_URL")
        # reset ensemble id to wait if next analysis is for ensemble or ids solo

    async with httpx.AsyncClient() as client:
        response: HTTPResponse = await client.post(core_url+endpoint)

    # reset ensemble id after each analysis is completed to keep track if analysis has been triggered for ensemble or not
    if ids.ensemble_id != None:
        ids.ensemble_id = None

    return response


async def send_alerts_to_core(ids):
    if ids.ensemble_id == None:
        endpoint = f"/ids/alerts/{ids.container_id}"
    else:
        endpoint = f"/ensemble/{ids.ensemble_id}/alerts/{ids.container_id}"

    # tell the core to stop/set status to idle again
    core_url = await get_env_variable("CORE_URL")
    alerts = await ids.parser.parse_alerts()
    data = {'alerts': alerts, 'analysis_type': "static"}
    async with httpx.AsyncClient() as client:
        response: HTTPResponse = await client.post(core_url+endpoint, json=data)

    return response



async def send_alerts_to_core_periodically(ids, period="30"):
    try:
        if ids.ensemble_id == None:
            endpoint = f"/ids/alerts/{ids.container_id}"
        else:
            endpoint = f"/ensemble/{ids.ensemble_id}/alerts/{ids.container_id}"
        # tell the core to stop/set status to idle again
        core_url = await get_env_variable("CORE_URL")

        while True:
            alerts = await ids.parser.parse_alerts()
            data = {'alerts': alerts, 'analysis_type': "network"}
            try:
                async with httpx.AsyncClient() as client:
                    response: HTTPResponse = await client.post(core_url+endpoint, json=data)
            except Exception as e:
                print("Somethign went wrong during alert sending... retrying on next iteration")
                
            await asyncio.sleep(period)

    except asyncio.CancelledError as e:
        print(f"Canceled the sending of alerts for network analysis for ids {ids.id}")
        