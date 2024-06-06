from http.client import HTTPResponse
import os
import httpx 

async def save_file(file, path):
    with open(path, "wb") as f:
        f.write(await file.read())


async def get_env_variable(name: str):
    return await os.getenv(name)


