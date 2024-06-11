from http.client import HTTPException, HTTPResponse
from typing import Optional

from fastapi import APIRouter, Depends, UploadFile, Form, Response
from ..models.ids_base import IDSBase
from .dependencies import get_ids_instance
from .utils import save_file, get_env_variable
from ..validation.models import NetworkAnalysisData, StaticAnalysisData
import httpx
import asyncio

router = APIRouter()

@router.get("/healthcheck")
async def healthcheck():
    return {"message": "healthy"}

# TODO: einmal alles testen (setup container, ensemble, analysis start, stop, etc.)

@router.post("/configuration")
async def test(container_id: str = Form(...) , file: UploadFile = Form(...)  ,ids: IDSBase = Depends(get_ids_instance)):
    if file is None:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # initialize container id variable to keep track which container is associated with the ids instance
    ids.container_id = int(container_id)

    temporary_file_path = "/tmp/temporary.txt"
    await save_file(file, temporary_file_path)
    response = await ids.configure(temporary_file_path)
    return {"message": response}


@router.post("/ruleset")
async def test(file: UploadFile = None ,ids: IDSBase = Depends(get_ids_instance)):
    if file is None:
        raise HTTPException(status_code=400, detail="No file provided")

    temporary_file_path = "/tmp/temporary.txt"
    await save_file(file, temporary_file_path)
    rsponse = await ids.configure_ruleset(temporary_file_path)
    return {"message": rsponse}


@router.post("/analysis/static")
async def static_analysis(ensemble_id: Optional[str] = Form(None), container_id: str = Form(...), file: UploadFile = Form(...), ids: IDSBase = Depends(get_ids_instance)):
    if file is None:
        raise HTTPException(status_code=400, detail="No file provided")
    
    if ensemble_id != None:
        ids.ensemble_id = ensemble_id

    temporary_file_path = "/tmp/dataset.pcap"
    await save_file(file, temporary_file_path)
    asyncio.create_task(ids.startStaticAnalysis(temporary_file_path, int(container_id)))
    http_response = Response(content=f"Started analysis for container {container_id}", status_code=200)

    return http_response

@router.post("/analysis/network")
async def network_analysis(network_analysis_data: NetworkAnalysisData, ids: IDSBase = Depends(get_ids_instance)):
    if network_analysis_data.ensemble_id != None:
        ids.ensemble_id = network_analysis_data.ensemble_id

    response = await ids.startNetworkAnalysis(network_analysis_data.container_id)
    return response

@router.post("/analysis/stop/")
async def stop_analysis(ids: IDSBase = Depends(get_ids_instance)):
    response = await ids.stopAnalysis()  

    # reset ensemble id to wait if next analysis is for ensemble or ids solo
    if ids.ensemble_id != None:
        ids.ensemble_id = None
  
    return response

async def tell_core_analysis_has_finished(ids: IDSBase = Depends(get_ids_instance)):
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