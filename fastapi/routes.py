from http.client import HTTPException, HTTPResponse

from fastapi import APIRouter, Depends, UploadFile, Form, Response
from ..models.ids_base import IDSBase
from .dependencies import get_ids_instance
from .utils import save_file, get_env_variable
from ..validation.models import NetworkAnalysisData, StaticAnalysisData
import httpx

router = APIRouter()

@router.get("/healthcheck")
async def healthcheck():
    return {"message": "healthy"}

@router.post("/configuration")
async def test(file: UploadFile = None ,ids: IDSBase = Depends(get_ids_instance)):
    if file is None:
        raise HTTPException(status_code=400, detail="No file provided")
    
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
async def static_analysis(container_id: str = Form(...), file: UploadFile = Form(...), ids: IDSBase = Depends(get_ids_instance)):
    if file is None:
        raise HTTPException(status_code=400, detail="No file provided")

    temporary_file_path = "/tmp/dataset.pcap"
    await save_file(file, temporary_file_path)
    response = await ids.startStaticAnalysis(temporary_file_path, int(container_id))

    http_response = Response(content=response, status_code=200)
    return http_response

@router.post("/analysis/network")
async def network_analysis(network_analysis_data: NetworkAnalysisData, ids: IDSBase = Depends(get_ids_instance)):
    response = await ids.startNetworkAnalysis()
    return response

@router.post("/analysis/stop/")
async def stop_analysis(ids: IDSBase = Depends(get_ids_instance)):
    response = await ids.stopAnalysis()    
    return response

async def tell_core_analysis_has_finished(container_id: int):
    # tell the core to stop/set status to idle again
    core_url = await get_env_variable("CORE_URL")
    endpoint = f"/ids/analysis/finish/{container_id}"
    async with httpx.AsyncClient() as client:
        response: HTTPResponse = await client.post(core_url+endpoint)
    return response