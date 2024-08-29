from http.client import HTTPException
from typing import Optional

from fastapi import APIRouter, Depends, UploadFile, Form, Response
from ..models.ids_base import IDSBase
from .dependencies import get_ids_instance
from ..general_utilities import save_file
from ..validation.models import NetworkAnalysisData
import asyncio

router = APIRouter()

@router.get("/healthcheck")
async def healthcheck():
    return {"message": "healthy"}


# TODO: send status codeds and response objects every time

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

@router.post("/configure/ensemble/add/{ensemble_id}")
async def add_to_ensemble(ensemble_id: int, ids: IDSBase = Depends(get_ids_instance)):
    ids.ensemble_id = ensemble_id
    return {"message": f"Added IDS to ensemble {ensemble_id}"}

@router.post("/configure/ensemble/remove")
async def remove_from_ensemble(ids: IDSBase = Depends(get_ids_instance)):
    message = {"message": f"Removed IDS to ensemble {ids.ensemble_id}"}
    ids.ensemble_id = None

    return message


@router.post("/ruleset")
async def test(file: UploadFile = None ,ids: IDSBase = Depends(get_ids_instance)):
    if file is None:
        raise HTTPException(status_code=400, detail="No file provided")

    temporary_file_path = "/tmp/temporary.txt"
    await save_file(file, temporary_file_path)
    response = await ids.configure_ruleset(temporary_file_path)
    return {"message": response}


@router.post("/analysis/static")
async def static_analysis(ensemble_id: Optional[str] = Form(None), dataset_id: str = Form(...), container_id: str = Form(...), dataset: UploadFile = Form(...), ids: IDSBase = Depends(get_ids_instance)):
    if dataset is None:
        raise HTTPException(status_code=400, detail="No file provided")
    
    if ensemble_id != None:
        ids.ensemble_id = int(ensemble_id)

    ids.dataset_id = dataset_id

    temporary_file_path = "/tmp/dataset.pcap"
    await save_file(dataset, temporary_file_path)
    asyncio.create_task(ids.startStaticAnalysis(temporary_file_path))
    ids.static_analysis_running = True
    http_response = Response(content=f"Started analysis for container {container_id}", status_code=200)

    return http_response

@router.post("/analysis/network")
async def network_analysis(network_analysis_data: NetworkAnalysisData, ids: IDSBase = Depends(get_ids_instance)):
    if network_analysis_data.ensemble_id != None:
        ids.ensemble_id = network_analysis_data.ensemble_id

    response = await ids.startNetworkAnalysis()
    return Response(content=response, status_code=200)


# TODO 10: kills the whole process whysoever
@router.post("/analysis/stop")
async def stop_analysis(ids: IDSBase = Depends(get_ids_instance)):
    print("now topping triggered by the endpint")
    await ids.stopAnalysis()  
    print("stopped processes")

    # reset ensemble id to wait if next analysis is for ensemble or ids solo
    if ids.ensemble_id != None:
        ids.ensemble_id = None
  
    if ids.dataset_id != None:
        ids.dataset_id = None
    
    print("set ids to none again")
    response = Response(content="successfully stopped analysis", status_code=200)
    return response