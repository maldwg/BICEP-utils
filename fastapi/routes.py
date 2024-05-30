from http.client import HTTPException
from fastapi import APIRouter, Depends, UploadFile
from ..models.ids_base import IDSBase
from .dependencies import get_ids_instance
router = APIRouter()



# TODO: negotioate endpoints 
# prepare execution by the idsbase 
# implementation for suricata
# adapt core and database
# test

@router.get("/healthcheck")
async def healthcheck():
    return {"message": "healthy"}

@router.post("/configuration")
async def test(file: UploadFile = None ,ids: IDSBase = Depends(get_ids_instance)):
    if file is None:
        raise HTTPException(status_code=400, detail="No file provided")
    
    temporary_file = "/tmp/temporary.txt"
    with open(temporary_file, "wb") as f:
        f.write(await file.read())
    return {"message": ids.configure(temporary_file)}

