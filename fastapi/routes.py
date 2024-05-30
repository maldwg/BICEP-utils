from fastapi import APIRouter, Depends
from ..models.ids_base import IDSBase
from .dependencies import get_ids_instance
router = APIRouter()



@router.get("/")
async def test(ids: IDSBase = Depends(get_ids_instance)):
    return {"message": ids.configure()}