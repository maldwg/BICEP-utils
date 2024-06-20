from pydantic import BaseModel
from typing import Optional

class NetworkAnalysisData(BaseModel):
    """

    """
    container_id: Optional[int]
    ensemble_id: Optional[int]


class StaticAnalysisData(BaseModel):
    """

    """
    container_id: Optional[int]
    ensemble_id: Optional[int]
    dataset_id: int