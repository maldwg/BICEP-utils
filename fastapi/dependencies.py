from fastapi import Request
from ..models.ids_base import IDSBase


def get_ids_instance(request: Request) -> IDSBase:
    return request.app.state.ids_instance