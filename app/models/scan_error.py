from pydantic import BaseModel


class ScanError(BaseModel):
    type: str
    message: str