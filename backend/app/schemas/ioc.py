"""Pydantic schema for IOC."""
from pydantic import BaseModel


class IOCBase(BaseModel):
    value: str
    ioc_type: str
