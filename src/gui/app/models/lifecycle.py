"""Optional lifecycle controls shared by stop and removal routes."""

from pydantic import BaseModel, StrictBool


class NodeStopOptions(BaseModel):
    force: StrictBool = False
