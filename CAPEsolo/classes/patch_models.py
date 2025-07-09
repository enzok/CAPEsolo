from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PatchEntry:
    address: int
    patchedBytes: str
    instruction: str
    originalBytes: str = ""
    timeStamp: datetime = field(default_factory=datetime.now)
