from dataclasses import dataclass, field


@dataclass
class BurpRequest:
    content: str
    hostname: str
    port: int
    https: bool

    @property
    def url(self) -> str:
        scheme = "https" if self.https else "http"
        return f"{scheme}://{self.hostname}:{self.port}"


@dataclass
class BurpResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw: str = ""


@dataclass
class ProxyHistoryItem:
    request: BurpRequest | None = None
    response: BurpResponse | None = None
    url: str = ""
    method: str = ""
    timestamp: int = 0
