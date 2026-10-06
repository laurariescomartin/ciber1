from dataclasses import dataclass

import httpx


@dataclass
class ScanContext:
    initial_url: str
    response: httpx.Response

    @property
    def final_url(self) -> str:
        return str(self.response.url)

    @property
    def status_code(self) -> int:
        return self.response.status_code

    @property
    def headers(self):
        return self.response.headers

    @property
    def html(self) -> str:
        return self.response.text