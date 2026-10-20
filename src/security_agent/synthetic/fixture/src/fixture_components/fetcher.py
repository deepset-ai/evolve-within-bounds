"""Contract-test fixture for the optimizer's code: a small component with one SSRF and one safe twin of it."""

import urllib.request

ALLOWED_HOSTS = {"api.example.com"}


def check_host(url: str) -> str:
    host = url.split("/")[2] if "://" in url else ""
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"host not allowed: {host}")
    return url


class Fetcher:
    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url
        self.timeout = timeout

    def run(self, path: str) -> dict:
        url = self.base_url + path
        with urllib.request.urlopen(url, timeout=self.timeout) as response:
            return {"body": response.read().decode("utf-8")}

    def run_checked(self, path: str) -> dict:
        url = check_host(self.base_url + path)
        with urllib.request.urlopen(url, timeout=self.timeout) as response:
            return {"body": response.read().decode("utf-8")}
