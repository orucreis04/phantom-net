from __future__ import annotations

import socketserver
from typing import Callable

from .detector import BehaviorDetector
from .models import Event
from .storage import EventStore


class DecoyTCPHandler(socketserver.BaseRequestHandler):
    service_name: str
    banner: str
    store: EventStore
    detector: BehaviorDetector

    def handle(self) -> None:
        source_ip = self.client_address[0]
        self.request.sendall(self.banner.encode("utf-8", errors="ignore"))
        try:
            payload = self.request.recv(1024).decode("utf-8", errors="replace")
        except OSError:
            payload = ""
        event = Event(
            source_ip=source_ip,
            service=self.service_name,
            event_type="tcp_probe",
            payload=payload[:1000],
        )
        self.store.add_event(self.detector.enrich(event))
        if self.service_name == "ssh":
            self.request.sendall(b"Permission denied, please try again.\r\n")
        else:
            self.request.sendall(b"ERR temporary backend failure\r\n")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_tcp_server(
    host: str,
    port: int,
    service_name: str,
    banner: str,
    store: EventStore,
    detector: BehaviorDetector,
) -> ThreadedTCPServer:
    handler: Callable[..., DecoyTCPHandler] = type(
        f"{service_name.title()}DecoyHandler",
        (DecoyTCPHandler,),
        {
            "service_name": service_name,
            "banner": banner,
            "store": store,
            "detector": detector,
        },
    )
    return ThreadedTCPServer((host, port), handler)
