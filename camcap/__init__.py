"""camcap — intercept, log and replay CGI / ONVIF commands sent to an IP camera.

Layers (see docs/design/camera-command-interceptor-proposal.md §3):

- redirector.py  Windows only. WinDivert rewrites packets destined to the camera
                 so they land on the local Relay, and rewrites the replies back.
- relay.py       Transparent TCP relay. Never modifies bytes; tees them to a decoder.
- decoders.py    Passive protocol decoders (HTTP via h11, RTSP, RAW fallback).
- model.py       Event record, in-memory store, JSONL / HAR export, redaction.
- wsse.py        WS-Security UsernameToken generation / re-signing.
- replay.py      Replays a log against the same or another camera.
- capture.py     Orchestrates redirector + relay for one camera IP.
- app.py / cli.py  pywebview UI and headless CLI.
"""

__version__ = "0.1.0"
