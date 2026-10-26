#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Meta Muse AI - Local Showcase Web Server
----------------------------------------
Lightweight HTTP server serving the Muse AI Introduction Landing Page.
Runs natively using Python built-in http.server on port 3000.
"""

import http.server
import socketserver
import os

PORT = 3000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Meta Muse AI Showcase Server running at: http://127.0.0.1:{PORT}")
        httpd.serve_forever()
