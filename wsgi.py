#!/usr/bin/env python
# This is a WSGI entry point for Gunicorn

from app import app, socketio

# This is the WSGI entry point that Gunicorn will use
application = socketio.middleware(app)

if __name__ == "__main__":
    socketio.run(app)