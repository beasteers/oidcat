import sys
import traceback
import flask


class RequestError(Exception):
    status_code = 500
    default_message = None
    payload = {}
    headers = {}
    def __init__(self, message=None, status_code=None, headers=None, payload=None):
        self.message = message or self.default_message
        super().__init__(self.message)
        self.status_code = status_code or self.status_code
        self.payload = dict(self.payload, **(payload or {}))
        self.headers = dict(self.headers, **(headers or {}))

class Unauthorized(RequestError):
    status_code = 401
    default_message = 'Insufficient privileges'
    headers = {'WWW-Authenticate': 'Bearer'}


def exc2response(exc):
    traceback.print_exc(file=sys.stderr)
    return flask.jsonify({
        'error': True,
        'type': type(exc).__name__,
        'message': getattr(exc, 'message', None) or str(exc),
        'traceback': traceback.format_exc(),
        **(getattr(exc, 'payload', None) or {})
    }), getattr(exc, 'status_code', 500), getattr(exc, 'headers', {})
