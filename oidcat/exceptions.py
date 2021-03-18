import sys
import traceback


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
    traceback_in_response = False


def exc2response(exc):
    import flask
    # build error payload
    payload = {
        'error': True,
        'type': type(exc).__name__,
        'message': getattr(exc, 'message', None) or str(exc),
        **(getattr(exc, 'payload', None) or {})
    }

    # allow arbitrary functionality
    handle_payload = getattr(exc, 'handle_payload', None)
    if handle_payload is not None:
        handle_payload(payload)

    if getattr(exc, 'traceback_in_response', not handle_payload):
        traceback.print_exc(file=sys.stderr)
        payload.setdefault('traceback', traceback.format_exc())
    else:
        sys.stderr.write('Raised Exception {type}: {message}\n'.format(**payload))
    return flask.jsonify(payload), getattr(exc, 'status_code', 500), getattr(exc, 'headers', {})
