import sys
import traceback


class _SafeDict(dict):
    def __missing__(self, key):
        return ''#'{' + str(key) + '}'

def safe_format(msg, data=None, **kw):
    return (msg or '').format_map(_SafeDict(data or {}, **kw))

class RequestError(Exception):
    status_code = 500
    payload = None
    headers = None
    def __init__(self, message=None, status_code=None, data=None, headers=None, format=False):
        self.status_code = status_code or self.status_code
        self.payload = dict(self.payload or {}, **(data or {}))
        self.headers = dict(self.headers or {}, **(headers or {}))
        # get message
        if format:
            message = safe_format(message, self.payload) or None
        self.message = message or self.default_message
        super().__init__(self.message)

    @property
    def default_message(self):
        if 'message' in self.payload:
            msg = '{type}: {message}' if 'type' in self.payload else '{message}'
            if 'traceback' in self.payload:
                msg += '\n\nRequest Traceback:\n{traceback}'
            return safe_format(msg, **self.payload).strip()

        elif self.payload:
            return 'Error with unknown format: {}'.format(self.payload)
        return 'error {}'.format(self.status_code)

    @classmethod
    def from_response(cls, resp, additional_message=None, defaults=None):
        defaults = dict({
            'type': 'Exception from server', 
            'message': 'The server returned an error response.', 
            'traceback': 'no traceback given in response: {}'.format(resp)
        }, **(defaults or {}))
        # TODO: drop server traceback if none exists
        return cls(
            ('{} - '.format(additional_message) if additional_message else '') + 
            '{type}: {message}\n\nServer Traceback:\n{traceback}'.format(**dict(defaults, **resp)), data=resp)

class Unauthorized(RequestError):
    status_code = 401
    default_message = 'Insufficient privileges'
    headers = {'WWW-Authenticate': 'Bearer'}
    traceback_in_response = False


def exc2response(exc, asresponse=False, include_tb=None, show_tb=True):
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

    # possibly add traceback
    if include_tb is None:
        include_tb = getattr(exc, 'traceback_in_response', not handle_payload)
    if include_tb:
        payload.setdefault('traceback', traceback.format_exc())

    if show_tb == 'short':
        sys.stderr.write('Raised Exception {type}: {message}\n'.format(**payload))
    elif show_tb:
        traceback.print_exc(file=sys.stderr)

    if asresponse:
        import flask
        payload = flask.jsonify(payload)
    return payload, getattr(exc, 'status_code', 500), getattr(exc, 'headers', {})
