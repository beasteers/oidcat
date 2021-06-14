# Changelog

## Feature Thoughts
 - Coerce `oidcat.RequestError` to more closely match `werkzeurg.HTTPError` with attributes like `description`, etc. Because then maybe `oidcat` errors could be handled like other `flask` errors and avoid confusion about different error json formats. But this would have to be a Major version upgrade.
 - add token signature validation to the token object (?)
 - add token blacklist checking - idk if this can be done thru something in the well-known config?

## 0.5.0
 - Added proper RTD docs, including a bunch of docstrings
 - Moved version specification into `__version__.py`. idk just trying out a different format for packages.
 - Did a lot of cleanup and removed a bunch of unnecessary code, assignments, etc.
 - Removed `Access(store_pass)` because it's honestly just not the right way to do it. use offline tokens instead `Access(offline=True)`!
 - Added `Access(discard_credentials)` which lets users be more strict and not store the username and password on the object.
    - Honestly, I'm not sure if this is really a big concern, but it's easy enough to remove if we find it unnecessary
 - Moved `refresh_buffer` and `refresh_token_buffer` into `WellKnown` instead of `Access` seeing as all it was getting used for was being passed to `WellKnown` anyways.
 - Made the use of `refresh_token_buffer` more consistent. it wasn't being used when getting a new refresh token which may have caused some temporary unauthorized access calls at some point.
 - Added a new exception base class `AuthenticationError` which `Unauthorized` subclasses. This is meant to capture both unauthorized errors from the server and from lack of credentials when authenticating, etc.
 - removed empty traceback message from `from_response` output message
 - Renamed `oidcat.Session`'s first argument `well_known_url` to `auth_url` for improved clarity.
 - Added `oidcat.response_json` which parses the json response and handles some errors: 
   - `oidcat` exception payloads returned from the server
   - "502 Bad Gateway" errors that get returned by nginx
 - Renamed `oidcat.util.get_redirect_uris` to `oidcat.util._get_redirect_uris` since it isn't a public API
 - Added more util tests
 - Added `Env().set(varA=5, varB=10);assert Env().varA == '5'` interface to set environment variables. (casts them to string because that's how env vars gotta be)

## 0.4.14
 - fixed key error for `{'error': 'unknown_error'}` in well known token query
 - Improved token validity error messages
 - fix ignored scopes in well-known token querying
 - importing `safe_format` into `util` as that is a more sensible place for it (needs to stay in `exceptions` to prevent circular import tho)
 - fixed error messages getting ignored due to falsey ErrStr class from flask_oidc
 - added `exc2response(..., include_tb=None, show_tb=True)` arguments which allow you to control when to include the traceback in the response and when to log to console.
   - `include_tb` is used for example if we want to only show tracebacks for certain users (conditional on token roles)
 - added `RequestError.from_response(..., additional_message)` which allows you to pass more contextual info
 - Added changelog !

Better late then never!