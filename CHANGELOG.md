# Changelog

# 0.4.14
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