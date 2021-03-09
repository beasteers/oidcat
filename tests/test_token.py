import pytest
import time
import datetime
import oidcat


EXAMPLE_TOKEN = 'eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAiWmxpZktlMnRwYkRsQWhlenZSS2h6aXl5YzZZR0JYMV9lb0dUUUFuM1NYMCJ9.eyJqdGkiOiAiMjFmYWY2MmQtYjI2NS00YTc4LTgzNmQtMWM3ZGM3ZjcwODk0IiwgImV4cCI6IDE2MTQ3Mzk3NDYsICJuYmYiOiAwLCAiaWF0IjogMTYxNDczOTE0NiwgImlzcyI6ICJodHRwczovL2Fkc2Zhc2RmYXNkZi5jb20vYXV0aC9yZWFsbXMvbWFzdGVyIiwgImF1ZCI6ICJhY2NvdW50IiwgInN1YiI6ICI1MDU5Y2ZjZC1hNGFhLTRiN2UtODUxNC1jMjkyYzZkODdkZWMiLCAidHlwIjogIkJlYXJlciIsICJhenAiOiAiaW5nZXN0IiwgImF1dGhfdGltZSI6IDAsICJzZXNzaW9uX3N0YXRlIjogImExYjhhMDdkLWMyOTktNDM0Yi05NWZhLTgzNzQyNTZkYmZkMSIsICJhY3IiOiAiMSIsICJhbGxvd2VkLW9yaWdpbnMiOiBbImh0dHBzOi8vYXNkZmFzZGYuY29tIl0sICJyZWFsbV9hY2Nlc3MiOiB7InJvbGVzIjogWyJvZmZsaW5lX2FjY2VzcyIsICJ1bWFfYXV0aG9yaXphdGlvbiIsICJwYXJ0aWNpcGFudCJdfSwgInJlc291cmNlX2FjY2VzcyI6IHsiYWNjb3VudCI6IHsicm9sZXMiOiBbIm1hbmFnZS1hY2NvdW50IiwgIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwgInZpZXctcHJvZmlsZSJdfX0sICJzY29wZSI6ICJlbWFpbCBwcm9maWxlIiwgImVtYWlsX3ZlcmlmaWVkIjogZmFsc2UsICJuYW1lIjogIkJvbyBhc2RmIiwgImRlcGxveW1lbnRfaWQiOiBbImRlcGxveW1lbnQtYWJjZGVmZ2hpIl0sICJwcmVmZXJyZWRfdXNlcm5hbWUiOiAiaW1zcGFtIiwgImdpdmVuX25hbWUiOiAiQm9vIiwgImZhbWlseV9uYW1lIjogImFzZGYiLCAiZW1haWwiOiAiYXNkZkBhZHNmLmNvbSJ9.fXi_-4a7vwrsJgLPiKpnWeG5ILIe1GeahtysW1gsepGBXLmpgpzP-wXoxsLpOMT3SsyEJjpaUCauYUqVzS10zSUP8y8yoej3nl38RmmPF5TRV6-_r9kOZUowO148RTF5vMvYxrPfNSb23jRy91J5PZMcbBNTzXGu4jFYW0tNonwCFLjjOYQlM7JmkaqoVPNYh1umR8MGaaXnjhXnS98cM0SiCSferhqcb8dlNV0ffiMDOzWUs15gfV07TF6qOz3u5KdIgS4AGvfJ--SnQlpVY2FL0ogom-_smUQVoLbrGEH27zbTog4qCq_Jxi2_BBWhtwmuRs6llJkFDVB3hvi2eg'

TOKEN_DATA = {
    'jti': '21faf62d-b265-4a78-836d-1c7dc7f70894',
    'exp': 1614739746,
    'nbf': 0,
    'iat': 1614739146,
    'iss': 'https://adsfasdfasdf.com/auth/realms/master',
    'aud': 'account',
    'sub': '5059cfcd-a4aa-4b7e-8514-c292c6d87dec',
    'typ': 'Bearer',
    'azp': 'ingest',
    'auth_time': 0,
    'session_state': 'a1b8a07d-c299-434b-95fa-8374256dbfd1',
    'acr': '1',
    'allowed-origins': ['https://asdfasdf.com'],
    'realm_access': {
        'roles': ['offline_access', 'uma_authorization', 'participant']
    },
    'resource_access': {
        'account': {
            'roles': ['manage-account', 'manage-account-links', 'view-profile']
        }
    },
    'scope': 'email profile',
    'email_verified': False,
    'name': 'Boo asdf',
    'deployment_id': ['deployment-abcdefghi'],
    'preferred_username': 'imspam',
    'given_name': 'Boo',
    'family_name': 'asdf',
    'email': 'asdf@adsf.com'
}

GIBBERISH = 'sblakdfjbafpiiweiuhfchxnkjlwhnqjhflwxhoquieonefflkxjwhelnhioqwfxhouiefqhxf71n4178xh53quxhnoxfhnq3'


def test_token():
    t = oidcat.Token(EXAMPLE_TOKEN)

def test_empty_token():
    t = oidcat.Token()
    assert not t
    assert dict(t) == {}

def test_token_data_access():
    t = oidcat.Token(EXAMPLE_TOKEN)
    # assert that it works like a dict
    assert dict(t) == TOKEN_DATA
    for k in TOKEN_DATA:
        assert t[k] == TOKEN_DATA[k]
        assert getattr(t, k) == TOKEN_DATA[k]
    with pytest.raises(KeyError):
        t['asdfasdfasdfasfsadbakshfkvajbdfkjvbakfjbvajkbf']
    with pytest.raises(AttributeError):
        t.asdfasdfasdfasfsadbakshfkvajbdfkjvbakfjbvajkbf

def test_token_expiration():
    # test token expiration
    DT = 0.5
    exp = datetime.datetime.now() + datetime.timedelta(seconds=DT)
    tokenstr = oidcat.token.mod_token(EXAMPLE_TOKEN, exp=datetime.datetime.timestamp(exp))
    t = oidcat.Token(tokenstr, buffer=DT/2)
    assert round(t.time_left.total_seconds(), 1) == DT
    assert t
    assert t.valid
    time.sleep(DT/2)
    assert not t
    assert t.valid
    time.sleep(DT/2)
    assert round(t.time_left.total_seconds(), 1) == 0
    assert not t
    assert not t.valid

def test_token_roles():
    t = oidcat.Token(EXAMPLE_TOKEN)
    realm = TOKEN_DATA['realm_access']['roles']
    client = TOKEN_DATA['resource_access']['account']['roles']
    # test any role check
    assert t.get_roles(client_id='account') == (realm+client, realm, client)
    assert t.has_role(realm[0], client_id='account')
    assert t.has_role(realm[0], GIBBERISH, client_id='account')
    assert not t.has_role(GIBBERISH, client_id='account')
    # test specific role scopes
    assert t.has_role(realm=realm[0], client_id='account')
    assert t.has_role(client=client[0], client_id='account')
    assert not t.has_role(realm=client[0], client_id='account')
    assert not t.has_role(client=realm[0], client_id='account')
    assert not t.has_role(realm=GIBBERISH, client_id='account')
    assert not t.has_role(client=GIBBERISH, client_id='account')

    # TODO: be more systematic
    assert t.check_roles(*realm) == [True] * len(realm)
    assert t.check_roles(*realm, realm_only=True) == [True] * len(realm)
    assert t.check_roles(*realm, required=True) == [True] * len(realm)
    assert t.check_roles(*realm, GIBBERISH, required=True) == [True] * len(realm) + [False]

    assert t.check_roles(GIBBERISH) == [False]
    assert t.check_roles(GIBBERISH, realm_only=True) == [False]
    assert t.check_roles(GIBBERISH, client_only=True) == [False]

    assert t.check_roles(*client, required=True) == [True] * len(client)
    assert t.check_roles(*client, realm_only=True) == [False] * len(realm)

    with pytest.raises(oidcat.Unauthorized):
        assert t.check_roles(*client, realm_only=True, required=True)
    with pytest.raises(oidcat.Unauthorized):
        assert t.check_roles(*client, client_id=GIBBERISH, required=True)
    with pytest.raises(oidcat.Unauthorized):
        assert t.check_roles(*realm, client_only=True, required=True)
    with pytest.raises(oidcat.Unauthorized):
        assert t.check_roles(GIBBERISH, required=True)
