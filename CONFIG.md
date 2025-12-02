OIDC config needed
==================

Before running the container, set these env vars (see `oidc_app/config.py`) so the IdP accepts your client:

- `CLIENT_ID` and `REDIRECT_URI`: register the redirect URI your client will actually use; any other redirect will be rejected.
- `RP_ID`: the relying party domain your client uses for WebAuthn.
- `OIDC_ISSUER`: the public URL of the IdP (use your localhost URL if testing locally).
- `OIDC_ISSUER_BACKEND`: the internal/back URL the container uses (use the Docker-internal host:port if it differs from the public one).

With those set to your own URLs/domains, the IdP will accept auth and token requests from your client.

Current sample values (as shipped):
- `OIDC_ISSUER`: `https://idp.licorice-us.eu`
- `OIDC_ISSUER_BACKEND`: `https://idp.licorice-us.eu`
- `CLIENT_ID`: `android-test-client`
- `REDIRECT_URI`: `myapp://callback`
- `RP_ID`: `licorice-us.eu`

If bioserver is down please contact `clancha@us.es`