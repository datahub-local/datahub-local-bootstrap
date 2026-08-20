#!/usr/bin/env python3
"""Mint an ArgoCD API token for a local account with the `apiKey` capability.

Reads a JSON object from stdin with the `account`, `signing_key` and
`issued_at` keys, and writes a JSON object with:

  token:  the JWT that API clients use as `Authorization: Bearer <token>`
  tokens: the `accounts.<account>.tokens` metadata that ArgoCD needs in
          argocd-secret to accept the token

The token id is derived from the signing key, so the playbook always mints the
same token instead of rotating it on every run. It never expires: rotate it by
changing `argocd_api_token_signing_key` or `argocd_api_token_issued_at`.
"""

import base64
import hashlib
import hmac
import json
import sys
import uuid


def encode(payload):
    return base64.urlsafe_b64encode(payload).rstrip(b"=")


def encode_claims(claims):
    return encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())


def main():
    params = json.load(sys.stdin)
    account = params["account"]
    issued_at = int(params["issued_at"])
    signing_key = (params["signing_key"] or "").encode()

    if not signing_key:
        sys.exit("argocd_api_token_signing_key must not be empty")

    digest = hashlib.sha256(b":".join([b"argocd-api-token", account.encode(), signing_key]))
    token_id = str(uuid.UUID(digest.hexdigest()[:32]))

    signed = b".".join(
        [
            encode_claims({"alg": "HS256", "typ": "JWT"}),
            encode_claims(
                {
                    "iss": "argocd",
                    "sub": "{0}:apiKey".format(account),
                    "jti": token_id,
                    "iat": issued_at,
                    "nbf": issued_at,
                }
            ),
        ]
    )
    signature = encode(hmac.new(signing_key, signed, hashlib.sha256).digest())

    json.dump(
        {
            "token": b".".join([signed, signature]).decode(),
            "tokens": [{"id": token_id, "iat": issued_at}],
        },
        sys.stdout,
    )


if __name__ == "__main__":
    main()
