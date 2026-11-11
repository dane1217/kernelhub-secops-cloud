"""OIDC authorization code + PKCE. Tokens remain on the server; DB sessions are opaque."""
import base64
from datetime import timedelta
import hashlib
import hmac
import secrets
import urllib.parse
import jwt

from .adapters import request_json
from .events import now, parse_time
from .service import Principal, Problem, audit, digest


class Authentication:
    def __init__(self, db, service, settings):
        self.db, self.service, self.settings = db, service, settings
        self.jwks = jwt.PyJWKClient(settings.oidc_base_internal+"/protocol/openid-connect/certs", timeout=5, lifespan=300)

    def begin(self):
        state, verifier, nonce = (secrets.token_urlsafe(32) for _ in range(3))
        with self.db.transaction() as tx:
            tx.execute("DELETE FROM oidc_states WHERE expires_at<?", (now(),))
            tx.execute("INSERT INTO oidc_states VALUES (?,?,?,?)", (digest(state), verifier, nonce, (parse_time(now())+timedelta(minutes=5)).isoformat()))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        return state, self.settings.issuer+"/protocol/openid-connect/auth?"+urllib.parse.urlencode({
            "client_id": self.settings.client_id, "redirect_uri": self.settings.public_url+"/auth/callback",
            "response_type": "code", "scope": "openid profile email", "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256"})

    def callback(self, state, cookie_state, code):
        if not cookie_state or not hmac.compare_digest(state, cookie_state):
            raise Problem(401, "invalid login state")
        with self.db.transaction() as tx:
            lock = " FOR UPDATE" if tx.postgres else ""
            stored = tx.one("SELECT * FROM oidc_states WHERE state_hash=?"+lock, (digest(state),))
            if not stored or stored["expires_at"] <= now():
                raise Problem(401, "expired login state")
            tx.execute("DELETE FROM oidc_states WHERE state_hash=?", (digest(state),))
        try:
            tokens = request_json(self.settings.oidc_base_internal+"/protocol/openid-connect/token", "POST",
                urllib.parse.urlencode({"grant_type": "authorization_code", "code": code,
                    "redirect_uri": self.settings.public_url+"/auth/callback", "client_id": self.settings.client_id,
                    "client_secret": self.settings.client_secret, "code_verifier": stored["verifier"]}).encode(),
                {"Content-Type": "application/x-www-form-urlencoded"})
            encoded = tokens["id_token"]
            key = self.jwks.get_signing_key_from_jwt(encoded).key
            claims = jwt.decode(encoded, key, algorithms=["RS256"], audience=self.settings.client_id,
                                issuer=self.settings.issuer, options={"require": ["exp", "iat", "iss", "sub", "aud", "nonce", "email"]})
            if not hmac.compare_digest(claims["nonce"], stored["nonce"]) or claims.get("email_verified") is not True:
                raise ValueError("unverified identity")
        except Exception as exc:
            raise Problem(401, "identity verification failed") from exc
        principal = self.service.register_identity(claims["sub"], claims["email"], self.settings.bootstrap_subject)
        session, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.db.transaction() as tx:
            tx.execute("INSERT INTO sessions VALUES (?,?,?,?)", (digest(session), principal.user_id, csrf, (parse_time(now())+timedelta(minutes=30)).isoformat()))
            audit(tx, None, principal.user_id, "session.login", principal.user_id)
        return session

    def session(self, token):
        if not token:
            raise Problem(401, "sign in required")
        with self.db.transaction() as tx:
            row = tx.one("SELECT s.csrf,s.expires_at,u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?", (digest(token),))
            if not row or row["expires_at"] <= now():
                raise Problem(401, "session expired")
            return Principal(row["id"], bool(row["platform_admin"])), row["csrf"], row["email"]

    def logout(self, token):
        with self.db.transaction() as tx:
            row = tx.one("SELECT user_id FROM sessions WHERE token_hash=?", (digest(token),))
            tx.execute("DELETE FROM sessions WHERE token_hash=?", (digest(token),))
            if row:
                audit(tx, None, row["user_id"], "session.logout", row["user_id"])
