"""Create local-only secrets and an OTP-protected Keycloak realm. Does not overwrite."""
import json
from pathlib import Path
import secrets
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    target = ROOT / ".env"
    if target.exists() or (ROOT / ".local" / "realm.json").exists():
        raise SystemExit("Local configuration already exists; refusing to replace credentials.")
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    values = {k: secrets.token_hex(24) for k in ("POSTGRES_PASSWORD", "DB_APP_PASSWORD", "DB_MIGRATION_PASSWORD", "KEYCLOAK_DB_PASSWORD", "KEYCLOAK_ADMIN_PASSWORD", "REDIS_PASSWORD", "OIDC_CLIENT_SECRET", "AWS_SECRET_ACCESS_KEY")}
    subject = str(uuid.uuid4())
    password = secrets.token_urlsafe(24)
    values.update(APP_ENV="development", PUBLIC_URL="http://localhost:8080", PRODUCT_NAME="KernelHub SecOps Cloud",
        DATABASE_URL=f"postgresql://secops_app:{values['DB_APP_PASSWORD']}@postgres/secops",
        MIGRATION_DATABASE_URL=f"postgresql://secops_migration:{values['DB_MIGRATION_PASSWORD']}@postgres/secops",
        BROKER_URL=f"redis://:{values['REDIS_PASSWORD']}@redis:6379/0",
        OIDC_ISSUER="http://localhost:8080/idp/realms/kernelhub", OIDC_INTERNAL_BASE="http://keycloak:8080/idp/realms/kernelhub",
        OIDC_CLIENT_ID="secops-web", BOOTSTRAP_SUBJECT=subject, OPENSEARCH_URL="http://opensearch:9200",
        S3_ENDPOINT="http://objects:8333", S3_BUCKET="secops-events", AWS_ACCESS_KEY_ID="secops-local", AWS_DEFAULT_REGION="us-east-1")
    target.write_text("\n".join(f'{k}="{v}"' for k,v in values.items())+"\n", encoding="utf-8")
    (local / "pg-init.sql").write_text(f"""CREATE ROLE secops_migration LOGIN PASSWORD '{values['DB_MIGRATION_PASSWORD']}';
CREATE ROLE secops_app LOGIN PASSWORD '{values['DB_APP_PASSWORD']}';
ALTER DATABASE secops OWNER TO secops_migration;
GRANT CREATE ON SCHEMA public TO secops_migration;
ALTER DEFAULT PRIVILEGES FOR ROLE secops_migration IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO secops_app;
CREATE ROLE keycloak LOGIN PASSWORD '{values['KEYCLOAK_DB_PASSWORD']}';
CREATE DATABASE keycloak OWNER keycloak;
""", encoding="utf-8")
    flows = [
      {"alias":"secops-browser","providerId":"basic-flow","topLevel":True,"builtIn":False,"authenticationExecutions":[
        {"authenticator":"auth-cookie","requirement":"ALTERNATIVE","priority":10,"authenticatorFlow":False},
        {"flowAlias":"secops-forms","requirement":"ALTERNATIVE","priority":20,"authenticatorFlow":True}]},
      {"alias":"secops-forms","providerId":"basic-flow","topLevel":False,"builtIn":False,"authenticationExecutions":[
        {"authenticator":"auth-username-password-form","requirement":"REQUIRED","priority":10,"authenticatorFlow":False},
        {"authenticator":"auth-otp-form","requirement":"REQUIRED","priority":20,"authenticatorFlow":False}]}]
    realm = {"realm":"kernelhub","enabled":True,"sslRequired":"none","registrationAllowed":False,
        "resetPasswordAllowed":False,"bruteForceProtected":True,"browserFlow":"secops-browser",
        "authenticationFlows":flows,"accessTokenLifespan":300,"ssoSessionMaxLifespan":1800,
        "clients":[{"clientId":"secops-web","enabled":True,"protocol":"openid-connect","publicClient":False,
                    "secret":values['OIDC_CLIENT_SECRET'],"standardFlowEnabled":True,"directAccessGrantsEnabled":False,
                    "redirectUris":["http://localhost:8080/auth/callback"],"webOrigins":["http://localhost:8080"],
                    "attributes":{"pkce.code.challenge.method":"S256"},"defaultClientScopes":["profile","email"]}],
        "users":[{"id":subject,"username":"pilot-admin","email":"pilot-admin@example.test","emailVerified":True,
                  "enabled":True,"firstName":"Pilot","lastName":"Administrator","requiredActions":["CONFIGURE_TOTP"],
                  "credentials":[{"type":"password","value":password,"temporary":False}]}]}
    (local/"realm.json").write_text(json.dumps(realm, indent=2), encoding="utf-8")
    (local/"pilot-login.txt").write_text(f"LOCAL DEVELOPMENT ONLY\nURL: http://localhost:8080\nUsername: pilot-admin\nPassword: {password}\nEnroll a real TOTP authenticator on first login.\n", encoding="utf-8")
    print("Local configuration created. Read .local/pilot-login.txt privately, then run docker compose up --build -d.")


if __name__ == "__main__":
    main()
