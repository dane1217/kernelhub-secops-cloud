import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Settings:
    environment: str = os.getenv("APP_ENV", "development")
    database_url: str = os.getenv("DATABASE_URL", "")
    public_url: str = os.getenv("PUBLIC_URL", "http://localhost:8080")
    product_name: str = os.getenv("PRODUCT_NAME", "KernelHub SecOps Cloud")
    brand_mark: str = os.getenv("BRAND_MARK", "K")
    brand_accent: str = os.getenv("BRAND_ACCENT", "#47e6bd")
    issuer: str = os.getenv("OIDC_ISSUER", "http://localhost:8080/idp/realms/kernelhub")
    oidc_base_internal: str = os.getenv("OIDC_INTERNAL_BASE", "http://keycloak:8080/idp/realms/kernelhub")
    client_id: str = os.getenv("OIDC_CLIENT_ID", "secops-web")
    client_secret: str = os.getenv("OIDC_CLIENT_SECRET", "")
    bootstrap_subject: str = os.getenv("BOOTSTRAP_SUBJECT", "")
    opensearch_url: str = os.getenv("OPENSEARCH_URL", "http://opensearch:9200")
    opensearch_user: str = os.getenv("OPENSEARCH_USER", "")
    opensearch_password: str = os.getenv("OPENSEARCH_PASSWORD", "")
    s3_bucket: str = os.getenv("S3_BUCKET", "secops-events")
    s3_endpoint: str = os.getenv("S3_ENDPOINT", "http://objects:8333")
    broker_url: str = os.getenv("BROKER_URL", "redis://redis:6379/0")

    def validate(self):
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", self.brand_accent) or not 1 <= len(self.brand_mark) <= 3:
            raise ValueError("invalid branding configuration")
        if not self.database_url.startswith("postgresql://"):
            raise ValueError("deployment requires PostgreSQL")
        if self.environment not in ("development", "staging", "production"):
            raise ValueError("invalid environment")
        if self.environment != "development":
            for url in (self.public_url, self.issuer, self.oidc_base_internal, self.opensearch_url):
                if urlparse(url).scheme != "https":
                    raise ValueError("staging/production require verified TLS for HTTP services")
            if not self.broker_url.startswith("rediss://") or "sslmode=verify-full" not in self.database_url:
                raise ValueError("staging/production require verified database and broker TLS")
            if self.s3_endpoint and not self.s3_endpoint.startswith("https://"):
                raise ValueError("object storage requires TLS")
        return self
