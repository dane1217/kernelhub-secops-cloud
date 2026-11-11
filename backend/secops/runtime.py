from .adapters import OpenSearch, S3Objects
from .config import Settings
from .db import Database
from .service import Service


def build():
    settings = Settings().validate()
    db = Database(settings.database_url)
    service = Service(db, OpenSearch(settings.opensearch_url, settings.opensearch_user, settings.opensearch_password),
                      S3Objects(settings.s3_bucket, settings.s3_endpoint, settings.environment != "development"))
    return settings, db, service
