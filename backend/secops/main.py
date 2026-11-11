from .api import create_app
from .auth import Authentication
from .runtime import build

settings, db, service = build()
app = create_app(service, Authentication(db, service, settings), settings)
