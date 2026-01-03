
import uuid
from __init__ import db

class DockerNetwork(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(80), nullable=False, unique=True)
    subnet = db.Column(db.String(40), nullable=True)
    gateway = db.Column(db.String(40), nullable=True)
    driver = db.Column(db.String(20), default="bridge")
