from app import app
from app import config_driver
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:9000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

config_driver(DB_name="memgraph", DB_uri="bolt://127.0.0.1:7687")
