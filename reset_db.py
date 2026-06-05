# reset_db.py  (run once, then delete)
from src.core.database import engine
from src.shared.models import SQLModel  # ensures all models are registered

# Import the models module so every table is registered on the metadata
import src.shared.models  # noqa

SQLModel.metadata.drop_all(engine)
SQLModel.metadata.create_all(engine)
print("Schema dropped and recreated.")