"""HandoffGuard: a verify-before-revoke offboarding agent for IT infrastructure."""
from pathlib import Path

from .planners import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

__version__ = "1.0.0"
