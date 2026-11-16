"""Local development configuration helpers."""

from pathlib import Path

from dotenv import load_dotenv


def load_local_environment() -> None:
    """Load the project's untracked .env file for local development."""
    project_root = Path(__file__).resolve().parents[1]
    load_dotenv(project_root / '.env')
