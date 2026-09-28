"""
P2 project settings.
Loads sensitive values from .env — never hardcode API keys here.
"""

import os

from dotenv import load_dotenv

load_dotenv()

OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen3:4b")
