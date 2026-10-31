#!/bin/zsh
set -e

cd "$(dirname "$0")"

if [ ! -f "venv/bin/activate" ]; then
  echo "Run ./setup.sh first."
  exit 1
fi

source venv/bin/activate
python -m uvicorn api:app   --host 127.0.0.1   --port 8000   --loop asyncio
