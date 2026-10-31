#!/bin/zsh
set -e

cd "$(dirname "$0")"

if [ ! -f "venv/bin/activate" ]; then
  echo "Run ./setup.sh first."
  exit 1
fi

source venv/bin/activate
python -m src.rag.build_index
python -m src.detect   "Your Chase account has been suspended. Verify now at http://secure-login.xyz"   --name Robert
