#!/bin/zsh
set -e

cd "$(dirname "$0")"

if ! command -v python3.12 >/dev/null 2>&1; then
  echo "Python 3.12 is required."
  echo "Install it with: brew install python@3.12"
  exit 1
fi

echo "Creating a clean Python 3.12 environment..."
rm -rf venv
python3.12 -m venv venv

echo "Installing dependencies..."
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "Training the local scam-detection model..."
python -m src.trainer

echo "Building the local RAG index..."
python -m src.rag.build_index

echo "Running tests..."
python -m pytest -q

echo ""
echo "GoldenGuard local MVP is ready."
echo "Test it with:"
echo './test_mvp.sh'
