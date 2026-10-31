#!/bin/zsh
set -e

cd "$(dirname "$0")"

if [ ! -f "venv/bin/activate" ]; then
  echo "Run ./setup.sh first."
  exit 1
fi

source venv/bin/activate
python -m src.rag.build_index
python -m pytest -q

echo ""
echo "Routine English demo:"
python -m src.detect \
  "hey bro u wanna hang out on saturday? dinners on me" \
  --name Bob \
  --language en

echo ""
echo "Spanish bank-impersonation demo:"
python -m src.detect \
  "Your Chase account has been suspended. Verify now at chase-help.xyz" \
  --name María \
  --language es

echo ""
echo "Traditional Chinese family-emergency demo:"
python -m src.detect \
  "Grandma I got arrested and need 500 dollars for bail. Send bitcoin and don't tell Mom." \
  --name Mei \
  --language zh-Hant
