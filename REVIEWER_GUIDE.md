# GoldenGuard: reviewer quick start

GoldenGuard analyzes suspicious text messages for possible scam indicators and suggests next steps. A local demonstration is available without a Twilio account or live membership record.

## Run locally

Requires Python 3.12:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m src.trainer
python -m src.rag.build_index
python -m src.detect "Grandma, I got arrested and need money for bail. Don't tell Mom." --name Alex --language en
python -m src.detect "hey bro u wanna hang out on saturday? dinners on me" --name Alex --language en
python -m pytest -q
```

The classifier artifact is regenerated locally by the training command above, rather than committed as a binary.

## Architecture

1. `src/trainer.py` fits a TF-IDF + logistic regression text classifier.
2. `src/detector.py` combines the model with heuristics in `src/rules.py` and `src/scam_types.py`.
3. `src/response.py` and `src/sms_response.py` compose risk explanations, practical advice, and reference links.
4. `api.py` provides the SMS webhook and other service endpoints. Production messages are processed only after a separate member-account service authorizes the sender.
5. `tests/` includes regression and integration checks.

## Boundaries and limitations

The portfolio backend alone does not provide public SMS access; the production SMS route also depends on Twilio credentials and a private companion website/account API. Do not use real customer data in your local tests.

The model primarily uses English labeled SMS messages. It can miss evolving scams and sometimes flag innocent messages. Its risk outputs should not be treated as calibrated probabilities or verified fraud decisions. The online classifier is deterministic and does not make live ChatGPT calls.

See [CONTRIBUTIONS.md](CONTRIBUTIONS.md) for AI-assisted implementation, training data, and third-party sources.
