# GoldenGuard

An SMS-based scam-warning service designed for older adults. Instead of downloading an app, registered users can text a suspicious message to GoldenGuard and receive a personalized warning with practical next steps.

The backend combines an English-language **TF-IDF / logistic regression classifier** with explicit scam indicators and contextual rules. It classifies warning signs, identifies a likely scam category, and uses deterministic templates to compose replies. Twilio handles incoming and outgoing SMS; a separate account service authorizes registered phone numbers.

## What I worked on

I chose SMS as the interface, established the overall classifier-and-rules approach, tested edge cases, and iterated on cases where the detector got things wrong. One of the earliest problems: innocent texts like "hey bro u wanna hang out?" were flagged too strongly while some family-emergency scams received weak warnings. I also worked through making the local detector accessible through Twilio webhooks and deployment.

This project involved significant AI coding assistance. See [Contributions and sources](CONTRIBUTIONS.md) for a specific breakdown rather than treating the repository as entirely handwritten code.

## Run it locally

Requires Python 3.12. A local demonstration works **without Twilio credentials, a real phone number, or the production member database**.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

# Rebuild the model and retrieval index using the included data/resources
python -m src.trainer
python -m src.rag.build_index

# Two messages I used to probe the system
python -m src.detect "hey bro u wanna hang out on saturday? dinners on me" --name Alex --language en
python -m src.detect "Grandma, I got arrested and need money for bail. Don't tell Mom." --name Alex --language en

# Run the existing automated tests
python -m pytest -q
```

The trained `.joblib` file is intentionally not committed; the training command above regenerates it from the included labeled messages. A running public SMS demonstration additionally requires Twilio credentials and the companion registered-member service.

## Where to look

| File | Role |
| --- | --- |
| [src/trainer.py](src/trainer.py) | TF-IDF feature extraction and logistic regression training |
| [src/detector.py](src/detector.py) | Main detection pipeline |
| [src/rules.py](src/rules.py) | Scam indicators and benign-context rules |
| [src/scam_types.py](src/scam_types.py) | Scam-type classification |
| [src/response.py](src/response.py) and [src/sms_response.py](src/sms_response.py) | Personalized responses and SMS formatting |
| [src/rag/](src/rag/) and [knowledge/](knowledge/) | Local retrieval of curated fraud-prevention resources |
| [api.py](api.py) | FastAPI endpoints and Twilio webhook |
| [tests/](tests/) | Regression tests for tricky examples and integration behavior |

## Limitations

GoldenGuard is an experimental scam-warning tool, not a verified fraud detector. It can miss emerging scams or flag legitimate messages. The training data is primarily English, and its risk ratings are not calibrated probabilities. The running detector does **not** call ChatGPT to analyze messages.

Training data includes the [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection). Safety resources reference FTC, AARP, and USPS publications. See [CONTRIBUTIONS.md](CONTRIBUTIONS.md) and [REVIEWER_GUIDE.md](REVIEWER_GUIDE.md).
