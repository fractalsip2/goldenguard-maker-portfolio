# GoldenGuard

An SMS-based scam-warning service designed for older adults. Instead of downloading an app, registered users can text a suspicious message to GoldenGuard and receive a personalized warning with practical next steps.

The backend combines an English-language **TF-IDF / logistic regression classifier** with explicit scam indicators and contextual rules. It classifies warning signs, identifies a likely scam category, and uses deterministic templates to compose replies. Twilio handles incoming and outgoing SMS; a separate account service authorizes registered phone numbers.

## What I worked on

I started GoldenGuard by figuring out how to turn a scam-detection algorithm into something people could actually use over SMS. I researched different libraries and frameworks, eventually choosing scikit-learn for the TF-IDF and logistic regression classifier, joblib for storing the trained model, and FastAPI and Uvicorn for the backend. I also decided to supplement the classifier with hard-coded rules for specific scam indicators, rather than relying entirely on the model's predictions.

A lot of my time went into testing the detector and finding where its logic failed. For example, a harmless "hey bro, wanna hang out?" message received an overly serious warning, while an obvious grandparent scam asking for bail money wasn't flagged strongly enough. I came up with different edge cases, examined the risk scores and classifications, and used the results to guide adjustments to the rules. I also worked on deciding how the final response should be structured, including the risk level, scam category, explanation, and recommended actions.

The other major challenge was getting everything connected. I had to figure out how Twilio would send incoming messages to a FastAPI webhook, pass them through the detector, and return the result as an SMS. Since Twilio couldn't reach my localhost server, I used a Cloudflare tunnel for local testing before deploying the backend on Render. I then worked through integrating the backend with the website's PostgreSQL-backed member system so it could recognize registered phone numbers and retrieve users' names and preferred languages. This also involved troubleshooting authentication errors between the two services, including repeated HTTP 401 responses.

Getting the classifier to work locally was relatively straightforward compared to getting the entire system to function together. I spent considerably more time testing messages, troubleshooting integrations, and figuring out why something that worked on my laptop wasn't necessarily working through an actual phone number.

This project involved significant AI coding assistance. See [Contributions and sources](CONTRIBUTIONS.md) for a specific breakdown.

## A note on live SMS testing

A few of my test messages have triggered Twilio's message-filtering error (30007), so occasionally a reply doesn't reach my phone even though GoldenGuard processed the text. I've mainly seen this when repeatedly testing similar USPS scams. I'm aware of the issue and plan to contact Twilio and adjust the SMS replies to reduce the filtering.

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
