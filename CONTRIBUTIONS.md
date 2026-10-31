# Development contributions and outside assistance

GoldenGuard began as an SMS-based scam detection concept for older adults. My work included choosing the text-message interface, establishing product requirements, selecting a combined classifier-and-rules approach, testing deliberately tricky messages, directing changes based on false positives and false negatives, and working through SMS, deployment, and account-service integration.

## AI-assisted implementation

ChatGPT helped write and revise substantial portions of the Python implementation, including parts of detection rules and response logic, and helped debug integration issues. This repository should not be interpreted as code independently handwritten line by line. GoldenGuard's live classifier and rule-based response system do not use ChatGPT to analyze incoming messages at runtime.

## Third-party tools and sources

- [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection), associated with Tiago A. Almeida and José María Gómez Hidalgo, provided the primary labeled training messages.
- scikit-learn implements TF-IDF features and logistic regression; joblib stores the fitted model.
- FastAPI and Uvicorn handle the HTTP server and Twilio SMS webhook.
- Twilio provides SMS transport; Render hosts the backend; PostgreSQL member information is accessed through a separate companion service.
- Online tutorials and documentation were used in development.
- The fraud-prevention guidance references the FTC, AARP, and the U.S. Postal Inspection Service; see `knowledge/resources.json` for article links.

## Notes for reviewers

This is a curated portfolio-review branch of an existing private repository, not a reconstruction of the project's original development history. Test cases document some of the messages that initially challenged the detector. This is a warning tool, not a validated guarantee that messages are safe or fraudulent.
