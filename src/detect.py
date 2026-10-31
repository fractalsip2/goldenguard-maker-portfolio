import argparse
import json

from src.detector import detect


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a suspicious message with GoldenGuard AI."
    )
    parser.add_argument("message", help="Message text to analyze")
    parser.add_argument("--name", default=None, help="User's first name")
    parser.add_argument(
        "--language",
        default="en",
        help="Response language: en, es, fr, de, zh-Hans, zh-Hant, or vi",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full structured JSON response",
    )
    args = parser.parse_args()

    try:
        result = detect(args.message, args.name, args.language)
    except (ValueError, FileNotFoundError) as error:
        print(json.dumps({"error": str(error)}, indent=2))
        raise SystemExit(1)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(result["personalized_response"])


if __name__ == "__main__":
    main()
