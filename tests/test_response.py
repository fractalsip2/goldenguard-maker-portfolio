from src.response import compose_response


def test_response_is_personalized_and_includes_links():
    response = compose_response(
        first_name="Robert Smith",
        risk_level="HIGH",
        scam_type="bank_impersonation",
        evidence=["The link is not an official bank domain."],
        action="Call the number on the back of your card.",
        resources=[
            {
                "provider": "AARP",
                "title": "Bank Impersonation Scams",
                "url": "https://example.com/bank",
            }
        ],
        organization="Chase",
        seed_text="test",
    )

    assert response["full_text"].startswith("Robert,")
    assert "Chase" in response["full_text"]
    assert "https://example.com/bank" in response["full_text"]
