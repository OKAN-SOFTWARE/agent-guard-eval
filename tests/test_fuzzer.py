"""Tests for red-team adversarial fuzzer."""

from agentguard.redteam.fuzzer import AgentRedTeamFuzzer


def test_generate_adversarial_prompts():
    fuzzer = AgentRedTeamFuzzer()
    prompt = "Summarize recent quarterly reports."
    test_cases = fuzzer.generate_adversarial_prompts(prompt)

    assert len(test_cases) >= 5
    categories = {tc.attack_category for tc in test_cases}
    assert "Direct Prompt Injection" in categories
    assert "Token Smuggling" in categories
    assert "Tool Hijacking" in categories

    for tc in test_cases:
        assert tc.payload
        assert tc.attack_name


def test_fuzz_tool_arguments():
    fuzzer = AgentRedTeamFuzzer()
    base_args = {"path": "documents/report.pdf", "timeout": 30}
    mutations = fuzzer.fuzz_tool_arguments(base_args)

    assert len(mutations) > 0
    # Make sure mutations target the string field
    assert any("../../../etc/passwd" in m["path"] for m in mutations)
    assert any("sk-" in m["path"] for m in mutations)
    # Integer field should remain untouched
    assert all(m["timeout"] == 30 for m in mutations)
