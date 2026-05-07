from enrichment.few_shot_examples import FEW_SHOT_EXAMPLES, EXAMPLE_PROMPT
import yaml

# This test covers the few-shot example formatting and YAML loading.
# run by executing: python -m tests.08_test_few_shot
# enrichment test



# Check all 5 examples are present
print(f"Number of examples: {len(FEW_SHOT_EXAMPLES)}")   # should be 5

# Check each example formats correctly
for ex in FEW_SHOT_EXAMPLES:
    msg = EXAMPLE_PROMPT.format(**ex)
    assert "Threat text:" in msg
    assert "Mapped TTPs" in msg
    print("[+]", ex["text"][:60].strip(), "...")

# Check the YAML loads cleanly
with open("config/few_shot_ttps.yaml") as f:
    data = yaml.safe_load(f)

examples = data["examples"]
print(f"\nYAML examples loaded: {len(examples)}")         # should be 5

for ex in examples:
    assert "id" in ex
    assert "text" in ex
    assert "ttps" in ex
    for ttp in ex["ttps"]:
        assert ttp["id"].startswith("T"), f"Bad TTP ID: {ttp['id']}"
    print("[+]", ex["id"])