from .harness import run_scenario


def main() -> None:
    harness = run_scenario()
    print("Auth method transition scenario: PASS")
    print(f"tokens: {len(harness.state.tokens)}")
    print(f"state writes: {len(harness.state.writes)}")
    print(f"ledger records: {len(harness.ledger.records)}")


if __name__ == "__main__":
    main()
