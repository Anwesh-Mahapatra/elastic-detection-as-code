## Rule change

- [ ] Rule file in `rules/elastic/*.toml` or `rules/sigma/*.yml`
- [ ] Replay test in `tests/cases/<rule>.yml` (positive attack data + negative benign data)
- [ ] New test data is ECS-only (the replay stage rejects non-ECS fields)
- [ ] `python -m dac.validate_rules lint` and `replay` pass locally

**What it detects / why now:**

**Known gaps or expected false positives:**
