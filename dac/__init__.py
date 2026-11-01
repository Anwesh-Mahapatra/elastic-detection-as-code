"""Detection-as-Code for Elastic Security.

Stage 1  lint      deterministic checks (schema, ECS, query shape)      -> dac.validate_rules lint
Stage 2  replay    run every rule against attack + benign ECS logs      -> dac.validate_rules replay
Stage 3  judge     LLM review with grounded, code-computed scoring      -> dac.ai_judge_elastic
Deploy             bulk import into Kibana's detection engine           -> dac.validate_rules deploy
"""

__version__ = "0.1.0"
