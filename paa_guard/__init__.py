"""paa10-guard: reference mitigations for the OWASP Top 10 for Personal AI Agents (PAA10).

The guard evaluates each proposed agent action against a policy and a small owner-controlled
state store, outside the acting model, and returns allow / require_approval / deny.
"""

__version__ = "0.1.0"
