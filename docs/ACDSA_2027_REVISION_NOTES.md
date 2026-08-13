# ACDSA 2027 revision notes

Implemented from the supervisor's technical plan:

1. Performance middleware and stage-level metrics (`t_san`, `t_score`, `t_db`, total latency).
2. PostgreSQL audit persistence in Docker Compose via SQLAlchemy/psycopg.
3. Sanitizer on/off experimental mode to estimate LGPD privacy overhead.
4. Locust concurrent-load workload.
5. UNSW-NB15 replay adapter for mass-log stability testing.
6. Quantitative result files and an English two-column article draft.

Scientific boundary: the rule-based SIARC score is not a trained ML model. Dataset replay validates pipeline stability and processing behaviour, not detection accuracy. No accuracy, recall, F1 or zero-day detection claims are made without an independent detection protocol.
