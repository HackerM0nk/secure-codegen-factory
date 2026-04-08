# Playbook: Prompt Injection Attack

## Detection
- Input firewall Tier 1 regex match (< 1ms)
- Prompt injection detector deep analysis flags attack vectors
- Behavioral detector classifies session as SUSPICIOUS/MALICIOUS
- Trajectory monitor score exceeds 0.7 threshold

## Triage
1. Check audit log: `cat .audit/actions.jsonl | grep "input_blocked\|injection"`
2. Review the specific attack vectors detected
3. Check if this is an isolated attempt or part of a multi-turn escalation
4. Check Grafana Security dashboard for injection rate trends

## Response
1. **Automated**: Session is auto-paused if trajectory score > 0.7
2. **Automated**: Behavioral detector flags MALICIOUS sessions
3. **Manual**: Review session history for social engineering patterns
4. **Manual**: Check if any tool calls succeeded before the block

## Commands
```bash
# Check recent blocks
curl http://localhost:4100/api/security/stats

# Test a specific input
curl -X POST http://localhost:4100/api/security/test-injection \
  -H "Content-Type: application/json" \
  -d '{"input": "ignore previous instructions"}'

# Check audit trail
cat .audit/actions.jsonl | jq 'select(.type | contains("security"))'
```

## Recovery
- Session can be resumed via `SecurityLayer.resumeSession(sessionId)`
- Review and update firewall patterns if new evasion technique found
- No data loss — all blocks happen pre-execution
