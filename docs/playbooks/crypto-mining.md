# Playbook: Crypto Mining Detection

## Detection
- Tetragon TracingPolicy detects known mining binaries (xmrig, cpuminer, etc.)
- AlertManager fires PossibleCryptoMining (CPU > 90% for 5 min)
- Prometheus workspace resource monitoring shows anomaly
- Output filter blocks download of mining tools

## Triage
1. Check pod resource usage: `kubectl top pod -n devfactory-workspaces`
2. Check process list in container
3. Verify Tetragon events for the pod
4. Check if mining binary was downloaded to /tmp

## Response
1. **Automated (Tetragon)**: Known mining process names are logged
2. **Automated (AlertManager)**: PossibleCryptoMining alert fires
3. **Automated (Incident Responder)**: Pod terminated on CRITICAL alert
4. **Manual**: Investigate how the miner was introduced

## Commands
```bash
# Check container processes
kubectl exec <pod> -n devfactory-workspaces -- ps aux

# Check CPU usage
kubectl top pod -n devfactory-workspaces

# Check /tmp for suspicious binaries
kubectl exec <pod> -n devfactory-workspaces -- ls -la /tmp/

# Kill pod
kubectl delete pod <pod> -n devfactory-workspaces --force

# Check Tetragon for process events
kubectl exec -n tetragon ds/tetragon -c tetragon -- \
  tetra getevents --type PROCESS_EXEC --namespace devfactory-workspaces
```

## Recovery
- Pod is terminated and recreated clean
- Review agent conversation that led to mining attempt
- Update output filter if new download pattern found
- Report resource abuse
