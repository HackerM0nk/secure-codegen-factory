# Playbook: Sandbox Escape Attempt

## Detection
- Output filter blocks: nsenter, chroot, unshare, pivot_root, docker.sock access
- Tetragon TracingPolicy kills escape processes (Sigkill)
- Tetragon monitors execve for escape tools in workspace namespace
- AlertManager fires SandboxViolationSpike alert

## Triage
1. Check Tetragon logs: `kubectl logs -n tetragon -l app.kubernetes.io/name=tetragon | grep workspace`
2. Identify the specific escape technique attempted
3. Check if any commands succeeded before the block
4. Verify container integrity

## Response
1. **Automated (Tetragon)**: Sigkill on nsenter/unshare/chroot execution
2. **Automated (Tetragon)**: Sigkill on SA token file access
3. **Automated (Incident Responder)**: CRITICAL alert triggers pod termination
4. **Manual**: Forensic review of container filesystem
5. **Manual**: Check if user uploaded binaries to /tmp

## Commands
```bash
# Check Tetragon events
kubectl exec -n tetragon ds/tetragon -c tetragon -- \
  tetra getevents -o compact --namespace devfactory-workspaces

# Kill suspicious pod
kubectl delete pod <pod-name> -n devfactory-workspaces --force

# Check network connections from pod
kubectl exec -n tetragon ds/tetragon -c tetragon -- \
  tetra getevents --type PROCESS_KPROBE --namespace devfactory-workspaces

# Review output filter logs
curl http://localhost:4100/api/security/stats
```

## Recovery
- Pod is terminated and recreated from last snapshot
- Rotate any credentials that may have been exposed
- Update Tetragon policies if new escape vector found
- File incident report with full Tetragon event log
