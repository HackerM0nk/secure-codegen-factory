# Output Filter

> Post-LLM command denylist engine. Sits between LLM output and shell
> execution. Implemented in `src/server/security/output-filter.ts`.

## How It Works

When the LLM generates a `shell_exec` tool call, the command string is
checked against two pattern lists before execution:

1. **BLOCK patterns** (24 rules) -- Command is rejected. The LLM receives
   an error message suggesting an alternative approach.
2. **ALERT patterns** (16 rules) -- Command is allowed but logged as an
   alert for security review.

Commands that match neither list receive a PASS verdict. All verdicts
(BLOCK, ALERT, PASS) are logged to an in-memory buffer (max 10,000 entries)
and emitted via a security event callback.

## BLOCK Patterns (24 Rules)

These commands are never allowed. Each carries a description used in the
error message returned to the LLM.

| Name | Category | What It Blocks | Why It Is Dangerous |
|---|---|---|---|
| `curl_pipe_bash` | Pipe-to-shell | `curl ... \| sh` | Remote code execution -- downloads and executes arbitrary code |
| `wget_pipe_sh` | Pipe-to-shell | `wget ... \| sh` | Same as curl pipe-to-shell |
| `curl_pipe_shell` | Pipe-to-shell | `curl ... \| /bin/sh` | Explicit path variant of pipe-to-shell |
| `dev_tcp` | Dev TCP/UDP | `/dev/tcp/` | Bash built-in TCP socket -- used for reverse shells |
| `dev_udp` | Dev TCP/UDP | `/dev/udp/` | Bash built-in UDP socket |
| `bash_reverse_shell` | Reverse shell | `bash -i >& /dev/tcp/` | Classic bash interactive reverse shell |
| `nc_reverse_shell` | Reverse shell | `nc -e /bin/` | Netcat reverse shell with exec |
| `ncat_reverse_shell` | Reverse shell | `ncat -e` | Ncat reverse shell |
| `socat_exec` | Reverse shell | `socat ... EXEC` | Socat with command execution |
| `python_socket_connect` | Reverse shell | `python -c ... socket ... connect` | Python one-liner reverse shell |
| `base64_pipe_bash` | Base64 exec | `echo ... \| base64 -d \| sh` | Encoded payload execution |
| `base64_pipe_shell` | Base64 exec | `base64 -d \| sh` | Direct base64 decode to shell |
| `eval_subshell` | Eval injection | `eval $(` | Eval with command substitution |
| `eval_double_quote_subshell` | Eval injection | `eval "$(` | Eval with quoted command substitution |
| `eval_backtick` | Eval injection | `` eval ` `` | Eval with backtick substitution |
| `curl_subshell_exec` | Eval injection | `$(curl` | Curl output used as command |
| `rm_rf_root` | Destructive | `rm -rf /` | Deletes entire filesystem |
| `rm_rf_root_var` | Destructive | `rm -rf / ` | Variant with trailing space |
| `write_etc` | System path write | `> /etc/` | Writing to system configuration |
| `append_etc` | System path write | `>> /etc/` | Appending to system configuration |
| `tee_etc` | System path write | `tee /etc/` | Tee to system configuration |
| `write_proc` | System path write | `> /proc/` | Writing to proc filesystem |
| `write_sys` | System path write | `> /sys/` | Writing to sysfs |
| `nsenter` | Container escape | `nsenter` | Enters another namespace -- container escape |
| `unshare_escape` | Container escape | `unshare` | Creates new namespace -- container escape |
| `chroot` | Container escape | `chroot` | Changes root directory -- container escape |
| `docker_sock` | Container escape | `docker.sock` | Direct Docker socket access |
| `metadata_ssrf` | Cloud SSRF | `169.254.169.254` | AWS/GCP/Azure metadata endpoint |
| `metadata_ssrf_v6` | Cloud SSRF | `[fd00:ec2::254]` | AWS IPv6 metadata endpoint |
| `k8s_sa_token` | K8s credential | `/var/run/secrets/kubernetes` | K8s service account token access |
| `k8s_sa_token_alt` | K8s credential | `serviceaccount/token` | K8s service account token (alt path) |
| `etc_shadow` | Credential access | `cat /etc/shadow` | Password hash file read |

## ALERT Patterns (16 Rules)

These commands are allowed but generate a security alert.

| Name | Category | What It Matches | Why It Is Suspicious |
|---|---|---|---|
| `chmod_777` | Permission change | `chmod 777` | World-writable permissions |
| `chmod_setuid` | Permission change | `chmod +s` | Set-UID bit -- privilege escalation vector |
| `chmod_u_setuid` | Permission change | `chmod u+s` | User set-UID bit |
| `ssh_keygen` | SSH operations | `ssh-keygen` | SSH key generation |
| `ssh_copy_id` | SSH operations | `ssh-copy-id` | SSH key deployment to remote hosts |
| `crontab` | Scheduled tasks | `crontab` | Cron job manipulation |
| `at_command` | Scheduled tasks | `at -f` | Scheduled command execution |
| `systemctl` | Service management | `systemctl` | System service manipulation |
| `useradd` | User management | `useradd` | User account creation |
| `passwd` | User management | `passwd` | Password changes |
| `adduser` | User management | `adduser` | User account creation (alt) |
| `iptables` | Network config | `iptables` | Firewall rule manipulation |
| `ip_route` | Network config | `ip route` | Network routing changes |
| `sus_port_4444` | Suspicious ports | curl/wget/nc to port 4444 | Common Metasploit listener port |
| `sus_port_1337` | Suspicious ports | curl/wget/nc to port 1337 | Common "leet" backdoor port |
| `sus_port_8888` | Suspicious ports | curl/wget/nc to port 8888 | Common reverse shell port |
| `sus_port_9001` | Suspicious ports | curl/wget/nc to port 9001 | Common Tor/backdoor port |

## Logging and Statistics

The filter maintains an in-memory buffer of the last 10,000 command log
entries. Each entry records:

- Truncated command (first 500 chars)
- Timestamp, project ID, user ID, conversation turn
- Verdict (BLOCK / ALERT / PASS)
- Pattern name (if matched)

Statistics are available via `getSecurityStats()` which returns total
blocks, alerts, passes, and top 10 most-blocked patterns.

## Related Docs

- [Input Firewall](input-firewall.md) -- Pre-LLM input filtering
- [Package Filter](package-filter.md) -- Package installation filtering
  (runs alongside the output filter for `npm install` commands)
- [Security Overview](README.md) -- Where this layer fits in the stack
