# Kubeconfig Hygiene

`kubeconfig-hygiene` audits Kubernetes client configuration without serializing embedded credentials.

```bash
devops-toolkit kubeconfig-hygiene \
  --kubeconfig ~/.kube/config \
  --expiry-days 30 \
  --format json \
  --output kubeconfig-report.json
```

Multiple `--kubeconfig` options are supported. Without them, the tool follows `KUBECONFIG` and then `~/.kube/config`.

## Checks

- group/world-readable files on POSIX systems;
- plaintext API endpoints and disabled TLS verification;
- embedded tokens, passwords, and client keys represented only by fingerprints;
- client-certificate expiry;
- legacy auth-provider and exec API versions;
- unrecognized exec plugins;
- stale current contexts and missing user/cluster references;
- duplicate context names and duplicated embedded credentials.

No cleanup or kubeconfig rewriting is performed.
