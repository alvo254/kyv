# kyv
Kyverno learning stuff


```
kubectl exec -n kube-system -ti daemonset/tetragon -c tetragon -- \
	tetra getevents -o compact
```

🎬 Detecting a container escape
This lab takes the first part of the Real World Attack out of the book and teaches you how to detect a container escape step by step. During the attack you will take advantage of a pod with an overly permissive configuration ("privileged" in Kubernetes) to enter into all the host namespaces with the nsenter command.

From there, you will write a static pod manifest in the /etc/kubernetes/manifests directory that will cause the kubelet to run that pod. Here you actually take advantage of a Kubernetes bug where you define a Kubernetes namespace that doesn’t exist for your static pod, which makes the pod invisible to the Kubernetes API server. This makes your stealthy pod invisible to kubectl commands.

After persisting the breakout by spinning up an invisible container, you are going to download and execute a malicious script in memory that never touches disk. Note that this simple python script represents a fileless malware which is almost impossible to detect by using traditional userspace tools.

The easiest way to perform a container escape is to spin up a pod with "privileged" in the pod spec. Kubernetes allows this by default and the privileged flag grants the container all Linux capabilities and access to host namespaces. The hostPID and hostNetwork flags run the container in the host PID and networking namespaces respectively, so it can interact directly with all processes and network resources on the node.

In the tab >_ Terminal 1 on the left side, start inspecting the Security Observability events again. This time we will specifically look for the events related to the pod named sith-infiltrator, where the attack is going to be performed.

shell

copy

run
kubectl exec -n kube-system -ti daemonset/tetragon -c tetragon \
  -- tetra getevents -o compact --pods sith-infiltrator
Now, let's switch >_ Terminal 2 and apply the privileged pod spec:

shell

copy

run
kubectl apply -f sith-infiltrator.yaml
Wait until it becomes ready:

shell

copy

run
kubectl get pods
The output should be:

NAME                 READY   STATUS    RESTARTS   AGE
sith-infiltrator   1/1     Running   0          36s

Now, let’s use >_ Terminal 2 and kubectl exec to get a shell in sith-infiltrator:

shell

copy

run
kubectl exec -it sith-infiltrator -- /bin/bash
In >_ Terminal 1, you can now observe the kubectl exec with the following process_exec event:

🚀 process default/sith-infiltrator /bin/bash            🛑 CAP_SYS_ADMIN
In >_ Terminal 2 in our kubectl shell, let's use nsenter command to enter the host's namespace and run bash as root on the host:

shell

copy

run
nsenter -t 1 -a bash
The nsenter command executes commands in specified namespaces. The first flag, -t defines the target namespace where the command will land. Every Linux machine runs a process with PID 1 which always runs in the host namespace. The other command line arguments define the other namespaces where the command also wants to enter, in this case, -a describes all the Linux namespaces, which are: cgroup, ipc, uts, net, pid, mnt, time.

So we break out from the container in every possible way and running the bash command as root on the host.

Cilium Tetragon provides an enforcement framework called TracingPolicy. TracingPolicy is a user-configurable Kubernetes custom resource definition (CRD) that allows you to trace arbitrary events in the kernel and define actions to take on match.

TracingPolicy is fully Kubernetes Identity Aware, so it can enforce on arbitrary kernel events and system calls after the Pod has reached a ready state. This allows you to prevent system calls that are required by the container runtime but should be restricted at application runtime. You can also make changes to the TracingPolicy that dynamically update the eBPF programs in the kernel without needing to restart your application or node.

Once there is an event triggered by a TracingPolicy and the corresponding signature, you can either send an alert to a Security Analyst or prevent the behaviour with a SIGKILL signal to the process.

crictl ps


