# DataHub.local - Bootstrap

Bootstrap a Kubernetes cluster via Ansible for deploying [**DataHub.local**](https://datahub-local.alvsanand.com/). With this Ansible project you can easily bring up a Kubernetes cluster on machines running:

- [X] Debian
- [X] Ubuntu
- [X] Raspberry Pi OS
- [X] RHEL Family (CentOS, Redhat, Rocky Linux...)
- [X] SUSE Family (SLES, OpenSUSE Leap, Tumbleweed...)
- [X] ArchLinux

on processor architectures:

- [X] x64
- [X] arm64
- [X] armhf

**IMPORTANT CHANGES**:

- Use of [Ingress-Nginx Controller](https://kubernetes.github.io/ingress-nginx) insteaf of Traefik.

## System requirements

The control node **must** have Ansible 8.0+ (ansible-core 2.15+)

All managed nodes in inventory must have:
- Passwordless SSH access
- Root access (or a user with equivalent permissions) 

It is also recommended that all managed nodes disable firewalls and swap. See [K3s Requirements](https://docs.k3s.io/installation/requirements) for more information.

## Usage

First copy the sample inventory to `inventory.yml`.

```bash
cp inventory-sample.yml inventory.yml
```

Second edit the inventory file to match your cluster setup. For example:
```bash
k3s_cluster:
  children:
    server:
      hosts:
        k3s-server-0:
          host: 192.0.2.50
    agent:
      hosts:
        k3s-agent-1:
          host: 192.0.2.51
        k3s-agent-2:
          host: 192.0.2.52
```

If needed, you can also edit `vars` section at the bottom to match your environment.

If multiple hosts are in the server group the playbook will automatically setup k3s in HA mode with embedded etcd.
An odd number of server nodes is required (3,5,7). Read the [official documentation](https://docs.k3s.io/datastore/ha-embedded) for more information.

Setting up a loadbalancer or VIP beforehand to use as the API endpoint is possible but not covered here.


For Debian/Ubuntu OS, ensure python3-apt is installed in the machines:

```bash
ansible k3s_cluster -i inventory.yml -b -m shell -a "apt-get update && apt-get install -y python3-apt"
```

Start provisioning of the cluster using the following command:

```bash
ansible-playbook playbook/site.yml -i inventory.yml
```

## Upgrading

A playbook is provided to upgrade K3s on all nodes in the cluster. To use it, update `k3s_version` with the desired version in `inventory.yml` and run:

```bash
ansible-playbook playbook/upgrade.yml -i inventory.yml
```

## Airgap Install

Airgap installation is supported via the `airgap_dir` variable. This variable should be set to the path of a directory containing the K3s binary and images. The release artifacts can be downloaded from the [K3s Releases](https://github.com/k3s-io/k3s/releases). You must download the appropriate images for you architecture (any of the compression formats will work).

An example folder for an x86_64 cluster:
```bash
$ ls ./playbook/my-airgap/
total 248M
-rwxr-xr-x 1 $USER $USER  58M Nov 14 11:28 k3s
-rw-r--r-- 1 $USER $USER 190M Nov 14 11:30 k3s-airgap-images-amd64.tar.gz

$ cat inventory.yml
...
airgap_dir: ./my-airgap # Paths are relative to the playbook directory
```

Additionally, if deploying on a OS with SELinux, you will also need to download the latest [k3s-selinux RPM](https://github.com/k3s-io/k3s-selinux/releases/latest) and place it in the airgap folder.


It is assumed that the control node has access to the internet. The playbook will automatically download the k3s install script on the control node, and then distribute all three artifacts to the managed nodes.

## Local Testing

A Vagrantfile is provided that provision a 5 nodes cluster using Vagrant (LibVirt or Virtualbox as provider). To use it:

```bash
vagrant up
```

By default, each node is given 2 cores and 2GB of RAM and runs Ubuntu 20.04. You can customize these settings by editing the `Vagrantfile`.

## Kubeconfig

After successful bringup, the kubeconfig of the cluster is copied to the control node  and merged with `~/.kube/config` under the `k3s-ansible` context.
Assuming you have [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl) installed, you can confirm access to your **Kubernetes** cluster with the following:

```bash
kubectl config use-context k3s-ansible
kubectl get nodes
```

If you wish for your kubeconfig to be copied elsewhere and not merged, you can set the `kubeconfig` variable in `inventory.yml` to the desired path.

## Bootstrapping

A playbook is provided to bootstrap the K8s cluster with base services ([cert-manager](https://cert-manager.io/), [Longhorn](https://longhorn.io/), [Sealed Secrets](https://sealed-secrets.netlify.app/) and [ArgoCD](argo-cd.readthedocs.io)). To use it, update `Bootstrap` vars with the desired configuration of the services and run:

```bash
ansible-playbook playbook/bootstrap.yml -i inventory.yml

# Update specific service
ansible-playbook playbook/bootstrap.yml -i inventory.yml --tags only-argocd
```

## Other commands

Furthermore, there are other playbook that helps you to manage the cluster:

- Reboot the K8s cluster in a safe manner, run:

  ```bash
  ansible-playbook playbook/reboot.yml -i inventory.yml
  ```
- Shutdown the K8s cluster in a safe manner, run:

  ```bash
  ansible-playbook playbook/shutdown.yml -i inventory.yml
  ```
- Execute shell command:

  ```bash
  ansible -i inventory.yml k3s_cluster -m shell -a 'hostname' --limit 'datahublocal-xiaomi12'
  ```
- Seal a secret:

  ```bash
  CREDENTIAL_KEY="password"
  CREDENTIAL_VALUE="strong_password"
  SECRET_NAMESPACE="default"
  SECRET_NAME="some-secret"

  echo -n "$CREDENTIAL_VALUE" \
     | kubectl create secret generic $SECRET_NAME -n $SECRET_NAMESPACE --dry-run=client --from-file=$CREDENTIAL_KEY=/dev/stdin -o json \
     | kubeseal --controller-namespace security --controller-name sealed-secrets -o yaml
  ```

### Debugging

For debugging purposes, you can run the bootstrapping against a local cluster. For that run:

```bash
k3d cluster create -v "/tmp/k3d/kubelet/pods:/var/lib/kubelet/pods@all" -p "8443:443@loadbalancer" --agents 2
```

In case you have problems with **ingress-nginx + oauth2-proxy**, run these commands to debug it:

```bash
kubectl logs -f -n kube-system daemonset/ingress-nginx-controller # Check ngnix logs

kubectl logs -f -n kube-system $(kubectl get pod -l 'app.kubernetes.io/name=oauth2-proxy' -n kube-system -o=name) # Check oauth2-proxy logs

kubectl run -it --rm --image=curlimages/curl curly -- sh # Run a pod with curl
```

Finally, when there are error in Ansible and you want to retrieve the variables:

```bash
ansible -i inventory.yml -m debug -a 'msg={{hostvars}}' all | grep k3s_location
```
