cilium install --version v1.16.2 \
  --set ipam.mode=cluster-pool \
  --set encryption.enabled=true \
  --set encryption.type=ipsec

cilium install --version v1.15.9 \
  --set ipam.mode=cluster-pool \
  --set encryption.enabled=true \
  --set encryption.type=wireguard \
  --set encryption.nodeEncryption=true


First, let's create a Kubernetes secret for the IPsec configuration to be stored.

The format for such IPsec Configuration and key is the following: key-id encryption-algorithms PSK-in-hex-format key-size.

Let's start by generating a random pre-shared key (PSK). We're going to create a random string of 20 characters (using dd with /dev/urandom as a source), then encode it as a hexdump with the xxd command.

Run the following command:

shell

copy

run
PSK=($(dd if=/dev/urandom count=20 bs=1 2> /dev/null | xxd -p -c 64))
echo $PSK
The $PSK variable now contains our hexdumped PSK.

In order to configure IPsec, you will need to pass this PSK along with a key ID (we'll choose 3 here), and a specification of the algorithm to be used with IPsec (we'll use GCM-128-AES, so we'll specify rfc4106(gcm(aes))). We'll specify the block size accordingly to 128.

Create a Kubernetes secret called cilium-ipsec-keys, and use this newly created PSK:

shell

copy

run
kubectl create -n kube-system secret generic cilium-ipsec-keys \
    --from-literal=keys="3+ rfc4106(gcm(aes)) $PSK 128"
This command might look confusing at first, but essentially a Kubernetes secret is a key-value pair, with the key being the name of the file to be mounted as a volume in the cilium-agent Pods while the value is the IPsec configuration in the format described earlier.

Note
The + sign in the secret is strongly recommended. It will force the use of per-tunnel IPsec keys. The former global IPsec keys are considered insecure (GHSA-pwqm-x5x6-5586) and were deprecated in v1.16. When using +, the per-tunnel keys will be derived from the secret you generated.

Decoding the secret created earlier is simple:

shell

copy

run
SECRET="$(kubectl get secrets cilium-ipsec-keys -o jsonpath='{.data}' -n kube-system | jq -r ".keys")"
echo $SECRET | base64 --decode
Your secret should be similar to this:

3+ rfc4106(gcm(aes)) da630c6acdbef2757ab7f5215b8b1811420e3f61 128
This maps to the following Cilium IPsec configuration :

key-id (an identifier of the key): arbitrarily set to 3
encryption-algorithms: AES-GCM GCM
PSK: da630c6acdbef2757ab7f5215b8b1811420e3f61
key-size: 128
Now that the IPSec configuration has been generated, let's install Cilium and IPsec.


Now that applications are deployed in the cluster, let's verify the traffic between the components is encrypted and encapsulated in IPsec tunnels.

First, let's run a shell in one of the Cilium agents:

shell

copy

run
kubectl -n kube-system exec -ti ds/cilium -- bash
Let's then install the packet analyzer tcpdump to inspect some of the traffic (you may not want to run these in production environments 😅).

shell

copy

run
apt-get update
apt-get -y install tcpdump
Let's now run tcpdump. We are filtering based on traffic on the cilium_vxlan interface.

When using Kind, Cilium is deployed by default in vxlan tunnel mode - meaning we set VXLAN tunnels between our nodes.

In Cilium's IPsec implementation, we use Encapsulating Security Payload (ESP) as the protocol to provide confidentiality and integrity.

Let's now run tcpdump and filter based on this protocol to show IPsec traffic:

shell

copy

run
tcpdump -n -i cilium_vxlan esp
Just wait a few seconds and you should see output similar to this:

13:35:34.009247 IP 10.0.2.120 > 10.0.0.18: ESP(spi=0x00000003,seq=0x55), length 116
13:35:34.009341 IP 10.0.2.120 > 10.0.0.18: ESP(spi=0x00000003,seq=0x56), length 116
13:35:34.009614 IP 10.0.0.18 > 10.0.2.120: ESP(spi=0x00000003,seq=0x55), length 208
13:35:34.009730 IP 10.0.0.18 > 10.0.2.120: ESP(spi=0x00000003,seq=0x56), length 164
13:35:34.014299 IP 10.0.2.120 > 10.0.0.18: ESP(spi=0x00000003,seq=0x57), length 92
13:35:34.014384 IP 10.0.2.120 > 10.0.0.18: ESP(spi=0x00000003,seq=0x58), length 92
13:35:34.014578 IP 10.0.0.18 > 10.0.2.120: ESP(spi=0x00000003,seq=0x57), length 196
13:35:34.014712 IP 10.0.0.18 > 10.0.2.120: ESP(spi=0x00000003,seq=0x58), length 116
13:35:34.258106 IP 10.0.3.68 > 10.0.0.18: ESP(spi=0x00000003,seq=0x59), length 92
In the example above, there are three IPs (10.0.2.120, 10.0.0.18, 10.0.3.68); yours are likely to be different). These are the IP addresses of Cilium agents and what we are seeing in the logs is a mesh of IPsec tunnels established between our agents. Notice all these tunnels were automatically provisioned by Cilium.

Every 15 seconds or so, you should see some new traffic, corresponding to the heartbeats between the Cilium agents.

Exit the tcpdump stream with Ctrl+c.


## Key rotation 

As we have seen earlier, the Cilium IPsec configuration and associated key are stored as a Kubernetes secret.

To rotate the key, you will therefore need to patch the previously created cilium-ipsec-keys Kubernetes secret, with kubectl patch secret. During the transition, the new and old keys will be used.

Let's try this now.

Exit the Cilium agent shell (with a prompt similar to root@kind-worker2:/home/cilium#):

shell

copy

run
exit
You should be back to the green root@server:~# prompt.

Now, let's extract and print some of the variables from our existing secret.

shell

copy

run
read KEYID ALGO PSK KEYSIZE < <(kubectl get secret -n kube-system cilium-ipsec-keys -o go-template='{{.data.keys | base64decode}}{{printf "\n"}}')
# Remove the '+' character from KEYID, then print it
KEYID=${KEYID%\+}
echo $KEYID
echo $PSK
When you run echo $KEYID, it should return 3. We could have guessed this, since we used 3 as the key ID when we initially generated the Kubernetes secret.

Notice the value of the existing PSK by running echo $PSK.

Let's rotate the key. We'll increment the Key ID by 1 and generate a new PSK. We'll use the same key size and encryption algorithm.

shell

copy

run
NEW_PSK=($(dd if=/dev/urandom count=20 bs=1 2> /dev/null | xxd -p -c 64))
echo $NEW_PSK
patch='{"stringData":{"keys":"'$((KEYID+1))'+ rfc4106(gcm(aes)) '$NEW_PSK' 128"}}'
kubectl patch secret -n kube-system cilium-ipsec-keys -p="${patch}" -v=1
You should see this response: secret/cilium-ipsec-keys patched.

Check the IPsec configuration again:

shell

copy

run
read NEWKEYID ALGO NEWPSK KEYSIZE < <(kubectl get secret -n kube-system cilium-ipsec-keys -o go-template='{{.data.keys | base64decode}}{{printf "\n"}}')
NEWKEYID=${NEWKEYID%\+}
echo $NEWKEYID
echo $NEWPSK
You can see that the key ID was incremented to 4 and that the PSK value has changed. This example illustrates simple key management with IPsec with Cilium. Production use would probably be more sophisticated.

