# kubernetes

A [cert-manager](https://cert-manager.io) `Certificate` renewed into a Secret, and a Deployment that mounts it for an app using keyload. When cert-manager renews the certificate, the kubelet updates the mounted files and keyload picks them up. No restart, and no reloader sidecar.

## Use it

[`app.yaml`](app.yaml) assumes:

- cert-manager is installed, with a `ClusterIssuer` named `internal-ca`. Change `issuerRef` to match yours.
- Your app's image, in place of `ghcr.io/example/api:1.0.0`, uses keyload like this:

```go
r, err := keyload.New(keyload.Files{
	Cert:      "/tls/tls.crt",
	Key:       "/tls/tls.key",
	Roots:     "/tls/ca.crt",
	ClientCAs: "/tls/ca.crt",
}, keyload.MinRemaining(time.Hour), keyload.OverlapWindow(24*time.Hour))
```

Then:

```sh
kubectl apply -f examples/kubernetes/app.yaml
kubectl get certificate api      # READY True once issued
kubectl logs deploy/api          # your OnReload logging
```

## What happens on renewal

1. cert-manager renews the certificate 8 hours before it expires (`renewBefore: 8h` on a `24h` certificate) and updates the `api-tls` Secret.
2. The kubelet writes the new files into a new directory in the volume and atomically swaps the `..data` symlink to point at it.
3. keyload watches the volume directory, sees the swap, validates the new files and swaps them in. New connections use the new certificate.

To test without waiting for a renewal, force one with `cmctl renew api`, or delete the Secret and let cert-manager recreate it.

## Things that matter

- **Mount the Secret as a directory**, as `app.yaml` does. A `subPath` mount never sees updates, from keyload or anything else.
- **`rotationPolicy: Always`** gives each renewal a new private key. keyload handles that, since it reloads the key with the certificate.
- **`MinRemaining(time.Hour)`** refuses a certificate that's about to expire, for example if a renewal is stuck and an old Secret is restored.
- **`OverlapWindow(24*time.Hour)`** keeps the old CA trusted for a day after the issuer's CA changes, so pods that haven't reloaded yet keep connecting.
- **Alerting:** the `prometheus.io/*` annotations assume your app serves `keyload.MetricsHandler` on port 9090; see the [metrics](../metrics) example.

Source: [`app.yaml`](app.yaml)
