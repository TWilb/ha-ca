# X.509 Certificate Issuer

Issue TLS server and client certificates signed by your own certificate authority (CA),
from a panel in the Home Assistant sidebar.

## Setup

1. Put your CA certificate and private key somewhere the app can read them. The default is
   `/ssl/ca/ca.crt` and `/ssl/ca/ca.key`. You can copy them there with the Samba or
   File editor app. PEM and DER are both accepted. RSA, ECDSA and Ed25519 CA keys work.
2. If the key is encrypted, enter its password as `ca_key_password`.
3. Start the app and open **Certificates** in the sidebar.

Don't have a CA yet? You can create one with OpenSSL:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
  -keyout ca.key -out ca.crt -days 3650 -subj "/CN=My Home CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
```

## Options

| Option | Description |
|---|---|
| `ca_cert` | Path to the CA certificate (in `/ssl` or `/share`) |
| `ca_key` | Path to the CA private key |
| `ca_key_password` | Password for an encrypted CA key (leave empty if none) |
| `default_days` | Default validity of new certificates (1 to 3650) |
| `default_key_type` | `ec-p256`, `ec-p384`, `rsa-2048`, `rsa-3072`, `rsa-4096` or `ed25519` |
| `default_profile` | `server`, `client` or `server+client` (sets Extended Key Usage) |
| `renew_days_before` | Renew this many days before expiry (default 30; for short-lived certificates at most a third of their lifetime) |
| `renew_with_new_key` | Default for new certificates: generate a fresh private key on each renewal (can be changed per certificate) |
| `notifications` | Show Home Assistant notifications about renewals, failures and expiring certificates |

## Using the app

- **Issue a new certificate:** the app generates a new key pair. Enter a Common Name and
  any subject alternative names (DNS names, IPs, e-mails; wildcards like `*.home.lan` are fine).
  For server certificates without SANs, the CN is added as a SAN automatically, because browsers
  ignore the CN.
- **Sign a CSR:** paste or upload a CSR. The private key never leaves your device.
- **Downloads:** certificate, private key, full chain, CA certificate, a ZIP of all of them,
  or a password-protected PKCS#12 (.p12/.pfx). Use *Legacy encryption* for older Android
  versions, macOS before 14, or Java 8.
- **Copy to /ssl:** writes `fullchain.pem`, `privkey.pem`, `cert.pem` and `chain.pem` to
  `/ssl/<folder>/`, for Home Assistant's `http:` settings or other apps (MQTT broker, NGINX).

## Automatic renewal

New certificates have **Renew automatically** switched on by default (a checkbox on the issue form).
The app checks every 6 hours, starting a minute after it starts. When a certificate is within its
renewal window, the app:

1. issues a successor with the same subject, names, usage and validity length. It uses a new or the
   existing private key, as set for that certificate. Certificates from a CSR keep the same public key.
2. rewrites the files in every `/ssl` folder you copied the certificate to with
   **Keep updated on renewal** ticked.
3. restarts the apps (and/or Home Assistant Core) you ticked under **Restart after renewal** on the
   certificate's page. Each target is restarted once per run, even if several certificates use it.
   Apps that aren't running are skipped. Core is restarted last.
4. sends a notification with the result. Notifications go out after Core is back up.

**Renew now** on a certificate's page does the same immediately (restarts run in the background).
The previous version stays in the app, marked as renewed, until it expires; then it is deleted.

If renewal fails (for example, the CA key password is wrong, or the CA certificate itself expires too
soon to issue a longer-lasting certificate), you get one notification per distinct error and the
certificate is marked *failing* in the list. Certificates with automatic renewal off get one
"expiring" notification instead.

To restart apps and Home Assistant and to send notifications, this app needs Supervisor
`manager` access and Home Assistant API access, which Home Assistant shows on the app's Info page.

Certificates are never valid past the CA's own expiry date; if you ask for longer, the
validity is shortened and you are warned.

## Security notes

- Issued certificates and generated private keys are stored in the app's `/data` folder,
  which is included in Home Assistant backups. Delete entries you no longer need.
- The UI is only reachable through Home Assistant ingress (logged-in users). It exposes no ports.
- Deleting a certificate does not revoke it; there is no CRL/OCSP support. Use short
  validity periods for anything you might need to withdraw.
- Clients must trust your CA certificate (download it from the top of the page).
