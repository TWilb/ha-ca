# Home Assistant app: X.509 Certificate Issuer

Issue X.509 certificates from your own CA directly in Home Assistant.

## Installation

1. Push this folder to a GitHub repository and set the URLs in `repository.yaml` and `x509_ca/config.yaml`.
2. In Home Assistant: **Settings → Apps → App store → ⋮ → Repositories**, add your repository URL.
3. Install **X.509 Certificate Issuer**, configure the CA paths, and start it.

Local alternative (no GitHub): copy the `x509_ca` folder to `/addons/x509_ca` on your Home Assistant
host (e.g. using the Samba app), then **⋮ → Check for updates** in the app store. It appears under *Local apps*.

See [x509_ca/DOCS.md](x509_ca/DOCS.md) for usage.
