## 1.1.0
- Automatic renewal before expiry, checked every 6 hours, plus a "Renew now" button.
- Copies in /ssl are kept up to date after renewal.
- Optional restarts after renewal, chosen per certificate (Home Assistant Core and/or apps).
- Home Assistant notifications for renewals, failures and certificates that are about to expire.
- Choose per certificate whether renewal generates a new private key.

## 1.0.0
- Initial release: issue certificates, sign CSRs, PEM/ZIP/PKCS#12 downloads, export to /ssl.
