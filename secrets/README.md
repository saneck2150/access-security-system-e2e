# secrets

Cryptographic key storage directory.

> ⚠️ **WARNING: FOR DEVELOPMENT/DEMO ONLY**
>
> This folder exists solely for local development and demonstration purposes.
> **NEVER** store production secrets in the source code repository!

## Contents

| File | Description |
|------|-------------|
| `master_key.hex` | 32-byte master key in hex format (64 characters) |

## Generating a Demo Key

```bash
mkdir -p secrets
head -c 32 /dev/urandom | xxd -p -c 64 > secrets/master_key.hex
```

## File Format

```
64 hexadecimal characters (representing 32 bytes)
Whitespace is ignored during parsing

Example:
a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890
```

---

## Production Secret Management

In a real production environment, **do NOT** store secrets in the filesystem alongside code. Use one of the following approaches:

### Recommended: Hardware Security Module (HSM)

```
┌─────────────────────────────────────────────────────────────────┐
│                    Production Architecture                      │
└─────────────────────────────────────────────────────────────────┘

     ┌──────────────────┐
     │  Access Server   │
     └────────┬─────────┘
              │ PKCS#11 / Cloud KMS API
              ▼
     ┌──────────────────┐
     │  HSM / Cloud KMS │  ◀── Keys never leave secure hardware
     │  • AWS KMS       │
     │  • Azure Key Vault│
     │  • Google Cloud KMS│
     │  • HashiCorp Vault│
     │  • Physical HSM  │
     └──────────────────┘
```

### Option 1: Cloud Key Management Services

| Provider | Service | Integration |
|----------|---------|-------------|
| AWS | KMS | Use AWS SDK, keys stored in HSM-backed KMS |
| Azure | Key Vault | Use Azure SDK with managed identity |
| Google Cloud | Cloud KMS | Use GCP SDK with service account |
| HashiCorp | Vault | REST API with AppRole authentication |

### Option 2: Environment Variables

```bash
# Set in systemd service, Docker, Kubernetes, etc.
export ACCESS_MASTER_KEY="<hex-encoded-key>"

# Application reads from environment instead of file
```

### Option 3: Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: access-security-secrets
type: Opaque
data:
  master-key: <base64-encoded-key>
---
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: access-server
      volumeMounts:
        - name: secrets
          mountPath: "/run/secrets"
          readOnly: true
  volumes:
    - name: secrets
      secret:
        secretName: access-security-secrets
```

### Option 4: Encrypted File with Secure Delivery

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Encrypted    │ ──▶ │ Secure Boot  │ ──▶ │ Decrypt to   │
│ key file     │     │ / TPM unlock │     │ memory only  │
└──────────────┘     └──────────────┘     └──────────────┘
```

## Security Checklist

### Development

- [x] `secrets/` is in `.gitignore`
- [x] Demo keys are randomly generated locally
- [x] Keys are not committed to version control

### Production

- [ ] Use HSM or cloud KMS for master key storage
- [ ] Implement key rotation procedures
- [ ] Enable audit logging for key access
- [ ] Use separate keys per environment (dev/staging/prod)
- [ ] Restrict filesystem permissions (`chmod 600`)
- [ ] Run application as non-root user
- [ ] Use memory-safe key handling (zeroing after use)
- [ ] Enable full disk encryption on servers

## Key Rotation

When rotating the master key in production:

1. Generate new master key in HSM/KMS
2. Update `keyManagement.currentKeyVersion` in config
3. Set `allowPreviousKeyVersion: true` temporarily
4. Re-encrypt all card peppers with new version
5. Update all readers to use new key version
6. Disable previous key version
7. Archive (don't delete) old key for audit log verification

## Related Files

| Path | Purpose |
|------|---------|
| `config/access_security.yaml` | References `keyManagement.masterKeyPath` |
| `key_manager/` | Loads and uses the master key |
| `data/access.db` | Audit log requires master key for verification |