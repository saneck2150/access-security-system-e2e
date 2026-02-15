### KEY EXAMPLE FOR DEMO ONLY!!!

To genarate random hex key use:
```bash
mkdir -p secrets
head -c 32 /dev/urandom | xxd -p -c 64 > secrets/master_key.hex
```