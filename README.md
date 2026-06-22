A CLI for webauthn.io to demonstrate the ability to register passkey from commandline.

Attestation = None

Keys are saved in the built-in local soft (virtual) authenticator.

# Usage

```
python3 -m venv venv
source venv/bin/activate
pip install cryptography cbor2 

chmod +x webauthn_client.sh
./webauthn_client.sh register testuser1
./webauthn_client.sh login testuser1
```

# Files

 - `./cookiejar` will keep the `sessionid`, which is assigned and changed via HTTP GET method when accessing `https://webauthn.io`
 - `./keystore` will keep the private keys from the local virtual soft authenticator.

# TODO

 - [ ] support Attestation Certificate
 - [ ] support CTAP2
 - [ ] support SE, keychains.app to protect private keys

# Video Demo

<https://youtu.be/bZNEjhtW7Wc>
