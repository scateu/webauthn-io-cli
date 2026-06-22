test:
	venv/bin/activate
	./webauthn_client.sh register abcd
	./webauthn_client.sh login abcd
clean:
	rm -r keystore
	rm cookiejar
