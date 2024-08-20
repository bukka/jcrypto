openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key private_key.pem -out certificate.pem -days 1825 -subj "/C=UK/ST=England/L=London/O=Zelenka/CN=Jakub"
