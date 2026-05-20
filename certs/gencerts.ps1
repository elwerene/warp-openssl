openssl ecparam -out ca.key -name prime256v1 -genkey
openssl req -new -sha256 -key ca.key -out ca.csr -batch -subj '/CN=CA'
openssl x509 -req -sha256 -extensions v3_ca  -days 3650 -in ca.csr -signkey ca.key -out ca.crt

openssl ecparam -out localhost.key -name prime256v1 -genkey
openssl req -new -sha256 -key localhost.key -out localhost.csr -batch -subj '/CN=localhost'
openssl x509 -req -extfile ./server.cnf -sha256 -days 3650 -in localhost.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out localhost.crt


openssl ecparam -out intermediate.key -name prime256v1 -genkey
openssl req -new -sha256 -key intermediate.key -out intermediate.csr -batch -subj '/CN=intermediate'
openssl x509 -req -extfile ./intermediate.cnf -sha256 -days 3650 -in intermediate.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out intermediate.crt

openssl genpkey -out client.key -algorithm RSA -pkeyopt rsa_keygen_bits:2048
openssl req -new -sha256 -key client.key -out client.csr -batch -subj '/CN=client'
openssl x509 -req -extfile ./client.cnf -sha256 -days 3650 -in client.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial -out client.crt

openssl x509 -in client.crt -text -noout
