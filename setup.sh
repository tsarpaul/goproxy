openssl genrsa -out cakey.pem 2048
openssl rsa -inform PEM -outform DER -in cakey.pem -out cakey.der

openssl req -new -x509 -days 9999 -key cakey.pem -out cacert.pem -subj "/CN=goproxy CA"
openssl x509 -inform PEM -outform DER -in cacert.pem -out cacert.der

openssl genrsa -out signkey.pem 2048
openssl rsa -inform PEM -outform DER -in signkey.pem -out signkey.der

mkdir certs
