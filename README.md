# Certificates
Example of opening and reading certificate information

 * Creating the self signed certificate for testing purposes :-
 * <p>
 * with extensions - no CSR file required
 * openssl req -x509 -newkey rsa:4096 -keyout myken.pem -out kencert.pem -days 365
 * <p>
 * <p>
 * no exentsions
 * openssl req -new -key my.key -sha256  -out MYSCR.csr
 * openssl x509 -req -days 365 -in MYSCR.csr -signkey my.key -sha256 -out full.crt
 * openssl x509 -req -days 365 -in MYCSR.csr -signkey my.key -sha256 -out full.pem
