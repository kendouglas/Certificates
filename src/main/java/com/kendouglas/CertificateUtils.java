package com.kendouglas;


import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERSequence;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Example of opening an X509 Certificate and reading some of the properties
 * <p>
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
 * <p>
 * <p>
 * 4]: ObjectId: 2.5.29.17 Criticality=true
 * SubjectAlternativeName [
 * Other-Name: Unrecognized ObjectIdentifier: 1.3.6.1.5.5.7.8.4
 * ]
 */
public class CertificateUtils {

    public static void main(String[] args) {
        System.out.println("Certificate");
        X509Certificate certificate = null;
        String subjectaltnamestring;
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            // Get the X509 certificate file a PEM
            certificate = getFileCertificate("C:\\Users\\ken_d\\Downloads\\Certificates\\src\\main\\resources\\test.pem");
            //System.out.println(certificate.toString());

            /**
             * SubjectAlternativeName [
             *   Other-Name: Unrecognized ObjectIdentifier: 1.3.6.1.5.5.7.8.4
             */
            // This prints out all of the available information that can be got at through the certificate.getxxx() methods
            System.out.println(getSubjectAlternativeNames(certificate));


            // Borrowed getDisplayNameFromCertificate() from https://www.programcreek.com/java-api-examples/?code=bcmapp%2Fbcm-android%2Fbcm-android-master%2Fthirdpart%2Fbitcoin%2Fsrc%2Fmain%2Fjava%2Forg%2Fbitcoinj%2Fcrypto%2FX509Utils.java#
            //
            //System.out.println(getDisplayNameFromCertificate(certificate, true));

            // Some of methods on the certificate return Collections which need to be iterated through
            // An example of this is in  parseHostNames()
            // System.out.println("Alternative Subject name");
            //System.out.println("Alternative Subject name=" + getSubjectAltName(certificate));
            //printHostNames(parseHostNames(certificate));

            //System.out.println("running "+ new DERUTF8String("Hint"));

            //System.out.println(getSubjectAlternativeNames(certificate));

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * getSubjectAlternativeNames
     * simply returns a list of Strings containing the alternative names used
     * Returns the ObjectIdentifier ID
     * but this can be changed to return what you want to see when asserting against the certificate
     *
     * @param certificate
     * @return
     */
    public static List<String> getSubjectAlternativeNames(X509Certificate certificate) {
        List<String> identities = new ArrayList<String>();
        try {
            Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
            // Check that the certificate includes the SubjectAltName extension
            if (altNames == null)
                return Collections.emptyList();
            // Use the type OtherName to search for the certified server name
            for (List item : altNames) {
                Integer type = (Integer) item.get(0);
                if (type == 0)
                    // Type OtherName found so return the associated value
                    try {
                        // Value is encoded using ASN.1 so decode it to get the server's identity
                        ASN1InputStream decoder = new ASN1InputStream((byte[]) item.toArray()[1]);
                        DEREncodable encoded = decoder.readObject();
                        // Position 0 is the ID

                        encoded = ((DERSequence) encoded).getObjectAt(0);
                        String identity = encoded.getDERObject().toString();

                        identities.add(identity);
                    } catch (Exception e) {
                        log("Error decoding subjectAltName" + e.getLocalizedMessage());
                    }
                // Other types are not good for XMPP so ignore them
                // log("SubjectAltName of invalid type found: " + certificate);
            }
        } catch (CertificateParsingException e) {
            log("Error parsing SubjectAltName in certificate: " + certificate + "\r\nerror:" + e.getLocalizedMessage());
        }
        return identities;
    }



    /**
     * @param keyFile
     * @return
     * @throws IOException
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static X509Certificate getFileCertificate(String keyFile) throws IOException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException {
        FileInputStream fis = null;
        ByteArrayInputStream bais = null;

        try {
            // use FileInputStream to read the file
            fis = new FileInputStream(keyFile);

            // read the bytes
            byte[] value = new byte[fis.available()];
            fis.read(value);
            bais = new ByteArrayInputStream(value);

            // get X509 certificate factory
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            // certificate factory can now create the certificate
            return (X509Certificate) certFactory.generateCertificate(bais);
        } finally {
            IOUtils.closeQuietly(fis);
            IOUtils.closeQuietly(bais);
        }
    }


    public static void log(String msg) {
        System.out.println(msg);
    }

}
