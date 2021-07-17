package com.kendouglas;

import com.google.common.base.Joiner;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1String;
import org.spongycastle.asn1.x500.AttributeTypeAndValue;
import org.spongycastle.asn1.x500.RDN;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.style.RFC4519Style;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * with extensions - no CSR file required
 * openssl req -x509 -newkey rsa:4096 -keyout myken.pem -out kencert.pem -days 365
 * <p>
 * no exentsions
 * openssl req -new -key my.key -sha256  -out MYSCR.csr
 * openssl x509 -req -days 365 -in MYSCR.csr -signkey my.key -sha256 -out full.crt
 * openssl x509 -req -days 365 -in MYCSR.csr -signkey my.key -sha256 -out full.pem
 */
public class CertificateUtils {

    public static void main(String[] args) {
        System.out.println("Certificate");
        X509Certificate certificate = null;
        try {
            certificate = getFileCertificate("C:\\Users\\ken_d\\Downloads\\Certificates\\src\\main\\resources\\kencert.pem");
            System.out.println(certificate.toString());

            System.out.println(getDisplayNameFromCertificate(certificate, false));

            String[] hostnames = parseHostNames(certificate);


        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static String[] parseHostNames(X509Certificate cert) {
        List<String> hostNameList = new ArrayList<>();
        try {
            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            if (altNames != null) {
                for (List<?> altName : altNames) {
                    if (altName.size() < 2) continue;
                    switch ((Integer) altName.get(0)) {
                        case GeneralName.dNSName:
                        case GeneralName.iPAddress:
                            Object data = altName.get(1);
                            if (data instanceof String) {
                                hostNameList.add(((String) data));
                            }
                            break;
                        default:
                    }
                }
            }
            System.out.println("Parsed hostNames: " + String.join(", ", hostNameList));
        } catch (CertificateParsingException e) {
            System.err.println("Can't parse hostNames from this cert.");
            e.printStackTrace();
        }
        return hostNameList.toArray(new String[hostNameList.size()]);
    }

    public static String getDisplayNameFromCertificate(X509Certificate certificate, boolean withLocation) throws CertificateParsingException {
        X500Name name = new X500Name(certificate.getSubjectX500Principal().getName());
        String commonName = null, org = null, location = null, country = null;

        for (RDN rdn : name.getRDNs()) {
            AttributeTypeAndValue pair = rdn.getFirst();
            String val = ((ASN1String) pair.getValue()).getString();
            ASN1ObjectIdentifier type = pair.getType();
            if (type.equals(RFC4519Style.cn))
                commonName = val;
            else if (type.equals(RFC4519Style.o))
                org = val;
            else if (type.equals(RFC4519Style.l))
                location = val;
            else if (type.equals(RFC4519Style.c))
                country = val;
        }

        final Collection<List<?>> subjectAlternativeNames = certificate.getSubjectAlternativeNames();
        String altName = null;
        if (subjectAlternativeNames != null)
            for (final List<?> subjectAlternativeName : subjectAlternativeNames)
                if ((Integer) subjectAlternativeName.get(0) == 1) // rfc822name
                    altName = (String) subjectAlternativeName.get(1);

        if (org != null) {
            return withLocation ? Joiner.on(", ").skipNulls().join(org, location, country) : org;
        } else if (commonName != null) {
            return commonName;
        } else {
            return altName;
        }
    }

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

}
