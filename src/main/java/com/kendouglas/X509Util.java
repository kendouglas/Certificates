package com.kendouglas;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Logger;


public class X509Util {

    private static Logger log = Logger.getLogger("X509Util");

    private static Hashtable<String, DERObjectIdentifier> algorithms = new Hashtable<String, DERObjectIdentifier>();
    private static Hashtable<String, RSASSAPSSparams> params     = new Hashtable<String, RSASSAPSSparams>();
    private static Set<DERObjectIdentifier>       noParams  = new HashSet<DERObjectIdentifier>();

    //private static final String X509_CERT_TYPE = "X.509";
    //private static final String PKCS7_ENCODING = "PKCS7";
    public  static final String BEGIN_CERT     = "-----BEGIN CERTIFICATE-----";
    public  static final String END_CERT       = "-----END CERTIFICATE-----";
    public  static final int    CERT_LINE_LENGTH = 64;
    public  static final String BEGIN_CERT_REQ = "-----BEGIN CERTIFICATE REQUEST-----";
    public  static final String END_CERT_REQ   = "-----END CERTIFICATE REQUEST-----";
    public  static final int    CERT_REQ_LINE_LENGTH = 76;

    static
    {
        algorithms.put("MD2WITHRSAENCRYPTION", PKCSObjectIdentifiers.md2WithRSAEncryption);
        algorithms.put("MD2WITHRSA", PKCSObjectIdentifiers.md2WithRSAEncryption);
        algorithms.put("MD5WITHRSAENCRYPTION", PKCSObjectIdentifiers.md5WithRSAEncryption);
        algorithms.put("MD5WITHRSA", PKCSObjectIdentifiers.md5WithRSAEncryption);
        algorithms.put("SHA1WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha1WithRSAEncryption);
        algorithms.put("SHA1WITHRSA", PKCSObjectIdentifiers.sha1WithRSAEncryption);
        algorithms.put("SHA224WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        algorithms.put("SHA224WITHRSA", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        algorithms.put("SHA256WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        algorithms.put("SHA256WITHRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        algorithms.put("SHA384WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        algorithms.put("SHA384WITHRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        algorithms.put("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("SHA512WITHRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("SHA1WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA224WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA256WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA384WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA512WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        algorithms.put("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        algorithms.put("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        algorithms.put("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        algorithms.put("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        algorithms.put("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        algorithms.put("SHA1WITHDSA", X9ObjectIdentifiers.id_dsa_with_sha1);
        algorithms.put("DSAWITHSHA1", X9ObjectIdentifiers.id_dsa_with_sha1);
        algorithms.put("SHA224WITHDSA", NISTObjectIdentifiers.dsa_with_sha224);
        algorithms.put("SHA256WITHDSA", NISTObjectIdentifiers.dsa_with_sha256);
        algorithms.put("SHA1WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA1);
        algorithms.put("ECDSAWITHSHA1", X9ObjectIdentifiers.ecdsa_with_SHA1);
        algorithms.put("SHA224WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA224);
        algorithms.put("SHA256WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA256);
        algorithms.put("SHA384WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA384);
        algorithms.put("SHA512WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA512);
        algorithms.put("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        algorithms.put("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        algorithms.put("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);

        //
        // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
        // The parameters field SHALL be NULL for RSA based signature algorithms.
        //
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA1);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA224);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA256);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA384);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA512);
        noParams.add(X9ObjectIdentifiers.id_dsa_with_sha1);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha224);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha256);

        //
        // RFC 4491
        //
        noParams.add(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        noParams.add(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);

        //
        // explicit params
        //
        AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, new DERNull());
        params.put("SHA1WITHRSAANDMGF1", creatPSSParams(sha1AlgId, 20));

        AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224, new DERNull());
        params.put("SHA224WITHRSAANDMGF1", creatPSSParams(sha224AlgId, 28));

        AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, new DERNull());
        params.put("SHA256WITHRSAANDMGF1", creatPSSParams(sha256AlgId, 32));

        AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, new DERNull());
        params.put("SHA384WITHRSAANDMGF1", creatPSSParams(sha384AlgId, 48));

        AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, new DERNull());
        params.put("SHA512WITHRSAANDMGF1", creatPSSParams(sha512AlgId, 64));
    }

    private static RSASSAPSSparams creatPSSParams(AlgorithmIdentifier hashAlgId, int saltSize)
    {
        return new RSASSAPSSparams(
                hashAlgId,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlgId),
                new DERInteger(saltSize),
                new DERInteger(1));
    }

    static DERObjectIdentifier getAlgorithmOID(String algorithmName)
    {
        algorithmName = Strings.toUpperCase(algorithmName);

        if (algorithms.containsKey(algorithmName))
        {
            return (DERObjectIdentifier)algorithms.get(algorithmName);
        }

        return new DERObjectIdentifier(algorithmName);
    }

    static AlgorithmIdentifier getSigAlgID( DERObjectIdentifier sigOid, String algorithmName)
    {
        if (noParams.contains(sigOid))
        {
            return new AlgorithmIdentifier(sigOid);
        }

        algorithmName = Strings.toUpperCase(algorithmName);

        if (params.containsKey(algorithmName))
        {
            return new AlgorithmIdentifier(sigOid, (DEREncodable)params.get(algorithmName));
        }
        else
        {
            return new AlgorithmIdentifier(sigOid, new DERNull());
        }
    }

    public static Iterator<String> getAlgNames()
    {
        Enumeration<String> e = algorithms.keys();
        List<String>        l = new ArrayList<String>();

        while (e.hasMoreElements())
        {
            l.add(e.nextElement());
        }

        return l.iterator();
    }
    public static String[] getECSpecsNames()
    {

        Enumeration		e = ECNamedCurveTable.getNames();
        List<String>	l = new ArrayList<String>();

        while (e.hasMoreElements())
            l.add((String) e.nextElement());

        return l.toArray(new String[] {});
    }
/*
    static Signature getSignatureInstance(
        String algorithm)
        throws NoSuchAlgorithmException
    {
        return Signature.getInstance(algorithm);
    }

    static Signature getSignatureInstance(
        String algorithm,
        String provider)
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        if (provider != null)
        {
            return Signature.getInstance(algorithm, provider);
        }
        else
        {
            return Signature.getInstance(algorithm);
        }
    }*/
/*
    static byte[] calculateSignature(
        DERObjectIdentifier sigOid,
        String              sigName,
        PrivateKey          key,
        SecureRandom        random,
        ASN1Encodable       object)
        throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        Signature sig;

        if (sigOid == null)
        {
            throw new IllegalStateException("no signature algorithm specified");
        }

        sig = X509Util.getSignatureInstance(sigName);

        if (random != null)
        {
            sig.initSign(key, random);
        }
        else
        {
            sig.initSign(key);
        }

        sig.update(object.getEncoded(ASN1Encodable.DER));

        return sig.sign();
    }*/
/*
    static byte[] calculateSignature(
        DERObjectIdentifier sigOid,
        String              sigName,
        String              provider,
        PrivateKey          key,
        SecureRandom        random,
        ASN1Encodable       object)
        throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        Signature sig;

        if (sigOid == null)
        {
            throw new IllegalStateException("no signature algorithm specified");
        }

        sig = X509Util.getSignatureInstance(sigName, provider);

        if (random != null)
        {
            sig.initSign(key, random);
        }
        else
        {
            sig.initSign(key);
        }

        sig.update(object.getEncoded(ASN1Encodable.DER));

        return sig.sign();
    }
*/
    /*
    static X509Principal convertPrincipal(
        X500Principal principal)
    {
        try
        {
            return new X509Principal(principal.getEncoded());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("cannot convert principal");
        }
    }
*/

    /**
     * Return an Extension DERObject from a certificate
     */
    public static DERObject getExtensionValue(X509Certificate cert, String oid)
            throws IOException {
        byte[] bytes = cert.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return aIn.readObject();
    } //getExtensionValue

    private static String getStringFromGeneralNames(DERObject names) {
        ASN1Sequence namesSequence = ASN1Sequence.getInstance((ASN1TaggedObject)names, false);
        if (namesSequence.size() == 0) {
            return null;
        }
        DERTaggedObject taggedObject = (DERTaggedObject)namesSequence.getObjectAt(0);
        return new String(ASN1OctetString.getInstance(taggedObject, false).getOctets());
    }

    /**
     * Return the CRL distribution point URL form a certificate.
     */
    public static DistributionPoint[] getCrlDistributionPoint(X509Certificate certificate)
            throws CertificateParsingException {
        try {
            DERObject obj = getExtensionValue(certificate, X509Extensions.CRLDistributionPoints.getId());
            if (obj != null) {
                CRLDistPoint crldp = new CRLDistPoint((ASN1Sequence) obj);
                DistributionPoint[] alldp = crldp.getDistributionPoints();
                return alldp;
            }
        }
        catch (Exception e) {
            e.printStackTrace();
            throw new CertificateParsingException(e.toString());
        }
        return null;
    }



    public static X509Certificate[] convertCertChaintoX509( Certificate[] certChain) {
        if (certChain==null)
            return null;
        X509Certificate[] tempX509CertificateChain = new X509Certificate[certChain.length];
        for (int i = 0; i < certChain.length; i++) {
            if ( certChain[i] instanceof X509Certificate)
                tempX509CertificateChain[i] = (X509Certificate) certChain[i];
        }
        return tempX509CertificateChain;
    }

    /**
     * Return Certificate Base 64 Encoded (PEM format)
     * @param cert
     * @return
     */
    public static String getCertBase64Encoded(X509Certificate cert) {
        try {
            String sTmp = new String(Base64.encode(cert.getEncoded()));
            String sEncoded = BEGIN_CERT + "\r\n";
            for(int iCnt = 0; iCnt < sTmp.length(); iCnt += 64)
            {
                int iLineLength;
                if(iCnt + 64 > sTmp.length())
                    iLineLength = sTmp.length() - iCnt;
                else
                    iLineLength = 64;
                sEncoded = sEncoded + sTmp.substring(iCnt, iCnt + iLineLength) + "\r\n";
            }

            sEncoded = sEncoded + END_CERT + "\r\n";
            return sEncoded;
        } catch(CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }




    /**
     * Reads a certificate in PEM-format from an InputStream. The stream may contain other things,
     * the first certificate in the stream is read.
     *
     * @param
     * @return Ordered Collection of X509Certificate, first certificate first, or empty Collection
     * @exception IOException if the stream cannot be read.
     * @exception CertificateException if the stream does not contain a correct certificate.
     */
    public static Collection<X509Certificate> getCertsFromPEM(InputStream certstream) throws IOException, CertificateException {
        ArrayList ret = new ArrayList();
        BufferedReader bufRdr = null;
        ByteArrayOutputStream ostr = null;
        PrintStream opstr = null;
        try {
            bufRdr = new BufferedReader(new InputStreamReader(certstream));
            while (bufRdr.ready()) {
                ostr = new ByteArrayOutputStream();
                opstr = new PrintStream(ostr);
                String temp;
                while ((temp = bufRdr.readLine()) != null
                        && !temp.equals(BEGIN_CERT))
                    continue;
                if (temp == null)
                    throw new IOException("Error in " + certstream.toString()
                            + ", missing " + BEGIN_CERT + " boundary");
                while ((temp = bufRdr.readLine()) != null
                        && !temp.equals(END_CERT))
                    opstr.print(temp);
                if (temp == null)
                    throw new IOException("Error in " + certstream.toString()
                            + ", missing " + END_CERT + " boundary");
                opstr.close();

                byte[] certbuf = Base64.decode(ostr.toByteArray());
                ostr.close();
                // Phweeew, were done, now decode the cert from file back to X509Certificate object
                CertificateFactory cf = getCertificateFactory();
                X509Certificate x509cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certbuf));
                ret.add(x509cert);
            }
        } finally {
            if (bufRdr != null) bufRdr.close();
            if (opstr != null) opstr.close();
            if (ostr != null) ostr.close();
        }
        //log.debug("<getcertfromPEM:" + ret.size());
        return ret;
    } // getCertsFromPEM
    /**
     * Reads a certificate in PEM-format from an InputStream. The stream may contain other things,
     * the first certificate in the stream is read.
     *
     * @param
     * @return Ordered Collection of X509Certificate, first certificate first, or empty Collection
     * @exception IOException if the stream cannot be read.
     * @exception CertificateException if the stream does not contain a correct certificate.
     */
    public static PKCS10CertificationRequest getCSRFromPEM(String csrFile) throws IOException, CertificateException {

        log.info("Loading certificate signing request from PEM file " + csrFile);

        BufferedReader bufRdr = null;
        ByteArrayOutputStream ostr = null;
        PrintStream opstr = null;
        PKCS10CertificationRequest pkcs10 = null;

        try {
            InputStream inStrm = new FileInputStream(csrFile);
            bufRdr = new BufferedReader(new InputStreamReader(inStrm));

            while (bufRdr.ready()) {
                ostr = new ByteArrayOutputStream();
                opstr = new PrintStream(ostr);
                String temp;

                //Jump CSR Header
                while ((temp = bufRdr.readLine()) != null
                        && !temp.equals(BEGIN_CERT_REQ))
                    continue;
                if (!temp.equals(BEGIN_CERT_REQ))
                    throw new IOException("Error in " + csrFile + ", missing " + BEGIN_CERT_REQ + " boundary");

                //Read Base 64 encoded lines
                while ((temp = bufRdr.readLine()) != null
                        && !temp.equals(END_CERT_REQ))
                    opstr.print(temp);

                //Jump CSR Footer
                if (!temp.equals(END_CERT_REQ))
                    throw new IOException("Error in "+csrFile+", missing " + END_CERT_REQ + " boundary");
                opstr.close();

                byte[] certbuf = Base64.decode(ostr.toByteArray());
                ostr.close();

                //Now decode the CSR from file back to PKCS10CertificationRequest object
                pkcs10 = new PKCS10CertificationRequest(certbuf);
            }
        } finally {
            if (bufRdr != null) bufRdr.close();
            if (opstr != null) opstr.close();
        }
        return pkcs10;
    }

    public static byte[] getCertEncodedPkcs7(X509Certificate cert) {
        return getCertsEncodedPkcs7(new X509Certificate[] { cert } );
    }

    public static byte[] getCertsEncodedPkcs7(X509Certificate certs[]) {
        try
        {
            ArrayList alCerts = new ArrayList();
            for(int iCnt = 0; iCnt < certs.length; iCnt++)
                alCerts.add(certs[iCnt]);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath cp = cf.generateCertPath(alCerts);
            return cp.getEncoded("PKCS7");
        } catch(CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }
    public static CertificateFactory getCertificateFactory() {
        try {
            return CertificateFactory.getInstance("X.509", "BC");
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

    // Fast convert a byte array to a hex string
    // with possible leading zero.
    public static String toHexString ( byte[] b ) {
        StringBuffer sb = new StringBuffer( b.length * 2 );
        for ( int i=0; i<b.length; i++ ) {
            // look up high nibble char
            sb.append( hexChar [( b[i] & 0xf0 ) >>> 4] );
            // look up low nibble char
            sb.append( hexChar [b[i] & 0x0f] );
        }
        return sb.toString();
    }

    // table to convert a nibble to a hex char.
    static char[] hexChar = { '0' , '1' , '2' , '3' , '4' , '5' , '6' , '7' , '8' , '9' , 'a' , 'b' , 'c' , 'd' , 'e' , 'f'};

    /** and be formed only of digits 0-9 A-F or
     * a-f. No spaces, minus or plus signs.
     * @return corresponding byte array.
     */
    public static byte[] fromHexString ( String s )
    {
        int stringLength = s.length();
        if ( (stringLength & 0x1) != 0 )
        {
            throw new IllegalArgumentException ( "fromHexString requires an even number of hex characters" );
        }byte[] b = new byte[stringLength / 2];

        for ( int i=0,j=0; i<stringLength; i+=2,j++ )
        {
            int high = charToNibble( s.charAt ( i ) );
            int low = charToNibble( s.charAt ( i+1 ) );
            b[j] = (byte)( ( high << 4 ) | low );
        }
        return b;
    }

    /**
     * Convert any X509Certificate implementation from any Security Provider to BouncyCastle Security Provider implementation.<br/>
     * If convertion failed for any reason, it return the input X509Certificate object.
     *
     * @param cert the certificate object to convert
     * @return X509CertificateObject implementation of X509Certificate
     */
    public static X509Certificate getBCCertificate(X509Certificate cert) {
        if ( cert!=null && !(cert instanceof X509CertificateObject) )
            try {
                ByteArrayInputStream bais = new ByteArrayInputStream(cert.getEncoded());
                cert = (X509Certificate) getCertificateFactory().generateCertificate(bais);
            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
        return cert;
    }
    /**
     * convert a single char to corresponding nibble.
     *
     * @param c char to convert. must be 0-9 a-f A-F, no
     * spaces, plus or minus signs.
     *
     * @return corresponding integer
     */
    private static int charToNibble ( char c )
    {
        if ( '0' <= c && c <= '9' )
        {
            return c - '0';
        }
        else if ( 'a' <= c && c <= 'f' )
        {
            return c - 'a' + 0xa;
        }
        else if ( 'A' <= c && c <= 'F' )
        {
            return c - 'A' + 0xa;
        }
        else
        {
            throw new IllegalArgumentException ( "Invalid hex character: " + c );
        }
    }

    public static X509CRL loadCRLFromDP(DistributionPoint dp) {
        //TODO: download crl from CDP
        log.info("CRL download from CDP not implemented yet.");
        return null;
    }

    public static boolean isValidCertificateForEncryption(
            X509Certificate certificate) {
        try {
            certificate.checkValidity();
            if (isValidKeyUsage(certificate,CertificateInfo.KEYENCIPHERMENT))
                return true;
        } catch (CertificateExpiredException e) {
            log.warning("try to use an expired certificate for encryption");
        } catch (CertificateNotYetValidException e) {
            log.warning("try to use a not yet valid certificate for encryption");
        }

        return false;
    }

    public static boolean isValidCertificateForSignature(
            X509Certificate certificate) {
        try {
            certificate.checkValidity();
            if (isValidKeyUsage(certificate,CertificateInfo.DIGITALSIGNATURE) && isValidKeyUsage(certificate,CertificateInfo.NONREPUDIATION) )
                return true;
            else {
                log.warning("a signature certificate must have digital signature and non repudiation key usage");
                return false;
            }
        } catch (CertificateExpiredException e) {
            log.warning("try to use an expired certificate for signature");
        } catch (CertificateNotYetValidException e) {
            log.warning("try to use a not yet valid certificate for encryption");
        }

        return false;
    }
    private static boolean isValidKeyUsage(X509Certificate certificate,
                                           int keyusage) {
        if (keyusage>=0 && keyusage<=8)
            if (certificate.getKeyUsage()!=null) {
                boolean[] ku = certificate.getKeyUsage();
                return ku[keyusage];
            }
        return false;
    }
}
