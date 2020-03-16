package josh.service.mitm.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class DynamicKeyStore {

    private X500Principal cacertPrin;

    public X509Certificate createCert(PublicKey pubKey, PrivateKey intPrivKey, PublicKey intPubKey, X509Certificate intCert, String cn, String o, String ou, String l, String st, String c) throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, CertificateException, IOException {

        final int daysTillExpiry = 10 * 365;

        final Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.DAY_OF_YEAR, daysTillExpiry);

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X500Principal subjectName = new X500Principal("CN=" + cn + ", OU=PortSwigger CA, O=PortSwigger, C=PortSwigger");

        certGen.setSerialNumber(java.math.BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(cacertPrin);
        certGen.setNotBefore(new Date());
        certGen.setNotAfter(expiry.getTime());
        certGen.setSubjectDN(subjectName);
        certGen.setPublicKey(pubKey);
        certGen.setSignatureAlgorithm("SHA256withRSA");

        X509Certificate cert = certGen.generate(intPrivKey);
        cert.checkValidity(new Date());
        cert.verify(intPubKey);

        return certGen.generate(intPrivKey);   // note: private key of CA*/
    }

    public X509Certificate createItermCert(PublicKey pubKey, PrivateKey caPrivKey, X509Certificate caCert, String cn, String o, String ou, String l, String st, String c) throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, CertificateException {
        final int daysTillExpiry = 10 * 365;

        final Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.DAY_OF_YEAR, daysTillExpiry);

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X500Principal subjectName = new X500Principal("CN=" + cn + ", OU=" + ou + ", O=" + o + ", L=" + l);

        certGen.setSerialNumber(java.math.BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setNotBefore(new Date());
        certGen.setNotAfter(expiry.getTime());
        certGen.setSubjectDN(subjectName);
        certGen.setPublicKey(pubKey);
        certGen.setSignatureAlgorithm("SHA256withRSA");
        X509Certificate cert = certGen.generateX509Certificate(caPrivKey);
        cert.checkValidity(new Date());
        cert.verify(caCert.getPublicKey());
        return cert;
    }

    public String generateKeyStore(String password, String cn) {
        String result = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyStore ks = KeyStore.getInstance("PKCS12");
            String fs = System.getProperty("file.separator");
            String JKS = System.getProperty("user.dir") + fs + "burpca.p12";
            File tmpF = new File(JKS);
            if (tmpF.exists()) {
                ks.load(new FileInputStream(JKS), "changeit".toCharArray());
                java.security.cert.Certificate cacert = ks.getCertificate("cacert");
                PrivateKey caPrivKey = (PrivateKey) ks.getKey("cacert", "changeit".toCharArray());
                PublicKey caPubKey = (PublicKey) cacert.getPublicKey();
                cacertPrin = ((X509Certificate) cacert).getSubjectX500Principal();
                System.out.println("LOG: format " + caPubKey.getFormat());
                char[] pw = "changeit".toCharArray();
                KeyPairGenerator r = KeyPairGenerator.getInstance("RSA");
                r.initialize(1024);
                KeyPair intkeyPair = r.generateKeyPair();
                KeyPairGenerator r1 = KeyPairGenerator.getInstance("RSA");
                r1.initialize(1024);
                r1.generateKeyPair();
                Certificate[] chain = new Certificate[2];
                chain[1] = cacert;
                chain[0] = (Certificate) createItermCert(intkeyPair.getPublic(), caPrivKey, (X509Certificate) cacert, cn, "PortSwigger", "PortSwigger", "PortSwigger", "PortSwigger", "PortSwigger");
                KeyStore newStore = KeyStore.getInstance("PKCS12");
                newStore.load(null, null);
                newStore.setKeyEntry("key", (Key) intkeyPair.getPrivate(), "changeit".toCharArray(), chain);

                String hidden = System.getProperty("user.home");
                hidden += "/.NoPEProxy/keystores/";
                File keyStoreDir = new File(hidden);
                if (!keyStoreDir.exists()) {
                    keyStoreDir.mkdir();
                }
                File keyStoreFile = new File(hidden + cn + ".p12");
                final FileOutputStream fos = new FileOutputStream(keyStoreFile);
                newStore.store(fos, pw);
                fos.close();
                System.out.println(keyStoreFile.getAbsolutePath());
                result = keyStoreFile.getAbsolutePath();
            } else {
                System.out.println("No P12 File");
            }
        } catch (IOException | IllegalStateException | InvalidKeyException | KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | UnrecoverableKeyException | CertificateException ex) {
        }
        return result;
    }

}
