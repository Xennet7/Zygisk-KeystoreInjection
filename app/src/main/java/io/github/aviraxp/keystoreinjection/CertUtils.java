package io.github.aviraxp.keystoreinjection;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.DEROctetString;


public class CertUtils {
    private static final Pattern lineTrimmer = Pattern.compile("^\\s+|\\s+$", Pattern.MULTILINE);

    public static Certificate parseCert(String cert) throws Throwable {
        cert = lineTrimmer.matcher(cert).replaceAll("");
        PemObject pemObject;
        try (PemReader reader = new PemReader(new StringReader(cert))) {
            pemObject = reader.readPemObject();
        }
        X509CertificateHolder holder = new X509CertificateHolder(pemObject.getContent());
        return (new JcaX509CertificateConverter().getCertificate(holder));
    }

    public static X500Name parseCertSubject(String cert) throws Throwable {
        cert = lineTrimmer.matcher(cert).replaceAll("");
        PemObject pemObject;
        try (PemReader reader = new PemReader(new StringReader(cert))) {
            pemObject = reader.readPemObject();
        }
        X509CertificateHolder holder = new X509CertificateHolder(pemObject.getContent());
        return holder.getSubject();
    }

    public static KeyPair parseKeyPair(String key) throws Throwable {
        key = lineTrimmer.matcher(key).replaceAll("");
        Object object;
        try (PEMParser parser = new PEMParser(new StringReader(key))) {
            object = parser.readObject();
        }
        PEMKeyPair pemKeyPair = (PEMKeyPair) object;
        return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
    }

    public static PrivateKey parsePrivateKey(String keyPair) throws RuntimeException {
        keyPair = lineTrimmer.matcher(keyPair).replaceAll("");
        try (PEMParser parser = new PEMParser(new StringReader(keyPair))) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) parser.readObject();
            return new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // --- NEW: Dummy certificate for TEE-broken devices ---
    public static X509Certificate buildDummyCert(KeyPair kp, String subjectCN) throws Exception {
        X500Name subject = new X500Name(subjectCN);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                java.math.BigInteger.valueOf(System.currentTimeMillis()),
                new java.util.Date(System.currentTimeMillis() - 1000L * 60 * 60),
                new java.util.Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365),
                subject,
                kp.getPublic()
        );

        String algo = kp.getPublic().getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
        ContentSigner signer = new JcaContentSignerBuilder(algo).build(kp.getPrivate());

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }
}
