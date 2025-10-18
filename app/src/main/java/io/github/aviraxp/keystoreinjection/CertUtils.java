package io.github.aviraxp.keystoreinjection;

import android.util.Base64;
import android.util.Log;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.LinkedList;

public final class CertUtils {

    public static Certificate parseCert(String base64) {
        try {
            byte[] bytes = Base64.decode(base64, Base64.DEFAULT);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return cf.generateCertificate(new ByteArrayInputStream(bytes));
        } catch (Throwable t) {
            Log.e("KeystoreInjection", "Failed to parse cert: " + t);
            return null;
        }
    }

    public static X500Name parseCertSubject(String base64) {
        try {
            Certificate cert = parseCert(base64);
            if (cert instanceof X509Certificate x509) {
                return new X500Name(x509.getSubjectX500Principal().getName());
            }
        } catch (Throwable t) {
            Log.e("KeystoreInjection", "Failed to parse subject: " + t);
        }
        return new X500Name("CN=Unknown");
    }

    public static KeyPair parseKeyPair(String base64PrivateKey) {
        try {
            byte[] keyBytes = Base64.decode(base64PrivateKey, Base64.DEFAULT);
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(privateSpec);

            // Generate a fake public key from private key (if needed)
            byte[] pubEncoded = privateKey.getEncoded(); // fallback
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
            PublicKey publicKey;
            try {
                publicKey = keyFactory.generatePublic(pubSpec);
            } catch (Exception e) {
                publicKey = null;
            }

            return new KeyPair(publicKey, privateKey);
        } catch (Throwable t) {
            Log.e("KeystoreInjection", "Failed to parse keypair: " + t);
            return null;
        }
    }

    public static PrivateKey parsePrivateKey(String base64) {
        try {
            byte[] bytes = Base64.decode(base64, Base64.DEFAULT);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Throwable t) {
            Log.e("KeystoreInjection", "Failed to parse private key: " + t);
            return null;
        }
    }

    /**
     * Build a dummy certificate with fake attestation extension.
     * This prevents "TEE broken" and "No attestation extensions found" errors.
     */
    public static X509Certificate buildDummyCert(KeyPair kp, String subjectDn) {
        try {
            X500Name subject = new X500Name(subjectDn);
            X500Name issuer = subject;
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24);
            Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365 * 10L);

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .build(kp.getPrivate());
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer, serial, notBefore, notAfter, subject, kp.getPublic());

            // === FAKE ANDROID ATTESTATION EXTENSION ===
            ASN1EncodableVector attestationSeq = new ASN1EncodableVector();
            attestationSeq.add(new DERUTF8String("FAKE_ATTESTATION_RECORD"));
            attestationSeq.add(new DEROctetString("FAKE_BOOT_HASH".getBytes()));
            DERSequence fakeAttestation = new DERSequence(attestationSeq);

            builder.addExtension(
                    new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"),
                    false,
                    fakeAttestation
            );

            // Basic constraints: end-entity, not CA
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(builder.build(signer));

            cert.checkValidity(new Date());
            cert.verify(kp.getPublic());

            return cert;
        } catch (Throwable t) {
            Log.e("KeystoreInjection", "Failed to build dummy cert: " + Log.getStackTraceString(t));
            return null;
        }
    }
}
