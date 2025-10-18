package io.github.aviraxp.keystoreinjection;

import android.util.Log;
import org.bouncycastle.asn1.x500.X500Name;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;

public final class EntryPoint {
    private static final Map<String, Keybox> certs = new HashMap<>();
    private static final Map<String, Certificate> store = new HashMap<>();

    static {
        try {
            java.security.KeyStore keyStore = java.security.KeyStore.getInstance("AndroidKeyStore");
            java.lang.reflect.Field keyStoreSpi = keyStore.getClass().getDeclaredField("keyStoreSpi");
            keyStoreSpi.setAccessible(true);
            CustomKeyStoreSpi.keyStoreSpi = (java.security.KeyStoreSpi) keyStoreSpi.get(keyStore);

            java.security.Provider provider = java.security.Security.getProvider("AndroidKeyStore");
            java.security.Security.removeProvider("AndroidKeyStore");
            java.security.Security.insertProviderAt(new CustomProvider(provider), 1);
        } catch (Throwable t) {
            Log.e("KeystoreInjection", Log.getStackTraceString(t));
        }
    }

    public static void receiveXml(String data) {
        XMLParser xmlParser = new XMLParser(data);
        try {
            int numberOfKeyboxes = Integer.parseInt(Objects.requireNonNull(
                    xmlParser.obtainPath("AndroidAttestation.NumberOfKeyboxes").get("text")));
            for (int i = 0; i < numberOfKeyboxes; i++) {
                String keyboxAlgorithm = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "]").get("algorithm");
                String privateKey = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "].PrivateKey").get("text");
                int numberOfCertificates = Integer.parseInt(Objects.requireNonNull(
                        xmlParser.obtainPath(
                                "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.NumberOfCertificates").get("text")));

                LinkedList<Certificate> certificateChain = new LinkedList<>();
                LinkedList<X500Name> certificateChainHolders = new LinkedList<>();
                for (int j = 0; j < numberOfCertificates; j++) {
                    Map<String, String> certData = xmlParser.obtainPath(
                            "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.Certificate[" + j + "]");
                    certificateChain.add(CertUtils.parseCert(certData.get("text")));
                    certificateChainHolders.add(CertUtils.parseCertSubject(certData.get("text")));
                }

                KeyPair kp = CertUtils.parseKeyPair(privateKey);
                store.put(keyboxAlgorithm, certificateChain.isEmpty() ? CertUtils.buildDummyCert(kp, "CN=FakeTEE") : certificateChain.get(0));
                certs.put(keyboxAlgorithm, new Keybox(kp,
                        CertUtils.parsePrivateKey(privateKey),
                        certificateChain,
                        certificateChainHolders));
            }
        } catch (Throwable t) {
            Log.e("KeystoreInjection", Log.getStackTraceString(t));
        }
    }

    public static void append(String alias, Certificate cert) {
        store.put(alias, cert);
    }

    public static Certificate retrieve(String alias) {
        Certificate cert = store.get(alias);
        if (cert != null) return cert;

        // Fallback: use first keybox to generate dummy cert
        for (Keybox k : certs.values()) {
            try {
                X509Certificate dummy = CertUtils.buildDummyCert(k.keypair(), "CN=FakeTEE");
                store.put(alias, dummy);
                return dummy;
            } catch (Throwable t) {
                Log.e("KeystoreInjection", Log.getStackTraceString(t));
            }
        }
        return null;
    }

    public static Keybox box(String type) {
        return certs.get(type);
    }
}
