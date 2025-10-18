package io.github.aviraxp.keystoreinjection;

import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.Objects;

public final class CustomKeyStoreSpi extends KeyStoreSpi {
    public static volatile KeyStoreSpi keyStoreSpi = null;

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        return keyStoreSpi.engineGetKey(alias, password);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        Log.d("KeystoreInjection", "GetChain alias requested: " + alias);

        Certificate leaf = EntryPoint.retrieve(alias);
        LinkedList<Certificate> certificateList = new LinkedList<>();

        if (leaf != null) {
            // Use stored leaf
            certificateList.add(leaf);
            try {
                if (((X509Certificate) leaf).getSigAlgName().contains("ECDSA")) {
                    certificateList.addAll(Objects.requireNonNull(EntryPoint.box("ecdsa")).certificateChain());
                } else {
                    certificateList.addAll(Objects.requireNonNull(EntryPoint.box("rsa")).certificateChain());
                }
            } catch (Throwable t) {
                Log.e("KeystoreInjection", Log.getStackTraceString(t));
            }
        } else {
            // TEE broken → generate dummy cert from first available keybox
            for (String type : new String[]{"ecdsa", "rsa"}) {
                Keybox k = EntryPoint.box(type);
                if (k != null) {
                    try {
                        Certificate dummy = CertUtils.buildDummyCert(k.keypair(), "CN=FakeTEE");
                        certificateList.add(dummy);
                        certificateList.addAll(k.certificateChain());
                        break;
                    } catch (Throwable t) {
                        Log.e("KeystoreInjection", Log.getStackTraceString(t));
                    }
                }
            }
        }

        return certificateList.isEmpty() ? new Certificate[0] : certificateList.toArray(new Certificate[0]);
    }
	
	
    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        keyStoreSpi.engineSetKeyEntry(alias, key, password, chain);
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        keyStoreSpi.engineSetKeyEntry(alias, key, chain);
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        keyStoreSpi.engineSetCertificateEntry(alias, cert);
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        keyStoreSpi.engineDeleteEntry(alias);
    }

    @Override
    public Enumeration<String> engineAliases() {
        return keyStoreSpi.engineAliases();
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return keyStoreSpi.engineContainsAlias(alias);
    }

    @Override
    public int engineSize() {
        return keyStoreSpi.engineSize();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return keyStoreSpi.engineIsKeyEntry(alias);
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return keyStoreSpi.engineIsCertificateEntry(alias);
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        return keyStoreSpi.engineGetCertificateAlias(cert);
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws CertificateException, IOException, NoSuchAlgorithmException {
        keyStoreSpi.engineStore(stream, password);
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws CertificateException, IOException, NoSuchAlgorithmException {
        keyStoreSpi.engineLoad(stream, password);
    }
}
