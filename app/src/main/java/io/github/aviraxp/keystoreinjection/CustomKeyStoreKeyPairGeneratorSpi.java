package io.github.aviraxp.keystoreinjection;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class CustomKeyStoreKeyPairGeneratorSpi extends KeyPairGeneratorSpi {

    private static final int ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX = 0;
    private static final int ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX = 1;
    private static final int ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX = 0;
    private static final int ATTESTATION_PACKAGE_INFO_VERSION_INDEX = 1;

    final String KEYSTORE = "AndroidKeyStore";
    private final String requestedAlgo;
    private KeyGenParameterSpec params;

    private KeyPairGenerator baseGenerator;

    public static final class RSA extends CustomKeyStoreKeyPairGeneratorSpi {
        public RSA() {
            super(KeyProperties.KEY_ALGORITHM_RSA);
        }
    }

    public static final class EC extends CustomKeyStoreKeyPairGeneratorSpi {
        public EC() {
            super(KeyProperties.KEY_ALGORITHM_EC);
        }
    }

    protected CustomKeyStoreKeyPairGeneratorSpi(String algo) {
        requestedAlgo = algo;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        try {
            baseGenerator = KeyPairGenerator.getInstance("OLD" + requestedAlgo, Security.getProvider(KEYSTORE));
            baseGenerator.initialize(keysize, random);
        } catch (Exception e) {
            Log.e("KeystoreInjection", Log.getStackTraceString(e));
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) {
        this.params = (KeyGenParameterSpec) params;
        try {
            baseGenerator = KeyPairGenerator.getInstance("OLD" + requestedAlgo, Security.getProvider(KEYSTORE));
            baseGenerator.initialize(params, random);
        } catch (Exception e) {
            Log.e("KeystoreInjection", Log.getStackTraceString(e));
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        String alias = params.getKeystoreAlias();
        Log.d("KeystoreInjection", "Generating KeyPair for alias: " + alias);

        // If alias already has a certificate, reuse keypair
        Certificate existing = EntryPoint.retrieve(alias);
        if (existing != null) return EntryPoint.box("ecdsa") != null
                ? EntryPoint.box("ecdsa").keypair()
                : EntryPoint.box("rsa").keypair();

        KeyPair kp;
        try {
            if (Objects.equals(requestedAlgo, KeyProperties.KEY_ALGORITHM_EC)) {
                kp = buildECKeyPair();
            } else {
                kp = buildRSAKeyPair();
            }

            // Build dummy certificate for TEE broken fallback
            X509Certificate dummyCert = CertUtils.buildDummyCert(kp, "CN=FakeTEE");
            EntryPoint.append(alias, dummyCert);

            Log.d("KeystoreInjection", "Generated dummy cert for alias: " + alias);
        } catch (Throwable t) {
            Log.e("KeystoreInjection", Log.getStackTraceString(t));
            return null;
        }

        return kp;
    }


    private Extension createExtension(int size) {
        try {
            final String verifiedBootKeyHex = "7c5ea4ca34a07b2d36b7c12b0dfa0a36738a528cf0253bcdb6b73d49aec77c91";
            final String verifiedBootHashHex = "0fc17b253f997e300c2d83f5ef08dd5a71e8619df25c4ad4f5ebb0babd548d28";

            byte[] verifiedBootKey = hexStringToByteArray(verifiedBootKeyHex);
            byte[] verifiedBootHash = hexStringToByteArray(verifiedBootHashHex);

            ASN1Encodable[] rootOfTrustEncodables = {new DEROctetString(verifiedBootKey), ASN1Boolean.TRUE,
                    new ASN1Enumerated(0), new DEROctetString(verifiedBootHash)};

            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEncodables);

            var Apurpose = new DERSet(getPurposesArray());
            var Aalgorithm = new ASN1Integer(getAlgorithm());
            var AkeySize = new ASN1Integer(size);
            var Adigest = new DERSet(getDigests());
            var AecCurve = new ASN1Integer(getEcCurve());
            var AnoAuthRequired = DERNull.INSTANCE;

            // TODO hex3l: add device properties to attestation
//            ASN1Encodable[] deviceProperties;
//            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
//                if (params.isDevicePropertiesAttestationIncluded()) {
//                    var platformReportedBrand = new DEROctetString(getSystemProperty(Build.BRAND).getBytes());
//                    var platformReportedDevice = new DEROctetString(getSystemProperty(Build.DEVICE).getBytes());
//                    var platformReportedProduct = new DEROctetString(getSystemProperty(Build.PRODUCT).getBytes());
//                    var platformReportedManufacturer = new DEROctetString(getSystemProperty(Build.MANUFACTURER).getBytes());
//                    var platformReportedModel = new DEROctetString(getSystemProperty(Build.MODEL).getBytes());
//                    deviceProperties = new ASN1Encodable[]{platformReportedBrand, platformReportedDevice,
//                            platformReportedProduct, platformReportedManufacturer, platformReportedModel};
//                }
//            }

            // To be loaded
            var AosVersion = new ASN1Integer(130000);
            var AosPatchLevel = new ASN1Integer(202509);

            // TODO hex3l: add applicationID to attestation
            var AapplicationID = createApplicationId();
            var AbootPatchlevel = new ASN1Integer(20250905);
            var AvendorPatchLevel = new ASN1Integer(20250905);

            var AcreationDateTime = new ASN1Integer(System.currentTimeMillis());
            var Aorigin = new ASN1Integer(0);

            var purpose = new DERTaggedObject(true, 1, Apurpose);
            var algorithm = new DERTaggedObject(true, 2, Aalgorithm);
            var keySize = new DERTaggedObject(true, 3, AkeySize);
            var digest = new DERTaggedObject(true, 5, Adigest);
            var ecCurve = new DERTaggedObject(true, 10, AecCurve);
            var noAuthRequired = new DERTaggedObject(true, 503, AnoAuthRequired);
            var creationDateTime = new DERTaggedObject(true, 701, AcreationDateTime);
            var origin = new DERTaggedObject(true, 702, Aorigin);
            var rootOfTrust = new DERTaggedObject(true, 704, rootOfTrustSeq);
            var osVersion = new DERTaggedObject(true, 705, AosVersion);
            var osPatchLevel = new DERTaggedObject(true, 706, AosPatchLevel);
            // TODO hex3l: add applicationID to attestation
            var applicationID = new DERTaggedObject(true, 709, AapplicationID);
            var vendorPatchLevel = new DERTaggedObject(true, 718, AvendorPatchLevel);
            var bootPatchLevel = new DERTaggedObject(true, 719, AbootPatchlevel);

            ASN1Encodable[] teeEnforcedEncodables = {purpose, algorithm, keySize, digest, ecCurve,
                    noAuthRequired, creationDateTime, origin, rootOfTrust, osVersion, osPatchLevel, applicationID, vendorPatchLevel, bootPatchLevel};

            ASN1OctetString keyDescriptionOctetStr = getAsn1OctetString(teeEnforcedEncodables);

            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, keyDescriptionOctetStr);

        } catch (Throwable t) {
            Log.e("KeystoreInjection", Log.getStackTraceString(t));
        }
        return null;
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private ASN1OctetString getAsn1OctetString(ASN1Encodable[] teeEnforcedEncodables) throws IOException {
        ASN1Integer attestationVersion = new ASN1Integer(3);
        ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(1);
        ASN1Integer keymasterVersion = new ASN1Integer(4);
        ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(1);
        ASN1OctetString attestationChallenge = new DEROctetString(params.getAttestationChallenge());
        ASN1OctetString uniqueId = new DEROctetString("".getBytes());
        ASN1Sequence softwareEnforced = new DERSequence();
        ASN1Sequence teeEnforced = new DERSequence(teeEnforcedEncodables);

        ASN1Encodable[] keyDescriptionEncodables = {attestationVersion, attestationSecurityLevel, keymasterVersion,
                keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, teeEnforced};

        ASN1Sequence keyDescriptionHackSeq = new DERSequence(keyDescriptionEncodables);

        return new DEROctetString(keyDescriptionHackSeq);
    }

    private ASN1Integer[] getPurposesArray() {
        int purposes = params.getPurposes();
        if (purposes == 0) {
            return new ASN1Integer[]{new ASN1Integer(0)};
        }
        int count = Integer.bitCount(purposes);

        ASN1Integer[] result = new ASN1Integer[count];
        int index = 0;

        for (int i = 0; purposes > 0; i++) {
            if ((purposes & 1) == 1) {
                result[index++] = new ASN1Integer(i);
            }
            purposes >>= 1;
        }

        return result;
    }

    private ASN1Encodable[] getDigests() {
        String[] digests = params.getDigests();
        ASN1Encodable[] result = new ASN1Encodable[digests.length];
        for (int i = 0; i < digests.length; i++) {
            String digest = digests[i];
            int d;
            switch (digest) {
                case KeyProperties.DIGEST_MD5 -> d = 1;
                case KeyProperties.DIGEST_SHA1 -> d = 2;
                case KeyProperties.DIGEST_SHA224 -> d = 3;
                case KeyProperties.DIGEST_SHA256 -> d = 4;
                case KeyProperties.DIGEST_SHA384 -> d = 5;
                case KeyProperties.DIGEST_SHA512 -> d = 6;
                default -> d = 0;
            }
            result[i] = new ASN1Integer(d);
        }
        return result;
    }

    private int getEcCurve() {
        String name = ((ECGenParameterSpec) params.getAlgorithmParameterSpec()).getName();
        int res;
        switch (name) {
            case "secp224r1" -> res = 0;
            case "secp256r1" -> res = 1;
            case "secp384r1" -> res = 2;
            case "secp521r1" -> res = 3;
            case "CURVE_25519" -> res = 4;
            default -> res = -1;
        }
        return res;
    }

    private int getKeySizeFromCurve() {
        String name = ((ECGenParameterSpec) params.getAlgorithmParameterSpec()).getName();
        int res;
        switch (name) {
            case "secp224r1" -> res = 224;
            case "secp256r1", "CURVE_25519" -> res = 256;
            case "secp384r1" -> res = 384;
            case "secp521r1" -> res = 521;
            default -> res = -1;
        }
        return res;
    }

    private int getAlgorithm() {
        return switch (requestedAlgo) {
            case KeyProperties.KEY_ALGORITHM_RSA -> 1;
            case KeyProperties.KEY_ALGORITHM_EC -> 3;
            // No support for other algorithms for now
            default -> 0;
        };
    }

    private KeyPair buildECKeyPair() throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
        ECGenParameterSpec spec = ((ECGenParameterSpec) params.getAlgorithmParameterSpec());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private KeyPair buildRSAKeyPair() throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
        RSAKeyGenParameterSpec spec = ((RSAKeyGenParameterSpec) Objects.requireNonNull(params.getAlgorithmParameterSpec()));
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    @SuppressLint({"PrivateApi", "PackageManagerGetSignatures"})
    private DEROctetString createApplicationId() {
        try {
            Context context = (Context) Class.forName("android.app.AppGlobals").getMethod("getInitialApplication").invoke(null);
            if (context == null) return null;
            PackageManager pm = context.getPackageManager();
            String packageName = context.getPackageName();
            PackageInfo packageInfo;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
            } else {
                packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
            }
            ASN1Encodable[] packageInfoAsn1Array = new ASN1Encodable[2];
            packageInfoAsn1Array[ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX] = new DEROctetString(packageName.getBytes(StandardCharsets.UTF_8));
            long versionCode = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P ? packageInfo.getLongVersionCode() : packageInfo.versionCode;
            packageInfoAsn1Array[ATTESTATION_PACKAGE_INFO_VERSION_INDEX] = new ASN1Integer(versionCode);
            DERSet packageInfosSet = new DERSet(new DERSequence(packageInfoAsn1Array));
            List<Signature> signatures = new ArrayList<>();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && packageInfo.signingInfo != null) {
                if (packageInfo.signingInfo.hasMultipleSigners()) {
                    Collections.addAll(signatures, packageInfo.signingInfo.getApkContentsSigners());
                } else {
                    Collections.addAll(signatures, packageInfo.signingInfo.getSigningCertificateHistory());
                }
            } else if (packageInfo.signatures != null) {
                Collections.addAll(signatures, packageInfo.signatures);
            }
            if (signatures.isEmpty()) return null;
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            ASN1Encodable[] signatureDigests = new ASN1Encodable[signatures.size()];
            for (int i = 0; i < signatures.size(); i++) {
                byte[] digest = md.digest(signatures.get(i).toByteArray());
                signatureDigests[i] = new DEROctetString(digest);
            }
            DERSet signatureDigestsSet = new DERSet(signatureDigests);
            ASN1Encodable[] applicationIdAsn1Array = new ASN1Encodable[2];
            applicationIdAsn1Array[ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX] = packageInfosSet;
            applicationIdAsn1Array[ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX] = signatureDigestsSet;

            return new DEROctetString(new DERSequence(applicationIdAsn1Array));
        } catch (Throwable t) {
            Log.e("KeystoreInjection", "Failed to create Application ID.", t);
            return null;
        }
    }

    @SuppressLint("PrivateApi")
    public String getSystemProperty(String key) {
        String value = null;

        try {
            value = (String) Class.forName("android.os.SystemProperties")
                    .getMethod("get", String.class).invoke(null, key);
        } catch (Throwable t) {
            Log.e("KeystoreInjection", Log.getStackTraceString(t));
        }

        return value;
    }
}
