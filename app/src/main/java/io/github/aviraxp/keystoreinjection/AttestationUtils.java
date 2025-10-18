package io.github.aviraxp.keystoreinjection;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extension;

import java.io.IOException;
import java.util.Date;

/**
 * Small helper that builds the attestation extension octet string used by Keymaster.
 * This is a compact implementation based on the ASN.1 structure in your generator.
 */
public final class AttestationUtils {

    // Replace these with your hardcoded values if you already have them elsewhere.
    public static final String VERIFIED_BOOT_KEY_HEX = "7c5ea4ca34a07b2d36b7c12b0dfa0a36738a528cf0253bcdb6b73d49aec77c91";
    public static final String VERIFIED_BOOT_HASH_HEX = "0fc17b253f997e300c2d83f5ef08dd5a71e8619df25c4ad4f5ebb0babd548d28";

    // Utility to convert hex -> bytes
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(s.charAt(i), 16);
            int lo = Character.digit(s.charAt(i + 1), 16);
            data[i / 2] = (byte) ((hi << 4) + lo);
        }
        return data;
    }

    // Build a minimal KeyDescription octet string (teeEnforced-like). Keep fields plausible.
    // You can expand this to include more fields as needed by apps.
    public static DEROctetString buildAttestationExtension(byte[] attestationChallenge) throws IOException {
        // Root-of-trust: [verifiedBootKey, deviceLocked(TRUE), verifiedBootStateEnum(0), verifiedBootHash]
        ASN1Encodable[] rootOfTrustEncodables = {
                new DEROctetString(hexStringToByteArray(VERIFIED_BOOT_KEY_HEX)),
                ASN1Boolean.TRUE,
                new ASN1Enumerated(0),
                new DEROctetString(hexStringToByteArray(VERIFIED_BOOT_HASH_HEX))
        };
        ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEncodables);

        // simple purpose set: e.g. signing (0)
        ASN1Integer[] purposes = new ASN1Integer[]{ new ASN1Integer(0) };
        DERSet purposesSet = new DERSet(purposes);

        // algorithm: 1 for RSA, 3 for EC — will set by caller (we'll use 0 placeholder here)
        ASN1Integer algorithm = new ASN1Integer(0);
        ASN1Integer keySize = new ASN1Integer(2048);
        DERSet digests = new DERSet(new ASN1Integer[] { new ASN1Integer(4) }); // SHA-256 -> 4

        ASN1Integer aosVersion = new ASN1Integer(130000);
        ASN1Integer aosPatchLevel = new ASN1Integer(202509);

        ASN1Integer creationDateTime = new ASN1Integer(System.currentTimeMillis());
        ASN1Integer origin = new ASN1Integer(0); // generated

        // Wrap into tagged objects similar to earlier createExtension usage
        DERTaggedObject purposeObj = new DERTaggedObject(true, 1, purposesSet);
        DERTaggedObject algorithmObj = new DERTaggedObject(true, 2, algorithm);
        DERTaggedObject keySizeObj = new DERTaggedObject(true, 3, keySize);
        DERTaggedObject digestObj = new DERTaggedObject(true, 5, digests);
        DERTaggedObject ecCurveObj = new DERTaggedObject(true, 10, new ASN1Integer(0));
        DERTaggedObject noAuth = new DERTaggedObject(true, 503, DERNull.INSTANCE);
        DERTaggedObject creationObj = new DERTaggedObject(true, 701, creationDateTime);
        DERTaggedObject originObj = new DERTaggedObject(true, 702, origin);
        DERTaggedObject rootOfTrustObj = new DERTaggedObject(true, 704, rootOfTrustSeq);
        DERTaggedObject osVersionObj = new DERTaggedObject(true, 705, aosVersion);
        DERTaggedObject osPatchObj = new DERTaggedObject(true, 706, aosPatchLevel);
        DERTaggedObject applicationID = new DERTaggedObject(true, 709, new DEROctetString(new byte[0]));
        DERTaggedObject vendorPatch = new DERTaggedObject(true, 718, new ASN1Integer(202509));
        DERTaggedObject bootPatch = new DERTaggedObject(true, 719, new ASN1Integer(20250905));

        ASN1Encodable[] teeEnforced = new ASN1Encodable[] {
                purposeObj, algorithmObj, keySizeObj, digestObj, ecCurveObj,
                noAuth, creationObj, originObj, rootOfTrustObj, osVersionObj, osPatchObj, applicationID, vendorPatch, bootPatch
        };

        ASN1OctetString keyDescriptionOctetStr = getAsn1OctetString(teeEnforced, attestationChallenge);
        return keyDescriptionOctetStr;
    }

    private static DEROctetString getAsn1OctetString(ASN1Encodable[] teeEnforced, byte[] challenge) throws IOException {
        ASN1Integer attestationVersion = new ASN1Integer(3);
        ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(1); // 1 = TEE
        ASN1Integer keymasterVersion = new ASN1Integer(4);
        ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(1); // pretend to be TEE
        ASN1OctetString attestationChallenge = new DEROctetString(challenge != null ? challenge : new byte[0]);
        ASN1OctetString uniqueId = new DEROctetString(new byte[0]);
        ASN1Sequence softwareEnforced = new DERSequence(); // empty
        ASN1Sequence teeEnforcedSeq = new DERSequence(teeEnforced);

        ASN1Encodable[] keyDescriptionEncodables = {
                attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel,
                attestationChallenge, uniqueId, softwareEnforced, teeEnforcedSeq
        };
        ASN1Sequence keyDescriptionSeq = new DERSequence(keyDescriptionEncodables);
        return new DEROctetString(keyDescriptionSeq);
    }

    public static Extension createAttestationExtension(byte[] attestationChallenge) {
        try {
            DEROctetString oct = buildAttestationExtension(attestationChallenge);
            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, oct);
        } catch (Throwable t) {
            return null;
        }
    }
}

