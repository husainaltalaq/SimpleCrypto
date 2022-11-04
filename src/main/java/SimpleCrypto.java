import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.*;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

//Example of Algorithm: "EC"
//Example of Signature Algorithm: "sha256withECDSA"
//Example of Charset: "UTF-8"
//Example of Certificate Type: "X.509"

public class SimpleCrypto {
    /************* Algorithms *************/
    public class algorithms{
        public static final String EC_ALG = "EC";
        public static final String RSA_ALG = "RSA";
        public static final String DSA_ALG = "DSA";
        public static final String RSASSA_PSS_ALG = "RSASSA-PSS";
        public static final String XDH_ALG = "XDH";
        public static final String X25519_ALG = "X25519";
        public static final String X448_ALG = "X448";
    }

    /************* Signature Algorithms *************/
    public class signatureAlgorithms{
        public static final String NONE_WITH_RSA = "NONEwithRSA";
        public static final String MD2_WITH_RSA = "MD2withRSA";
        public static final String MD5_WITH_RSA = "MD5withRSA";
        public static final String SHA1_WITH_RSA = "SHA1withRSA";
        public static final String SHA224_WITH_RSA = "SHA224withRSA";
        public static final String SHA256_WITH_RSA = "SHA256withRSA";
        public static final String SHA384_WITH_RSA = "SHA384withRSA";
        public static final String SHA512_WITH_RSA = "SHA512withRSA";
        public static final String SHA512_224_WITH_RSA = "SHA512/224withRSA";
        public static final String SHA512_256_WITH_RSA = "SHA512/256withRSA";
        public static final String SHA3_224_WITH_RSA = "SHA3-224withRSA";
        public static final String SHA3_256_WITH_RSA = "SHA3-256withRSA";
        public static final String SHA3_384_WITH_RSA = "SHA3-384withRSA";
        public static final String SHA3_512_WITH_RSA = "SHA3-512withRSA";
        public static final String RSASSA_PSS = "RSASSA-PSS";
        public static final String NONE_WITH_DSA = "NONEwithDSA";
        public static final String SHA1_WITH_DSA = "SHA1withDSA";
        public static final String SHA224_WITH_DSA = "SHA224withDSA";
        public static final String SHA256_WITH_DSA = "SHA256withDSA";
        public static final String SHA384_WITH_DSA = "SHA384withDSA";
        public static final String SHA512_WITH_DSA = "SHA512withDSA";
        public static final String SHA3_224_WITH_DSA = "SHA3-224withDSA";
        public static final String SHA3_256_WITH_DSA = "SHA3-256withDSA";
        public static final String SHA3_384_WITH_DSA = "SHA3-384withDSA";
        public static final String SHA3_512_WITH_DSA = "SHA3-512withDSA";
        public static final String NONE_WITH_ECDSA = "NONEwithECDSA";
        public static final String SHA1_WITH_ECDSA = "SHA1withECDSA";
        public static final String SHA224_WITH_ECDSA = "SHA224withECDSA";
        public static final String SHA256_WITH_ECDSA = "SHA256withECDSA";
        public static final String SHA384_WITH_ECDSA = "SHA384withECDSA";
        public static final String SHA512_WITH_ECDSA = "SHA512withECDSA";
        public static final String SHA3_224_WITH_ECDSA = "SHA3-224withECDSA";
        public static final String SHA3_256_WITH_ECDSA = "SHA3-256withECDSA";
        public static final String SHA3_384_WITH_ECDSA = "SHA3-384withECDSA";
        public static final String SHA3_512_WITH_ECDSA = "SHA3-512withECDSA";
        public static final String NONE_WITH_DSAINP1363FORMAT = "NONEwithDSAinP1363Format";
        public static final String SHA1_WITH_DSAINP1363FORMAT = "SHA1withDSAinP1363Format";
        public static final String SHA224_WITH_DSAINP1363FORMAT = "SHA224withDSAinP1363Format";
        public static final String SHA256_WITH_DSAINP1363FORMAT = "SHA256withDSAinP1363Format";
        public static final String NONE_WITH_ECDSAINP1363FORMAT = "NONEwithECDSAinP1363Format";
        public static final String SHA1_WITH_ECDSAINP1363FORMAT = "SHA1withECDSAinP1363Format";
        public static final String SHA224_WITH_ECDSAINP1363FORMAT = "SHA224withECDSAinP1363Format";
        public static final String SHA256_WITH_ECDSAINP1363FORMAT = "SHA256withECDSAinP1363Format";
        public static final String SHA384_WITH_ECDSAINP1363FORMAT = "SHA384withECDSAinP1363Format";
        public static final String SHA512_WITH_ECDSAINP1363FORMAT = "SHA512withECDSAinP1363Format";
    }
    public static byte[] generateSignature(String algorithm, String signatureAlgorithm, String charset, String privateKeyString, String plainText) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        byte[] encoded = Base64.decodeBase64(privateKeyString);
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(keyFactory.generatePrivate(keySpec));
        signer.update(plainText.getBytes(charset));
        byte[] signature = signer.sign();

        return signature;
    }

    public static boolean validateSignature(String algorithm, String signatureAlgorithm, String charset, String publicKeyString, String signature, String plainText) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKeyString));
        Signature verifier = Signature.getInstance(signatureAlgorithm);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        verifier.initVerify(publicKey);
        verifier.update(plainText.getBytes(charset));
        boolean result = verifier.verify(Base64.decodeBase64(signature));

        return result;
    }

    public static String getPublicKey(String algorithm, String certificateType, String certificate) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream targetStream = new ByteArrayInputStream(Base64.decodeBase64(certificate));
        CertificateFactory cf = CertificateFactory.getInstance(certificateType);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(targetStream);
        PublicKey publicKey = cert.getPublicKey();
        byte[] encoded = publicKey.getEncoded();
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encoded);

        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PublicKey key = keyFactory.generatePublic(x509EncodedKeySpec);

        return Base64.encodeBase64String(key.getEncoded());
    }

    /*public static void main(String[] args) throws SQLException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, UnsupportedEncodingException, CertificateException {
        String message =  "This is a Test Message";

        String signature = Base64.encodeBase64String(generateSignature(algorithms.EC_ALG, signatureAlgorithms.SHA256_WITH_ECDSA, String.valueOf(StandardCharsets.UTF_8),"ME0CAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEMzAxAgEBBCBxf/9PJHF1iprFcQ8B\n" +
                "lwOZhkGUXa0YdRkz5gJmG0EVjqAKBggqhkjOPQMBBw==", message));

        System.out.println("Plain text Signature: " + signature);

        boolean verify = validateSignature(SimpleCrypto.algorithms.EC_ALG,SimpleCrypto.signatureAlgorithms.SHA256_WITH_ECDSA, String.valueOf(StandardCharsets.UTF_8),"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiTweVoM0jQ77LzkNGVUHYf7V0Uk4ikd5JA+sBZuxVIl4RzXCpfF+ytZtgh3xawpyFidwMHvhXBChwff5YvAf+A==", signature, message);

        System.out.println("Plain text verification: " + verify);


        System.out.println(SimpleCrypto.getPublicKey(algorithms.EC_ALG, "X.509", "MIIF1zCCBL+gAwIBAgITEgAAABndiO20V5WguQAAAAAAGTANBgkqhkiG9w0BAQsF\n" +
                "ADBVMRUwEwYKCZImiZPyLGQBGRYFTE9DQUwxFzAVBgoJkiaJk/IsZAEZFgdCRU5F\n" +
                "RklUMSMwIQYDVQQDExpCRU5FRklULUlTU1VJTkctVEVTVC1DQS1DQTAeFw0yMTA3\n" +
                "MjgxMjEyMzdaFw0yMzA3MjgxMjEyMzdaMHIxCzAJBgNVBAYTAkJIMRAwDgYDVQQI\n" +
                "EwdCYWhyYWluMQ8wDQYDVQQHEwZNYW5hbWExEDAOBgNVBAoTB0JFTkVGSVQxEDAO\n" +
                "BgNVBAsTB0JFTkVGSVQxHDAaBgNVBAMTE0VDSEVRVUUgQ0VOVFJBTCBVQVQwWTAT\n" +
                "BgcqhkjOPQIBBggqhkjOPQMBBwNCAASJPB5WgzSNDvsvOQ0ZVQdh/tXRSTiKR3kk\n" +
                "D6wFm7FUiXhHNcKl8X7K1m2CHfFrCnIWJ3Awe+FcEKHB9/li8B/4o4IDTDCCA0gw\n" +
                "HQYDVR0OBBYEFKhTjnnIm0VdM9CYjp82FbEuVecUMB8GA1UdIwQYMBaAFC1y1Khp\n" +
                "oK655Ml1N4oEXUMQAoktMIIBNwYDVR0fBIIBLjCCASowggEmoIIBIqCCAR6GTmh0\n" +
                "dHA6Ly9pc3N1aW5nLXRlc3QtY2EuQkVORUZJVC5MT0NBTC9DZXJ0RW5yb2xsL0JF\n" +
                "TkVGSVQtSVNTVUlORy1URVNULUNBLUNBLmNybIaBy2xkYXA6Ly8vQ049QkVORUZJ\n" +
                "VC1JU1NVSU5HLVRFU1QtQ0EtQ0EsQ049aXNzdWluZy10ZXN0LWNhLENOPUNEUCxD\n" +
                "Tj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1\n" +
                "cmF0aW9uLERDPUJFTkVGSVQsREM9TE9DQUw/Y2VydGlmaWNhdGVSZXZvY2F0aW9u\n" +
                "TGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIIBgQYI\n" +
                "KwYBBQUHAQEEggFzMIIBbzB4BggrBgEFBQcwAoZsaHR0cDovL2lzc3VpbmctdGVz\n" +
                "dC1jYS5CRU5FRklULkxPQ0FML0NlcnRFbnJvbGwvaXNzdWluZy10ZXN0LWNhLkJF\n" +
                "TkVGSVQuTE9DQUxfQkVORUZJVC1JU1NVSU5HLVRFU1QtQ0EtQ0EuY3J0MIG7Bggr\n" +
                "BgEFBQcwAoaBrmxkYXA6Ly8vQ049QkVORUZJVC1JU1NVSU5HLVRFU1QtQ0EtQ0Es\n" +
                "Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO\n" +
                "PUNvbmZpZ3VyYXRpb24sREM9QkVORUZJVCxEQz1MT0NBTD9jQUNlcnRpZmljYXRl\n" +
                "P2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTA1BggrBgEF\n" +
                "BQcwAYYpaHR0cDovL2lzc3VpbmctdGVzdC1jYS5CRU5FRklULkxPQ0FML29jc3Aw\n" +
                "IQYJKwYBBAGCNxQCBBQeEgBXAGUAYgBTAGUAcgB2AGUAcjAOBgNVHQ8BAf8EBAMC\n" +
                "B4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggEBAJXRYCv6\n" +
                "Ed7BasEYqMuZ7KOQotavVBYtIzwOplsRfdikPBsAGQubCYmw59Sb8xM50mXe29L2\n" +
                "zf9Nz7QhOdWya5fvTEAVe+v+uXlyAXobdOI9gIKNyqraH23XQwH+a59yNC2/Y9yT\n" +
                "mImlMmWW3aODIZPPXOs34UCH5eSmlq7OXVyzhmXvTwc46Rmd7Mha0uv7rVTYyiZx\n" +
                "Kw6tTmsCZ13BVLrbQy93e26+2ag1+wI/EEYshKYUg5GPYxVaGVVf0UzDKljbqWCp\n" +
                "9DmnBGUHWTZ0iIVGOmjvoCZ+pzBHblkrN1haTNQNJxBSJK1RSAzar54l5Il6EyQx\n" +
                "MiD3yGP+WJVyZws="));
    }*/

}
