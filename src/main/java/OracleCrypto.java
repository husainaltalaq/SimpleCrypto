import org.apache.commons.codec.binary.Base64;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Clob;
import java.sql.SQLException;

public class OracleCrypto {
    private static String clobToString(Clob data) {
        StringBuilder sb = new StringBuilder();
        try {
            Reader reader = data.getCharacterStream();
            BufferedReader br = new BufferedReader(reader);

            int ch;
            while ((ch = reader.read()) != -1) {
                sb.append("" + (char) ch);
            }
            br.close();
        } catch (SQLException e) {
            e.getMessage();
        } catch (IOException e) {
            e.getMessage();
        }
        return sb.toString();
    }

    public static String clobTest(Clob tst) {
        return clobToString(tst);
    }

    public static String generateSignature(String algorithm, String signatureAlgorithm, String charset, String privateKeyString, Clob plainText) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        return Base64.encodeBase64String(SimpleCrypto.generateSignature(algorithm, signatureAlgorithm, charset, privateKeyString, clobToString(plainText)));
    }

    public static boolean validateSignature(String algorithm, String signatureAlgorithm, String charset, String publicKeyString, String signature, Clob plainText) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        return SimpleCrypto.validateSignature(algorithm, signatureAlgorithm, charset, publicKeyString, signature, clobToString(plainText));
    }


    // Commented Example
    public static void main(String[] args) throws SQLException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, NoSuchProviderException, InvalidKeyException, UnsupportedEncodingException, CertificateException, CertificateException {
        String testMessage =  "This is a Test Message";

        Clob message = new javax.sql.rowset.serial.SerialClob(testMessage.toCharArray());

        String signature = generateSignature(SimpleCrypto.algorithms.EC_ALG, SimpleCrypto.signatureAlgorithms.SHA256_WITH_ECDSA, String.valueOf(StandardCharsets.UTF_8),"ME0CAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEMzAxAgEBBCBxf/9PJHF1iprFcQ8B\n" +
                "lwOZhkGUXa0YdRkz5gJmG0EVjqAKBggqhkjOPQMBBw==", message);

        System.out.println("Plain text Signature: " + signature);

        boolean verify = validateSignature(SimpleCrypto.algorithms.EC_ALG,SimpleCrypto.signatureAlgorithms.SHA256_WITH_ECDSA, String.valueOf(StandardCharsets.UTF_8),"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiTweVoM0jQ77LzkNGVUHYf7V0Uk4ikd5JA+sBZuxVIl4RzXCpfF+ytZtgh3xawpyFidwMHvhXBChwff5YvAf+A==", signature, message);

        System.out.println("Plain text verification: " + verify);


        System.out.println(SimpleCrypto.getPublicKey(SimpleCrypto.algorithms.EC_ALG, "X.509", "MIIF1zCCBL+gAwIBAgITEgAAABndiO20V5WguQAAAAAAGTANBgkqhkiG9w0BAQsF\n" +
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
    }
}
