import java.io.FileInputStream;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.*;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.util.Base64;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.List;

public class ValidateCert {

    public static void main(String[] args) {
        if (args.length < 3 || !"-format".equals(args[0])) {
            System.err.println("Usage for single cert: validate-cert -format <DER|PEM> <myRCAcertFile>");
            System.err.println("Usage for cert chain: validate-cert -format <DER|PEM> <myRCAcertFile> <myICAcertFile> ... <myLeafcertFile>");
            System.exit(1);
        }

        String format = args[1];
        String[] certFiles = new String[args.length - 2];
        System.arraycopy(args, 2, certFiles, 0, args.length - 2);

        try {
            if (certFiles.length == 1) {
                // Si un seul certificat est fourni
                X509Certificate cert = loadCertificate(certFiles[0], format);
                validateCertificate(cert);
                System.out.println("Single certificate is valid.");
            } else {
                // Pour une chaîne de certificats
                validateCertChain(certFiles, format);
                System.out.println("Certificate chain is valid.");
            }
        } catch (Exception e) {
            System.err.println("Validation error: " + e.getMessage());
        }
    }


    private static X509Certificate loadCertificate(String certFile, String format) throws IOException, CertificateException {
        FileInputStream fis = new FileInputStream(certFile);
        byte[] fileContent = fis.readAllBytes();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        if (format.equalsIgnoreCase("DER")) {
            // Vérifier si le fichier contient des en-têtes/pieds de page PEM
            String fileContentString = new String(fileContent);
            if (fileContentString.contains("-----BEGIN CERTIFICATE-----") || fileContentString.contains("-----END CERTIFICATE-----")) {
                throw new CertificateException("File is not in DER format; PEM headers found.");
            }
            // Si aucun en-tête PEM n'est trouvé, nous pouvons essayer de traiter le fichier comme DER
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(fileContent));
        } else if (format.equalsIgnoreCase("PEM")) {
            String pemString = new String(fileContent);
            if (!pemString.contains("-----BEGIN CERTIFICATE-----") || !pemString.contains("-----END CERTIFICATE-----")) {
                throw new CertificateException("File does not contain PEM format certificate.");
            }
            String base64Encoded = pemString.replace("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END CERTIFICATE-----", "");
            byte[] derDecoded = Base64.getDecoder().decode(base64Encoded);
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derDecoded));
        } else {
            throw new IllegalArgumentException("Unsupported format: " + format);
        }
    }

    private static void validateCertificate(X509Certificate cert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        PublicKey key = cert.getPublicKey();
        cert.verify(key); // Valide la signature du certificat avec la clé publique contenue dans le certificat

        System.out.println("Signature Algorithm: " + cert.getSigAlgName());
        System.out.println("Signature: " + cert.getSignature());
        System.out.println("Subject: " + cert.getSubjectDN());
        System.out.println("Issuer: " + cert.getIssuerDN());

        // Vérification de KeyUsage
        boolean keyCertSign = cert.getKeyUsage()[5];
        if (!keyCertSign) {
            throw new CertificateException("KeyUsage does not allow keyCertSign");
        }

        // Vérification de la période de validité
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new CertificateException("The certificate has expired", e);
        } catch (CertificateNotYetValidException e) {
            throw new CertificateException("The certificate is not yet valid", e);
        }

        // Vérification de la signature
        String sigAlgName = cert.getSigAlgName();
        Signature signature = Signature.getInstance(sigAlgName);
        signature.initVerify(key);
        signature.update(cert.getTBSCertificate());

        if (!signature.verify(cert.getSignature())) {
            throw new SignatureException("Signature does not match.");
        }
    }

    private static void validateCertChain(String[] certFiles, String format) throws Exception {
        // Charger tous les certificats dans un tableau
        X509Certificate[] certs = new X509Certificate[certFiles.length];
        for (int i = 0; i < certFiles.length; i++) {
            certs[i] = loadCertificate(certFiles[i], format);
        }

        // Vérifier la chaîne de certificats
        for (int i = 0; i < certs.length - 1; i++) {
            X509Certificate issuer = certs[i];
            X509Certificate subject = certs[i + 1];

            // Vérifiez que le sujet est signé par l'émetteur
            subject.verify(issuer.getPublicKey());

            // Vérifiez la correspondance des sujets et des émetteurs
            if (!issuer.getSubjectX500Principal().equals(subject.getIssuerX500Principal())) {
                throw new CertificateException("Subject of certificate " + (i + 1) + " does not match issuer of certificate " + i);
            }

            // Vérification de BasicConstraints
            if (i < certs.length - 2) { // Pas nécessaire pour le certificat feuille
                boolean isCA = issuer.getBasicConstraints() != -1;
                if (!isCA) {
                    throw new CertificateException("Certificate " + i + " is not a CA certificate as required");
                }
            }
        }
    }
}
