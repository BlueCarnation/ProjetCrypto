import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.*;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.math.ec.ECPoint;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

public class ValidateCert {

    // Cache pour les CRL téléchargées
    private static Map<String, X509CRL> crlCache = new HashMap<>();

    public static void main(String[] args) {
        // Vérification des arguments
        if (args.length < 3 || !"-format".equals(args[0])) {
            System.err.println("Usage for single cert: validate-cert -format <DER|PEM> <myRCAcertFile>");
            System.err.println("Usage for cert chain: validate-cert -format <DER|PEM> <myRCAcertFile> <myICAcertFile> ... <myLeafcertFile>");
            System.exit(1);
        }

        String format = args[1]; // Format du certificat (DER ou PEM).
        String[] certFiles = new String[args.length - 2]; // Chemins des fichiers de certificat.
        System.arraycopy(args, 2, certFiles, 0, args.length - 2);

        try {
            if (certFiles.length == 1) {
                // Charge et valide un seul certificat.
                X509Certificate cert = loadCertificate(certFiles[0], format);
                validateCertificate(cert);
            } else {
                // Charge et valide une chaîne de certificats.
                validateCertChain(certFiles, format);
                System.out.println("Certificate chain is valid.");
            }
        } catch (Exception e) {
            System.err.println("Validation error: " + e.getMessage());
        }
    }

    // Charge un certificat à partir d'un fichier, en utilisant le format spécifié (DER ou PEM).
    private static X509Certificate loadCertificate(String certFile, String format) throws IOException, CertificateException {
        // Ouvre le fichier de certificat et lit son contenu.
        FileInputStream fis = new FileInputStream(certFile);
        byte[] fileContent = fis.readAllBytes();

        // Crée une fabrique de certificats pour le type X.509.
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Traite le fichier en fonction de son format (DER ou PEM) et renvoie le certificat chargé.
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

    // Valide un certificat, en vérifiant sa signature, sa période de validité, et son statut de révocation.
    private static void validateCertificate(X509Certificate cert) throws Exception {
        PublicKey key = cert.getPublicKey();
        List<String> validationErrors = new ArrayList<>();

        if (key instanceof RSAPublicKey) {
            // Vérification de la signature RSA
            boolean isValidRSA = verifyRSASignature(cert, (RSAPublicKey) key);
            if (!isValidRSA) {
                System.err.println("RSA Signature verification failed.");
            } else {
                System.out.println("RSA Signature verified successfully.");
            }
        } else if (key instanceof ECPublicKey) {
            // Vérification de la signature ECDSA
            try {
                boolean isValidECDSA = verifyECDSASignature(cert, cert.getTBSCertificate());
                if (!isValidECDSA) {
                    System.err.println("ECDSA Signature verification failed.");
                } else {
                    System.out.println("ECDSA Signature verified successfully.");
                }
            } catch (GeneralSecurityException e) {
                System.err.println("Failed to verify ECDSA signature: " + e.getMessage());
            }
        } else {
            // Autres types de clés
            try {
                cert.verify(key);
            } catch (SignatureException e) {
                validationErrors.add("Signature does not match.");
            }
        }

        // Vérification de KeyUsage
        try {
            boolean keyCertSign = cert.getKeyUsage()[5];
            if (!keyCertSign) {
                validationErrors.add("KeyUsage does not allow keyCertSign.");
            }
        } catch (NullPointerException e) {
            validationErrors.add("KeyUsage information is missing.");
        }

        // Vérification de la période de validité
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException e) {
            validationErrors.add("The certificate has expired.");
        } catch (CertificateNotYetValidException e) {
            validationErrors.add("The certificate is not yet valid.");
        }

        // Vérification CRL/OCSP pour un seul certificat
        try {
            checkRevocation(cert, null); // Passer null si le certificat est auto-signé ou si l'émetteur n'est pas disponible
            System.out.println("Revocation status: The certificate is not revoked.");
        } catch (Exception e) {
            System.err.println("Revocation check failed: " + e.getMessage());
            validationErrors.add("Revocation check failed: " + e.getMessage());
        }

        // Décidez de la validité basée sur la liste des erreurs.
        if (!validationErrors.isEmpty()) {
            System.err.println("Validation errors found:");
            validationErrors.forEach(error -> System.err.println(" - " + error));
            System.err.println("Certificate is INVALID.");
        } else {
            System.out.println("Certificate is valid.");
        }

        // Affichage des informations du certificat
        System.out.println("Signature Algorithm: " + cert.getSigAlgName());
        System.out.println("Signature: " + Arrays.toString(cert.getSignature()));
        System.out.println("Subject: " + cert.getSubjectDN());
        System.out.println("Issuer: " + cert.getIssuerDN());
    }

    private static void checkCRL(X509Certificate cert, X509Certificate issuerCert) throws Exception {
        String ocspUrl = getOCSPUrl(cert);

        if (ocspUrl != null && !ocspUrl.isEmpty()) {
            // Si une URL OCSP est disponible, effectuez la vérification OCSP
            System.out.println("OCSP URL found: " + ocspUrl);
            checkOCSP(cert, issuerCert, ocspUrl);
        } else {
            // Sinon, effectuez la vérification CRL comme auparavant
            List<String> crlDistPoints = getCRLDistributionPoints(cert);
            for (String crlDP : crlDistPoints) {
                X509CRL crl = downloadCRL(crlDP);
                if (crl.isRevoked(cert)) {
                    throw new CertificateException("The certificate is revoked by CRL at " + crlDP);
                }
            }
        }
    }

    private static List<String> getCRLDistributionPoints(X509Certificate cert) throws IOException {
        byte[] crldpExt = cert.getExtensionValue("2.5.29.31");
        if (crldpExt == null) {
            return new ArrayList<>();
        }
        // Supposons que la valeur est directement l'URL en tant que chaîne.
        String url = new String(crldpExt);
        List<String> urls = new ArrayList<>();
        urls.add(url);
        return urls;
    }

    private static X509CRL downloadCRL(String crlDP) throws IOException, CRLException, CertificateException {
        // Vérifier si la CRL pour cette URL est déjà dans le cache
        if (crlCache.containsKey(crlDP)) {
            X509CRL crl = crlCache.get(crlDP);
            // Vérifier si la CRL est encore valide
            if (crl.getNextUpdate() != null && new Date().before(crl.getNextUpdate())) {
                System.out.println("Using cached CRL.");
                return crl;
            } else {
                System.out.println("Cached CRL is outdated.");
            }
        }

        // Si la CRL n'est pas dans le cache ou est périmée, la télécharger
        System.out.println("Downloading new CRL.");
        URL crlURL = new URL(crlDP);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL) cf.generateCRL(crlURL.openStream());

        // Mettre à jour le cache avec la nouvelle CRL
        crlCache.put(crlDP, crl);
        return crl;
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
            PublicKey issuerPublicKey = issuer.getPublicKey();

            // Déterminer le type de clé publique et vérifier la signature en conséquence
            if (issuerPublicKey instanceof RSAPublicKey) {
                // Vérification de la signature RSA
                if (!verifyRSASignature(subject, (RSAPublicKey) issuerPublicKey)) {
                    throw new Exception("Failed RSA signature verification for certificate " + (i + 1));
                }
            } else if (isECDSAPublicKey(issuerPublicKey)) {
                // Vérification de la signature ECDSA
                byte[] signatureBytes = subject.getSignature();
                byte[] tbsCertificate = subject.getTBSCertificate(); // Les données signées (To Be Signed)

                if (!verifyECDSASignature(subject, tbsCertificate)) {
                    throw new Exception("Failed ECDSA signature verification for certificate " + (i + 1));
                }
            } else {
                // Pour les types de clés non reconnus, utilisez la méthode de vérification par défaut
                subject.verify(issuerPublicKey);
            }

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

            if (issuer != null) { // Sauf pour le certificat racine auto-signé
                checkRevocation(subject, issuer);
            }
        }
    }

    private static boolean isECDSAPublicKey(PublicKey publicKey) {
        // Vérifie si l'algorithme de la clé publique est ECDSA
        return publicKey.getAlgorithm().equals("EC") || publicKey.getAlgorithm().equals("ECDSA");
    }

    private static boolean verifyRSASignature(X509Certificate subject, RSAPublicKey publicKey) throws Exception {
        // Calcule le hash SHA-256 du contenu du certificat
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
        byte[] certData = subject.getTBSCertificate(); // Les données à signer (TBS = To Be Signed)
        byte[] hash = sha256Digest.digest(certData);

        // Obtention de la signature à vérifier
        byte[] signature = subject.getSignature();

        // Déchiffrement de la signature avec la clé publique RSA
        BigInteger signatureInt = new BigInteger(1, signature);
        BigInteger modulus = publicKey.getModulus();
        BigInteger exponent = publicKey.getPublicExponent();
        BigInteger decryptedSignatureInt = signatureInt.modPow(exponent, modulus);

        // Conversion du BigInteger déchiffré en un tableau d'octets. Ce tableau contient le hash déchiffré.
        // Approche simplifié qui ignore la structure ASN.1 entourant le hash de la signature
        byte[] decryptedSignature = decryptedSignatureInt.toByteArray();

        // La longueur du hash SHA-256 est de 32 octets. Les derniers 32 octets de la signature déchiffrée doivent correspondre au hash calculé.
        // Encore une fois on ignore la structure ASN.1 donc fonctionne uniquement si signature et hash dans les informations
        if (decryptedSignature.length < hash.length) {
            return false; // La signature déchiffrée est trop courte pour contenir le hash attendu.
        }

        // Comparer le hash extrait de la signature déchiffrée avec le hash calculé.
        for (int i = 0; i < hash.length; i++) {
            if (hash[i] != decryptedSignature[decryptedSignature.length - hash.length + i]) {
                return false; // Les hashes ne correspondent pas.
            }
        }

        return true;
    }

    private static boolean verifyECDSASignature(X509Certificate cert, byte[] data) throws GeneralSecurityException {
        PublicKey publicKey = cert.getPublicKey();

        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("Public key must be an instance of ECPublicKey for ECDSA verification.");
        }

        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        ECParameterSpec spec = ecPublicKey.getParams();

        // Conversion to BouncyCastle types
        ECPoint Q = EC5Util.convertPoint(spec, ecPublicKey.getW());
        X9ECParameters ecParams = ECNamedCurveTable.getByName("P-256");
        ECDomainParameters domainParameters = new ECDomainParameters(ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());

        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(Q, domainParameters);

        ECDSASigner signer = new ECDSASigner();
        signer.init(false, publicKeyParameters);

        BigInteger[] rs = decodeSignature(cert.getSignature());
        if (rs == null) {
            throw new GeneralSecurityException("Invalid ECDSA signature format.");
        }

        // Hash the data with SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);

        if (!signer.verifySignature(hash, rs[0], rs[1])) {
            throw new GeneralSecurityException("ECDSA signature verification failed.");
        }

        return true;
    }

    private static BigInteger[] decodeSignature(byte[] signature) {
        return new BigInteger[]{new BigInteger("r-value"), new BigInteger("s-value")};
    }

    private static String getOCSPUrl(X509Certificate cert) throws IOException {
        try {
            byte[] aiaExtensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
            if (aiaExtensionValue != null) {
                DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(aiaExtensionValue)).readObject());
                AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(ASN1Sequence.getInstance(oct.getOctets()));
                for (AccessDescription accessDescription : authorityInformationAccess.getAccessDescriptions()) {
                    if (accessDescription.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                        GeneralName generalName = accessDescription.getAccessLocation();
                        if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String ocspUrl = ((ASN1String) generalName.getName()).getString();
                            return ocspUrl;
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error extracting OCSP URL: " + e);
        }
        return null;
    }

    public static void checkOCSP(X509Certificate cert, X509Certificate issuerCert, String ocspUrl) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        if (issuerCert == null) {
            throw new IllegalArgumentException("Issuer certificate is null, OCSP check cannot be performed.");
        }

        System.out.println("OCSP URL found: " + ocspUrl);

        // Créer l'identifiant du certificat pour la requête OCSP
        CertificateID id = new CertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuerCert),
                cert.getSerialNumber());

        // Construire la requête OCSP
        OCSPReq ocspReq = new OCSPReqBuilder().addRequest(id).build();

        // Envoyer la requête OCSP et recevoir la réponse
        byte[] bytes = ocspReq.getEncoded();
        URL url = new URL(ocspUrl);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        con.setDoOutput(true);
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        con.setRequestProperty("Accept", "application/ocsp-response");
        con.getOutputStream().write(bytes);

        // Lire la réponse
        InputStream in = (InputStream) con.getContent();
        OCSPResp ocspResponse = new OCSPResp(in);
        BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();

        // Vérifier la réponse pour chaque certificat
        boolean revoked = false;
        if (basicResponse != null) {
            for (SingleResp resp : basicResponse.getResponses()) {
                CertificateStatus status = resp.getCertStatus();
                if (status == CertificateStatus.GOOD) {
                    System.out.println("Certificate status: GOOD");
                } else if (status instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
                    System.out.println("Certificate status: REVOKED");
                    revoked = true;
                } else if (status instanceof org.bouncycastle.cert.ocsp.UnknownStatus) {
                    System.out.println("Certificate status: UNKNOWN");
                }
            }
        }

        if (revoked) {
            throw new Exception("The certificate has been revoked.");
        }
    }

    private static void checkRevocation(X509Certificate cert, X509Certificate issuerCert) throws Exception {
        String ocspUrl = getOCSPUrl(cert);
        if (ocspUrl != null && !ocspUrl.isEmpty()) {
            System.out.println("Attempting OCSP check...");
            checkOCSP(cert, issuerCert, ocspUrl);
        } else {
            System.out.println("Attempting CRL check...");
            checkCRL(cert, issuerCert);
        }
    }
}