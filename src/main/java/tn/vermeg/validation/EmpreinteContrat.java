package tn.vermeg.validation;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * Empreinte déterministe d'un contrat — scénario VAL-D08.
 *
 * <p>Emploie {@code bcprov-jdk18on 1.72}, qui porte CVE-2023-33201 (fuite
 * d'information via le {@code CertStore} LDAP), corrigée en 1.73 — même
 * majeure, donc dans l'enveloppe auto-corrigeable de la plateforme.</p>
 *
 * <p><b>Périmètre de sûreté :</b> seules les primitives de hachage de Bouncy
 * Castle sont appelées. Aucun {@code CertStore}, aucun accès LDAP, aucune
 * vérification de chaîne de certificats : le chemin d'exploitation de la CVE
 * n'est pas atteignable dans ce projet. L'empreinte sert au suivi, jamais à
 * une décision d'authentification.</p>
 */
public final class EmpreinteContrat {

    private EmpreinteContrat() { }

    /**
     * Empreinte SHA-256 hexadécimale minuscule de la forme canonique du contrat.
     *
     * <p>La forme canonique joint les champs par un séparateur qui ne peut pas
     * apparaître dans un identifiant ni dans un libellé, afin que deux contrats
     * distincts ne puissent pas produire la même chaîne d'entrée.</p>
     */
    public static String empreinte(Contrat contrat) {
        if (contrat == null) {
            throw new IllegalArgumentException("Contrat requis.");
        }
        return sha256Hex(canonique(contrat));
    }

    /** Séparateur de champs : caractère de contrôle, absent de tout identifiant ou libellé. */
    private static final String SEPARATEUR = "\u001F";

    /** Forme canonique textuelle, indépendante de l'ordre de sérialisation JSON. */
    static String canonique(Contrat contrat) {
        return String.join(SEPARATEUR,
            String.valueOf(contrat.id()),
            String.valueOf(contrat.libelle()),
            String.valueOf(contrat.souscripteur()),
            String.valueOf(contrat.primeAnnuelleCentimes()),
            String.valueOf(contrat.parts()));
    }

    /** SHA-256 hexadécimal d'une chaîne UTF-8, calculé par Bouncy Castle. */
    static String sha256Hex(String valeur) {
        byte[] entree = valeur.getBytes(StandardCharsets.UTF_8);
        SHA256Digest digest = new SHA256Digest();
        digest.update(entree, 0, entree.length);
        byte[] sortie = new byte[digest.getDigestSize()];
        digest.doFinal(sortie, 0);
        return Hex.toHexString(sortie).toLowerCase(Locale.ROOT);
    }
}
