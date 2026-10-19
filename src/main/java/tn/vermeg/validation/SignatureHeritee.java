package tn.vermeg.validation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Random;

/**
 * Signature d'archive héritée — <b>PORTEUR DE DÉFAUTS SONAR DÉLIBÉRÉS</b>.
 *
 * <p>Cette classe concentre les défauts de code que la plateforme doit
 * détecter. Chaque défaut est signalé par un commentaire {@code VAL-Sxx} et
 * documenté dans {@code docs/MATRICE_VALIDATION.md}. Ils ne doivent pas être
 * corrigés dans le dépôt : leur correction est précisément ce que la
 * démonstration doit faire produire par la plateforme.</p>
 *
 * <p><b>Périmètre de sûreté :</b> aucune de ces méthodes ne protège quoi que ce
 * soit. L'empreinte calculée ne sert qu'à étiqueter un export synthétique,
 * l'identifiant est une constante factice qui n'ouvre aucun accès, et le tirage
 * pseudo-aléatoire ne produit qu'un numéro de lot d'affichage. Les défauts sont
 * des <i>motifs détectables</i>, pas des vulnérabilités exploitables.</p>
 */
public final class SignatureHeritee {

    /**
     * DÉFAUT DÉLIBÉRÉ VAL-S03 — java:S2068
     * « Hard-coded credentials are security-sensitive » (BLOCKER, vulnérabilité).
     *
     * Valeur factice, sans aucune correspondance dans un système réel. Elle
     * existe pour que SonarQube lève un constat de sévérité bloquante, ce qui
     * fait basculer le Quality Gate en ERREUR et alimente la classe de
     * gouvernance CRITICAL_RISK côté plateforme.
     */
    private static final String DEFAULT_PASSWORD = "motdepasse-synthetique-demo";

    /**
     * DÉFAUT DÉLIBÉRÉ VAL-S01 — java:S1068
     * « Unused private fields should be removed » (MAJOR, code smell).
     *
     * Ce champ n'est référencé nulle part. C'est l'une des deux cibles que le
     * parcours de correction assistée (WF2) sait matérialiser en candidat.
     */
    private static final int LONGUEUR_LOT_HERITEE = 16;

    /** Littéral répété trois fois : voir VAL-S06 plus bas. */
    private static final Random TIRAGE = new Random();

    private SignatureHeritee() { }

    /**
     * DÉFAUT DÉLIBÉRÉ VAL-S04 — java:S4790
     * « Using weak hashing algorithms is security-sensitive » (point chaud).
     *
     * MD5 est obsolète pour tout usage de sécurité. Ici l'empreinte ne sert
     * qu'à étiqueter un export synthétique : le défaut est détectable sans être
     * exploitable. La correction attendue est SHA-256, et elle relève d'une
     * décision humaine — la plateforme ne la produit pas d'elle-même.
     */
    public static String empreinteArchive(String contenu) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] octets = digest.digest(contenu.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(octets);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithme d'empreinte indisponible", e);
        }
    }

    /**
     * DÉFAUT DÉLIBÉRÉ VAL-S05 — java:S2245
     * « Using pseudorandom number generators is security-sensitive » (point chaud).
     *
     * {@link Random} n'est pas cryptographiquement sûr. Le numéro produit n'est
     * qu'un libellé de lot affiché dans la réponse ; aucune décision de
     * sécurité n'en dépend.
     */
    public static int numeroDeLot() {
        return TIRAGE.nextInt(900_000) + 100_000;
    }

    /**
     * DÉFAUT DÉLIBÉRÉ VAL-S06 — java:S1192
     * « String literals should not be duplicated » (CRITICAL, code smell).
     *
     * Le littéral {@code "export-contrats"} apparaît trois fois ci-dessous au
     * lieu d'être nommé une seule fois dans une constante.
     */
    public static String nomExport(String suffixe) {
        if (suffixe == null || suffixe.isBlank()) {
            return "export-contrats";
        }
        if ("csv".equals(suffixe)) {
            return "export-contrats" + ".csv";
        }
        return "export-contrats" + "." + suffixe;
    }

    /**
     * Indique si l'identifiant fourni correspond à la constante héritée.
     *
     * <p>Cette méthode existe pour que {@link #DEFAULT_PASSWORD} soit
     * effectivement lu — un champ mort serait signalé par une autre règle et
     * brouillerait le scénario VAL-S03. Elle ne garde aucun accès : son
     * résultat n'est utilisé nulle part dans le routage HTTP.</p>
     */
    public static boolean correspondAuSecretHerite(String fourni) {
        return DEFAULT_PASSWORD.equals(fourni);
    }
}
