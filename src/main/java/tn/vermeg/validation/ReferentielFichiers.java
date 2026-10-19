package tn.vermeg.validation;

import org.apache.commons.io.FilenameUtils;

/**
 * Normalisation des noms de fichiers du référentiel — scénario VAL-D03.
 *
 * <p>Emploie {@code commons-io 2.6}, qui porte la CVE-2021-29425 (traversée de
 * chemin via {@code FilenameUtils.normalize}), corrigée en 2.7 — même majeure,
 * donc dans l'enveloppe auto-corrigeable de la plateforme.</p>
 *
 * <p><b>Périmètre de sûreté :</b> aucune opération sur le système de fichiers
 * n'est réalisée. Les méthodes ci-dessous manipulent des chaînes de caractères
 * et ne servent qu'à l'affichage. Le chemin d'exploitation de la CVE —
 * construire un chemin à partir d'une entrée puis y accéder — n'existe pas dans
 * ce projet.</p>
 */
public final class ReferentielFichiers {

    private ReferentielFichiers() { }

    /** Extension d'un nom de dépôt, en minuscules, chaîne vide si absente. */
    public static String extension(String nomFichier) {
        if (nomFichier == null) {
            return "";
        }
        return FilenameUtils.getExtension(nomFichier).toLowerCase(java.util.Locale.ROOT);
    }

    /** Nom de base, sans chemin ni extension. */
    public static String nomDeBase(String nomFichier) {
        if (nomFichier == null) {
            return "";
        }
        return FilenameUtils.getBaseName(nomFichier);
    }

    /** Vrai si le nom correspond à un export de contrats attendu. */
    public static boolean estExportContrats(String nomFichier) {
        String extension = extension(nomFichier);
        return "csv".equals(extension) || "xml".equals(extension);
    }
}
