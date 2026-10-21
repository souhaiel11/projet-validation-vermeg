package tn.vermeg.validation;

import org.jsoup.nodes.Entities;

/**
 * Échappement des libellés de contrat avant insertion dans la page HTML —
 * scénario VAL-D09.
 *
 * <p>Emploie {@code jsoup 1.14.3}, qui porte CVE-2022-36033 (contournement de
 * l'assainissement HTML), corrigée en 1.15.3 — même majeure, donc dans
 * l'enveloppe auto-corrigeable de la plateforme.</p>
 *
 * <p><b>Périmètre de sûreté :</b> seul l'échappement d'entités
 * ({@link Entities#escape}) est appelé. La CVE porte sur le contournement de
 * {@code Jsoup.clean()} avec une liste blanche — fonction que ce projet
 * n'appelle jamais. L'échappement d'entités, lui, neutralise les caractères
 * actifs sans tenter d'autoriser un sous-ensemble de balises.</p>
 */
public final class EtiquetteHtml {

    private EtiquetteHtml() { }

    /**
     * Libellé prêt à être inséré dans du contenu HTML.
     *
     * <p>{@code null} devient la chaîne vide : une étiquette absente ne doit
     * jamais produire le texte « null » dans une page.</p>
     */
    public static String echappe(String libelle) {
        if (libelle == null) {
            return "";
        }
        return Entities.escape(libelle);
    }

    /** Élément de liste HTML décrivant un contrat, libellé échappé. */
    public static String elementListe(Contrat contrat) {
        if (contrat == null) {
            throw new IllegalArgumentException("Contrat requis.");
        }
        return "<li>" + echappe(contrat.id()) + " — " + echappe(contrat.libelle()) + "</li>";
    }
}
