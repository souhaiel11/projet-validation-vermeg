package tn.vermeg.validation;

import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import org.apache.commons.lang3.StringUtils;

/**
 * Catalogue de contrats en mémoire — données synthétiques.
 *
 * <p>Emploie {@code commons-lang3} (scénario VAL-D02, provenance
 * PROPERTY_MANAGED) : la dépendance est réellement sur le chemin d'exécution,
 * elle n'est pas déclarée pour la seule satisfaction du scanner.</p>
 */
public final class CatalogueContrats {

    private static final List<Contrat> CONTRATS = List.of(
        new Contrat("CTR-0001", "Épargne Horizon",      "Societe Alpha",   120_000,  12),
        new Contrat("CTR-0002", "Prévoyance Sérénité",  "Societe Beta",     84_500,   7),
        new Contrat("CTR-0003", "Retraite Collective",  "Societe Gamma",   256_000,  31),
        new Contrat("CTR-0004", "Santé Entreprise",     "Societe Delta",    47_250,   4),
        new Contrat("CTR-0005", "Capitalisation Plus",  "Societe Epsilon", 310_750,  19));

    private CatalogueContrats() { }

    public static List<Contrat> tous() {
        return CONTRATS;
    }

    /**
     * Recherche par identifiant, insensible à la casse et aux espaces de bord.
     * {@code commons-lang3} porte la normalisation : {@link StringUtils#trimToEmpty}
     * traite le cas {@code null} sans branche supplémentaire.
     */
    public static Optional<Contrat> parId(String id) {
        String recherche = StringUtils.trimToEmpty(id);
        if (StringUtils.isBlank(recherche)) {
            return Optional.empty();
        }
        return CONTRATS.stream()
            .filter(c -> StringUtils.equalsIgnoreCase(c.id(), recherche))
            .findFirst();
    }

    /** Référence de contrat normalisée sur huit positions, remplie à gauche par des zéros. */
    public static String referenceNormalisee(String id) {
        String chiffres = StringUtils.getDigits(StringUtils.trimToEmpty(id));
        return StringUtils.leftPad(chiffres, 8, '0');
    }

    /** Valeur totale du portefeuille, calculée en mémoire. */
    public static long valeurTotaleCentimes() {
        return CONTRATS.stream().mapToLong(Contrat::valeurTotaleCentimes).sum();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DÉFAUT DÉLIBÉRÉ VAL-S02 — java:S125 « Sections of code should not be
    // commented out » (MAJOR, code smell).
    //
    // Ce bloc est du code mis en commentaire, pas une explication. C'est
    // exactement le motif que la règle S125 détecte, et c'est l'une des deux
    // cibles que le parcours de correction assistée (WF2) sait matérialiser.
    // Ne pas supprimer : la suppression est précisément ce que la plateforme
    // doit proposer d'elle-même.
    // Voir docs/MATRICE_VALIDATION.md, ligne VAL-S02.
    // ─────────────────────────────────────────────────────────────────────────
    // public static long valeurTotaleAvecMajoration(double taux) {
    //     long base = valeurTotaleCentimes();
    //     long majoration = Math.round(base * taux);
    //     return base + majoration;
    // }
    //
    // public static List<Contrat> parSouscripteur(String souscripteur) {
    //     return CONTRATS.stream()
    //         .filter(c -> c.souscripteur().equalsIgnoreCase(souscripteur))
    //         .toList();
    // }

    /**
     * Valeur totale recalculée par agrégation SQL (scénario VAL-D01, H2).
     * {@link OptionalLong#empty()} signifie « indisponible », jamais « zéro » :
     * la distinction est celle que la plateforme impose à ses propres scanners.
     */
    public static OptionalLong valeurTotaleCentimesDepuisBase() {
        return ValorisationPortefeuille.valeurTotaleCentimes(CONTRATS);
    }
}
