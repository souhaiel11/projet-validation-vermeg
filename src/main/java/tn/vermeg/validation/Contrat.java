package tn.vermeg.validation;

/**
 * Contrat d'assurance — données synthétiques.
 *
 * @param id                     identifiant stable du contrat
 * @param libelle                intitulé commercial
 * @param souscripteur           nom du souscripteur (synthétique)
 * @param primeAnnuelleCentimes  prime annuelle, en centimes, pour éviter le flottant
 * @param parts                  nombre de parts détenues
 */
public record Contrat(String id, String libelle, String souscripteur,
                      int primeAnnuelleCentimes, int parts) {

    public Contrat {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("Identifiant de contrat obligatoire");
        }
        if (primeAnnuelleCentimes < 0 || parts < 0) {
            throw new IllegalArgumentException("Montant ou nombre de parts négatif");
        }
    }

    /** Valeur totale portée par le contrat, en centimes. */
    public long valeurTotaleCentimes() {
        return (long) primeAnnuelleCentimes * parts;
    }
}
