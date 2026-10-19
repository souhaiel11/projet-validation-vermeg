package tn.vermeg.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Contrats de dépendances.
 *
 * <p>Chaque test exerce une dépendance porteuse d'un scénario de validation et
 * vérifie le <b>comportement</b> dont l'application dépend, pas son numéro de
 * version. C'est ce qui rend ces tests utiles à la chaîne de remédiation :</p>
 *
 * <ul>
 *   <li>ils <b>passent</b> après une montée de version légitime de même majeure
 *       (commons-lang3 3.12.0 → 3.18.0, commons-io 2.6 → 2.7, h2 2.1.212 →
 *       2.2.220), ce qui permet au candidat d'être accepté ;</li>
 *   <li>ils <b>échouent</b> si une montée de version altère le comportement
 *       attendu, ce qui fait rejeter le candidat avant toute écriture Git.</li>
 * </ul>
 *
 * <p>Un candidat qui casse l'un de ces tests ne doit jamais atteindre une Pull
 * Request : c'est le contrôle négatif NC-1 de la matrice de validation.</p>
 */
class ContratsDependancesTest {

    @Test
    @DisplayName("commons-lang3 — le remplissage à gauche reste stable sur 3.x")
    void contratCommonsLang3() {
        assertEquals("00000001", CatalogueContrats.referenceNormalisee("CTR-0001"));
        assertEquals("00000042", CatalogueContrats.referenceNormalisee("  ctr-42  "));
        assertEquals("00000000", CatalogueContrats.referenceNormalisee(null));
    }

    @Test
    @DisplayName("commons-lang3 — la recherche insensible à la casse reste stable")
    void contratRechercheInsensible() {
        assertTrue(CatalogueContrats.parId("ctr-0002").isPresent());
        assertTrue(CatalogueContrats.parId("  CTR-0002 ").isPresent());
        assertFalse(CatalogueContrats.parId("   ").isPresent());
        assertFalse(CatalogueContrats.parId(null).isPresent());
    }

    @Test
    @DisplayName("commons-io — l'extraction d'extension reste stable sur 2.x")
    void contratCommonsIo() {
        assertEquals("csv", ReferentielFichiers.extension("export-contrats.CSV"));
        assertEquals("", ReferentielFichiers.extension("export-contrats"));
        assertEquals("", ReferentielFichiers.extension(null));
        assertEquals("export-contrats", ReferentielFichiers.nomDeBase("/tmp/export-contrats.csv"));
    }

    @Test
    @DisplayName("commons-io — la reconnaissance d'un export reste stable")
    void contratReconnaissanceExport() {
        assertTrue(ReferentielFichiers.estExportContrats("lot.csv"));
        assertTrue(ReferentielFichiers.estExportContrats("lot.XML"));
        assertFalse(ReferentielFichiers.estExportContrats("lot.pdf"));
        assertFalse(ReferentielFichiers.estExportContrats(null));
    }

    @Test
    @DisplayName("commons-configuration2 — l'interpolation reste stable sur 2.x")
    void contratCommonsConfiguration() throws Exception {
        Map<String, String> conf = ChargeurConfiguration.configuration();
        assertEquals("projet-validation-vermeg", conf.get("application.nom"));
        assertEquals("banc-essai", conf.get("application.environnement"));
        // L'interpolation met commons-text sur le chemin d'exécution réel :
        // si elle cessait de fonctionner, la dépendance transitive ne serait
        // plus exercée et le scénario VAL-D05 perdrait son fondement.
        assertEquals("projet-validation-vermeg v1.0.0 (banc-essai)",
                     conf.get("application.libelle"));
    }

    @Test
    @DisplayName("snakeyaml — la lecture sûre du descripteur reste stable sur 1.x")
    void contratSnakeyaml() {
        Map<String, Object> descripteur = DescripteurYaml.lire();
        assertFalse(descripteur.isEmpty(), "Le descripteur embarqué doit être lisible");
        assertEquals("banc-essai", descripteur.get("environnement"));
        assertEquals("/health", descripteur.get("cheminSante"));
        assertEquals(8080, descripteur.get("portEcoute"));
        assertEquals("inconnu", DescripteurYaml.texte("cleAbsente", "inconnu"));
    }
}
