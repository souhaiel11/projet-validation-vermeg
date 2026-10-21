package tn.vermeg.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Contrats de comportement des trois scénarios auto-corrigeables ajoutés
 * (VAL-D07 commons-compress, VAL-D08 bcprov, VAL-D09 jsoup).
 *
 * <p>Ces tests vérifient le <b>comportement dont l'application dépend</b>, pas
 * les numéros de version : ils passent après une montée de version légitime de
 * même majeure, et échouent si le comportement change. C'est ce qui permet au
 * vérificateur de candidats de prouver qu'une correction automatique est sûre,
 * et c'est aussi le levier du contrôle négatif NC-1.</p>
 */
class ScenariosAutoCorrigeablesTest {

    private static Contrat contrat() {
        return new Contrat("CT-0001", "Épargne Sérénité", "Dupont", 120_000, 3);
    }

    /** Construit en mémoire une archive ZIP contenant les entrées demandées. */
    private static byte[] archive(String... noms) throws IOException {
        ByteArrayOutputStream tampon = new ByteArrayOutputStream();
        try (ZipArchiveOutputStream zip = new ZipArchiveOutputStream(tampon)) {
            for (String nom : noms) {
                ZipArchiveEntry entree = new ZipArchiveEntry(nom);
                byte[] contenu = ("contenu de " + nom).getBytes(StandardCharsets.UTF_8);
                entree.setSize(contenu.length);
                zip.putArchiveEntry(entree);
                zip.write(contenu);
                zip.closeArchiveEntry();
            }
        }
        return tampon.toByteArray();
    }

    // ── VAL-D07 — commons-compress ──────────────────────────────────────────

    @Test
    @DisplayName("VAL-D07 : l'inventaire restitue les entrées de l'archive, dans l'ordre")
    void inventaireRestitueLesEntrees() throws IOException {
        byte[] octets = archive("contrats.csv", "contrats.xml");
        assertEquals(List.of("contrats.csv", "contrats.xml"),
            ArchiveReferentiel.inventaire(octets));
    }

    @Test
    @DisplayName("VAL-D07 : une archive absente ou vide donne un inventaire vide, sans exception")
    void archiveVideDonneInventaireVide() throws IOException {
        assertEquals(List.of(), ArchiveReferentiel.inventaire(null));
        assertEquals(List.of(), ArchiveReferentiel.inventaire(new byte[0]));
    }

    @Test
    @DisplayName("VAL-D07 : une archive d'exports reconnus est acceptée, une autre est refusée")
    void seulsLesExportsReconnusSontAcceptes() throws IOException {
        assertTrue(ArchiveReferentiel.contientUniquementDesExports(archive("contrats.csv")));
        assertFalse(ArchiveReferentiel.contientUniquementDesExports(archive("contrats.csv", "notes.txt")));
    }

    // ── VAL-D08 — bcprov ────────────────────────────────────────────────────

    @Test
    @DisplayName("VAL-D08 : l'empreinte SHA-256 est la valeur de référence connue")
    void empreinteConnue() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            EmpreinteContrat.sha256Hex(""));
        assertEquals("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            EmpreinteContrat.sha256Hex("hello"));
    }

    @Test
    @DisplayName("VAL-D08 : l'empreinte est stable pour un même contrat et distingue deux contrats")
    void empreinteStableEtDiscriminante() {
        assertEquals(EmpreinteContrat.empreinte(contrat()), EmpreinteContrat.empreinte(contrat()));
        Contrat autre = new Contrat("CT-0002", "Épargne Sérénité", "Dupont", 120_000, 3);
        assertNotEquals(EmpreinteContrat.empreinte(contrat()), EmpreinteContrat.empreinte(autre));
    }

    @Test
    @DisplayName("VAL-D08 : un contrat absent est refusé, jamais haché comme une chaîne vide")
    void contratAbsentRefuse() {
        assertThrows(IllegalArgumentException.class, () -> EmpreinteContrat.empreinte(null));
    }

    // ── VAL-D09 — jsoup ─────────────────────────────────────────────────────

    @Test
    @DisplayName("VAL-D09 : les caractères actifs d'un libellé sont neutralisés")
    void caracteresActifsNeutralises() {
        String echappe = EtiquetteHtml.echappe("<script>alert(1)</script>");
        assertFalse(echappe.contains("<script>"));
        assertFalse(echappe.contains("</script>"));
        assertTrue(echappe.contains("&lt;"));
    }

    @Test
    @DisplayName("VAL-D09 : un libellé absent devient une chaîne vide, jamais le texte « null »")
    void libelleAbsentDevientChaineVide() {
        assertEquals("", EtiquetteHtml.echappe(null));
    }

    @Test
    @DisplayName("VAL-D09 : l'élément de liste porte l'identifiant et le libellé échappés")
    void elementListeEchappeLesDeuxChamps() {
        Contrat injecte = new Contrat("CT-0003", "Plan <b>Dynamique</b>", "Martin", 90_000, 2);
        String element = EtiquetteHtml.elementListe(injecte);
        assertTrue(element.startsWith("<li>"));
        assertTrue(element.endsWith("</li>"));
        assertTrue(element.contains("CT-0003"));
        assertFalse(element.contains("<b>"));
    }
}
