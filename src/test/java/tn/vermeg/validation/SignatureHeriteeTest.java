package tn.vermeg.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Couverture de la classe porteuse des défauts Sonar.
 *
 * <p>Ces tests ne valident pas de bonnes pratiques : ils documentent le
 * comportement actuel d'un code volontairement défectueux, afin que la classe
 * soit couverte et que SonarQube l'analyse plutôt que de la ranger en code mort.
 * La correction des défauts est attendue de la plateforme, pas du dépôt.</p>
 */
class SignatureHeriteeTest {

    @Test
    @DisplayName("L'empreinte MD5 est stable pour une même entrée")
    void empreinteStable() {
        String a = SignatureHeritee.empreinteArchive("export-contrats");
        String b = SignatureHeritee.empreinteArchive("export-contrats");
        assertEquals(a, b);
        assertEquals(32, a.length(), "MD5 produit 32 caractères hexadécimaux");
    }

    @Test
    @DisplayName("Deux entrées différentes produisent deux empreintes différentes")
    void empreinteDiscriminante() {
        assertFalse(SignatureHeritee.empreinteArchive("lot-1")
            .equals(SignatureHeritee.empreinteArchive("lot-2")));
    }

    @Test
    @DisplayName("Le numéro de lot tient sur six chiffres")
    void numeroDeLotBorne() {
        for (int i = 0; i < 50; i++) {
            int n = SignatureHeritee.numeroDeLot();
            assertTrue(n >= 100_000 && n < 1_000_000, "Hors bornes : " + n);
        }
    }

    @Test
    @DisplayName("Le nom d'export suit le suffixe fourni")
    void nomExport() {
        assertEquals("export-contrats", SignatureHeritee.nomExport(null));
        assertEquals("export-contrats", SignatureHeritee.nomExport("  "));
        assertEquals("export-contrats.csv", SignatureHeritee.nomExport("csv"));
        assertEquals("export-contrats.xml", SignatureHeritee.nomExport("xml"));
    }

    @Test
    @DisplayName("La constante héritée ne correspond à aucune autre valeur")
    void secretHerite() {
        assertFalse(SignatureHeritee.correspondAuSecretHerite("autre-chose"));
        assertFalse(SignatureHeritee.correspondAuSecretHerite(null));
    }
}
