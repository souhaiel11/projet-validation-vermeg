package tn.vermeg.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.OptionalLong;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Agrégation SQL en mémoire — scénario VAL-D01 (h2). */
class ValorisationPortefeuilleTest {

    @Test
    @DisplayName("L'agrégat SQL retrouve la somme calculée en mémoire")
    void agregatConcordeAvecLeCalculEnMemoire() {
        OptionalLong sql = CatalogueContrats.valeurTotaleCentimesDepuisBase();
        assertTrue(sql.isPresent(), "L'agrégation SQL doit aboutir sur le banc d'essai");
        assertEquals(CatalogueContrats.valeurTotaleCentimes(), sql.getAsLong());
    }

    @Test
    @DisplayName("Un portefeuille vide produit « indisponible », jamais zéro")
    void portefeuilleVide() {
        // SUM() sur une table vide renvoie NULL en SQL. Le code doit le
        // traduire en « indisponible » et non en 0 : c'est la même exigence
        // que celle imposée aux scanners de la plateforme.
        assertEquals(OptionalLong.empty(),
                     ValorisationPortefeuille.valeurTotaleCentimes(List.of()));
    }

    @Test
    @DisplayName("L'agrégat suit le contenu fourni")
    void agregatSurSousEnsemble() {
        List<Contrat> deux = List.of(
            new Contrat("CTR-A", "A", "Alpha", 1_000, 2),
            new Contrat("CTR-B", "B", "Beta",  2_000, 3));
        OptionalLong sql = ValorisationPortefeuille.valeurTotaleCentimes(deux);
        assertTrue(sql.isPresent());
        assertEquals(8_000L, sql.getAsLong());
    }

    @Test
    @DisplayName("La valeur d'un contrat est le produit prime × parts")
    void valeurUnitaire() {
        assertEquals(1_440_000L, new Contrat("X", "X", "X", 120_000, 12).valeurTotaleCentimes());
    }
}
