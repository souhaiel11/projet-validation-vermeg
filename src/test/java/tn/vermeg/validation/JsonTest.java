package tn.vermeg.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Sérialisation JSON — le contrat de santé dépend de son exactitude. */
class JsonTest {

    @Test
    @DisplayName("Une table ordonnée conserve l'ordre d'insertion")
    void ordreConserve() {
        assertEquals("{\"a\":1,\"b\":2,\"c\":3}",
            Json.write(Json.ordered("a", 1, "b", 2, "c", 3)));
    }

    @Test
    @DisplayName("Un nombre impair d'arguments est refusé")
    void argumentsImpairs() {
        assertThrows(IllegalArgumentException.class, () -> Json.ordered("a"));
    }

    @Test
    @DisplayName("Les caractères spéciaux sont échappés")
    void echappement() {
        assertEquals("{\"k\":\"a\\\"b\\\\c\\nd\"}",
            Json.write(Json.ordered("k", "a\"b\\c\nd")));
    }

    @Test
    @DisplayName("null, booléens et listes sont rendus correctement")
    void typesDivers() {
        assertEquals("{\"n\":null,\"b\":true,\"l\":[1,2]}",
            Json.write(Json.ordered("n", null, "b", true, "l", List.of(1, 2))));
    }

    @Test
    @DisplayName("Un contrat est sérialisé avec ses cinq champs")
    void serialisationContrat() {
        Contrat c = new Contrat("CTR-0001", "Épargne", "Alpha", 1000, 2);
        String json = Json.write(Json.contrat(c));
        assertEquals("{\"id\":\"CTR-0001\",\"libelle\":\"Épargne\",\"souscripteur\":\"Alpha\","
                   + "\"primeAnnuelleCentimes\":1000,\"parts\":2}", json);
    }

    @Test
    @DisplayName("Un contrat sans identifiant est refusé à la construction")
    void contratInvalide() {
        assertThrows(IllegalArgumentException.class,
            () -> new Contrat("  ", "x", "y", 1, 1));
        assertThrows(IllegalArgumentException.class,
            () -> new Contrat("CTR-X", "x", "y", -1, 1));
    }
}
