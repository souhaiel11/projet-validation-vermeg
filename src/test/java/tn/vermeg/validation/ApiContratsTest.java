package tn.vermeg.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Routage HTTP — exercé sans ouvrir de port. */
class ApiContratsTest {

    @Test
    @DisplayName("La collection de contrats est servie avec ses cinq éléments")
    void collectionComplete() {
        App.Reponse r = App.router("GET", "/api/contrats");
        assertEquals(200, r.statut());
        assertTrue(r.corps().contains("\"nombre\":5"), r.corps());
        assertTrue(r.corps().contains("CTR-0001"));
        assertTrue(r.corps().contains("CTR-0005"));
    }

    @Test
    @DisplayName("Un contrat existant est servi seul")
    void contratUnitaire() {
        App.Reponse r = App.router("GET", "/api/contrats/CTR-0003");
        assertEquals(200, r.statut());
        assertTrue(r.corps().contains("Retraite Collective"));
    }

    @Test
    @DisplayName("Un identifiant inconnu produit 404, jamais un objet vide")
    void contratInconnu() {
        App.Reponse r = App.router("GET", "/api/contrats/CTR-9999");
        assertEquals(404, r.statut());
        assertEquals("{\"error\":\"not_found\"}", r.corps());
    }

    @Test
    @DisplayName("Un identifiant vide est une requête mal formée, pas le premier contrat")
    void identifiantVide() {
        assertEquals(404, App.router("GET", "/api/contrats/").statut());
    }

    @Test
    @DisplayName("Un chemin imbriqué est refusé")
    void cheminImbrique() {
        assertEquals(404, App.router("GET", "/api/contrats/CTR-0001/parts").statut());
    }

    @Test
    @DisplayName("Un chemin inconnu produit 404")
    void cheminInconnu() {
        assertEquals(404, App.router("GET", "/api/inexistant").statut());
    }

    @Test
    @DisplayName("La page d'accueil est servie en HTML")
    void pageAccueil() {
        App.Reponse r = App.router("GET", "/");
        assertEquals(200, r.statut());
        assertEquals("text/html; charset=utf-8", r.typeContenu());
        assertTrue(r.corps().contains("<!doctype html>"));
    }

    @Test
    @DisplayName("Les informations exposent l'application et son avertissement")
    void informations() {
        App.Reponse r = App.router("GET", "/api/info");
        assertEquals(200, r.statut());
        assertTrue(r.corps().contains("projet-validation-vermeg"));
        assertTrue(r.corps().contains("VULNERABLE"));
    }
}
