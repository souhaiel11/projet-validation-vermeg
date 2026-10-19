package tn.vermeg.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Contrat de santé — la plateforme compare un corps attendu, octet pour octet.
 * Si ce test casse, la vérification de déploiement casse aussi.
 */
class ContratSanteTest {

    @Test
    @DisplayName("GET /health renvoie exactement {\"status\":\"UP\"}")
    void santeEstDeterministe() {
        assertEquals("{\"status\":\"UP\"}", App.sante());
    }

    @Test
    @DisplayName("Deux appels successifs produisent les mêmes octets")
    void santeNeVariePas() {
        assertEquals(App.sante(), App.sante());
    }

    @Test
    @DisplayName("La route /health est servie en JSON avec un statut 200")
    void routeSante() {
        App.Reponse r = App.router("GET", "/health");
        assertEquals(200, r.statut());
        assertEquals("application/json; charset=utf-8", r.typeContenu());
        assertEquals("{\"status\":\"UP\"}", r.corps());
    }

    @Test
    @DisplayName("HEAD est accepté comme GET sur le contrat de santé")
    void methodeHead() {
        assertEquals(200, App.router("HEAD", "/health").statut());
    }

    @Test
    @DisplayName("Une méthode d'écriture est refusée, pas ignorée")
    void methodeRefusee() {
        App.Reponse r = App.router("POST", "/health");
        assertEquals(405, r.statut());
        assertEquals("{\"error\":\"method_not_allowed\"}", r.corps());
    }

    @Test
    @DisplayName("L'avertissement reste présent dans l'application")
    void avertissementPresent() {
        assertSame(App.AVERTISSEMENT, App.AVERTISSEMENT);
        assertEquals(true, App.AVERTISSEMENT.contains("VULNERABLE"));
    }
}
