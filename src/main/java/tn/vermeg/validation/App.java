package tn.vermeg.validation;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.logging.Logger;

/**
 * PROJET DE VALIDATION VERMEG — application intentionnellement vulnérable.
 * BANC D'ESSAI UNIQUEMENT. Ne jamais exposer sur un réseau public.
 *
 * <p>Serveur HTTP bâti sur {@code com.sun.net.httpserver}, fourni par le JDK :
 * aucune dépendance de framework. Ce choix est délibéré — les seules
 * dépendances déclarées sont celles qui portent un scénario de validation, de
 * sorte qu'un scan ne mélange jamais les vulnérabilités de démonstration avec
 * celles d'un framework.</p>
 *
 * <p><b>Périmètre de sûreté global :</b> aucune exécution de code fournie par
 * l'appelant, aucun accès au système de fichiers, aucun appel réseau sortant,
 * aucun identifiant réel, données synthétiques uniquement. Seules les méthodes
 * GET et HEAD sont acceptées.</p>
 */
public final class App {

    public static final String AVERTISSEMENT =
        "PROJET DE VALIDATION INTENTIONNELLEMENT VULNERABLE — BANC D'ESSAI UNIQUEMENT";
    public static final String NOM_APPLICATION = "projet-validation-vermeg";
    public static final String VERSION_APPLICATION = "1.0.0";

    private static final String TYPE_JSON = "application/json; charset=utf-8";
    private static final String TYPE_HTML = "text/html; charset=utf-8";

    private static final String ERREUR_INTROUVABLE = "not_found";
    private static final String ERREUR_METHODE = "method_not_allowed";

    private static final Logger LOG = Logger.getLogger(App.class.getName());

    private App() { }

    // ── Réponses, construites séparément du transport pour rester testables ──

    /**
     * Contrat de santé. Déterministe à l'octet : aucun horodatage, aucune durée
     * de fonctionnement, aucun champ variable. La validation de déploiement
     * compare un corps attendu, elle ne peut pas comparer une valeur qui change.
     */
    public static String sante() {
        return Json.write(Json.ordered("status", "UP"));
    }

    public static String informations() {
        return Json.write(Json.ordered(
            "application", NOM_APPLICATION,
            "version", VERSION_APPLICATION,
            "libelle", ChargeurConfiguration.libelle(),
            "environnement", DescripteurYaml.texte("environnement", "banc-essai"),
            "avertissement", AVERTISSEMENT,
            "sourceDonnees", "synthetique-en-memoire"));
    }

    public static String contrats() {
        List<Map<String, Object>> elements = CatalogueContrats.tous().stream()
            .map(Json::contrat).toList();
        // Deux sources pour la même grandeur, nommées séparément : le calcul en
        // mémoire est toujours disponible ; l'agrégat SQL peut être absent, et
        // l'est alors explicitement — jamais remplacé en silence par un zéro.
        OptionalLong sql = CatalogueContrats.valeurTotaleCentimesDepuisBase();
        return Json.write(Json.ordered(
            "nombre", elements.size(),
            "valeurTotaleCentimes", CatalogueContrats.valeurTotaleCentimes(),
            "valeurTotaleCentimesSql", sql.isPresent() ? sql.getAsLong() : null,
            "numeroDeLot", SignatureHeritee.numeroDeLot(),
            "elements", elements));
    }

    /** {@code Optional.empty()} signifie « inconnu » : l'appelant répond 404. */
    public static Optional<String> contrat(String id) {
        return CatalogueContrats.parId(id).map(c -> Json.write(Json.contrat(c)));
    }

    public static String erreur(String code) {
        return Json.write(Json.ordered("error", code));
    }

    /**
     * Page d'accueil HTML.
     *
     * <p>DÉFAUT DÉLIBÉRÉ VAL-Z01 à VAL-Z03 — cette page est servie <b>sans
     * en-tête de sécurité</b> : ni {@code Content-Security-Policy}, ni
     * {@code X-Frame-Options}, ni {@code X-Content-Type-Options}. C'est ce que
     * l'analyse dynamique (OWASP ZAP) doit relever. Ces constats sont, pour la
     * plateforme, en <b>détection seule</b> : aucune stratégie de remédiation
     * de configuration web n'est qualifiée dans la chaîne.</p>
     */
    public static String accueil() {
        return """
            <!doctype html>
            <html lang="fr">
            <head><meta charset="utf-8"><title>Projet de validation VERMEG</title></head>
            <body>
              <h1>Projet de validation VERMEG</h1>
              <p><strong>Application intentionnellement vulnerable — banc d'essai uniquement.</strong></p>
              <ul>
                <li><a href="/health">/health</a></li>
                <li><a href="/api/info">/api/info</a></li>
                <li><a href="/api/contrats">/api/contrats</a></li>
              </ul>
            </body>
            </html>
            """;
    }

    // ── Transport ───────────────────────────────────────────────────────────

    /** Résultat d'un routage : statut, type de contenu et corps. */
    public record Reponse(int statut, String typeContenu, String corps) { }

    /**
     * Routage pur, isolé du serveur HTTP pour que les tests exercent exactement
     * le même code que l'exécution réelle, sans ouvrir de port.
     */
    public static Reponse router(String methode, String chemin) {
        if (!"GET".equals(methode) && !"HEAD".equals(methode)) {
            return new Reponse(405, TYPE_JSON, erreur(ERREUR_METHODE));
        }
        if ("/".equals(chemin))              return new Reponse(200, TYPE_HTML, accueil());
        if ("/health".equals(chemin))        return new Reponse(200, TYPE_JSON, sante());
        if ("/api/info".equals(chemin))      return new Reponse(200, TYPE_JSON, informations());
        if ("/api/contrats".equals(chemin))  return new Reponse(200, TYPE_JSON, contrats());

        if (chemin.startsWith("/api/contrats/")) {
            String id = chemin.substring("/api/contrats/".length());
            // Un identifiant vide n'est pas « le premier contrat » : c'est une
            // requête mal formée, et on le dit.
            if (id.isBlank() || id.contains("/")) {
                return new Reponse(404, TYPE_JSON, erreur(ERREUR_INTROUVABLE));
            }
            return contrat(id)
                .map(corps -> new Reponse(200, TYPE_JSON, corps))
                .orElseGet(() -> new Reponse(404, TYPE_JSON, erreur(ERREUR_INTROUVABLE)));
        }
        return new Reponse(404, TYPE_JSON, erreur(ERREUR_INTROUVABLE));
    }

    public static HttpServer demarrer(String adresse, int port) throws IOException {
        // Boucle locale par défaut. 0.0.0.0 n'est accepté que dans un conteneur.
        if (!"127.0.0.1".equals(adresse) && !"0.0.0.0".equals(adresse)) {
            throw new IllegalArgumentException("Adresse de liaison non autorisée : " + adresse);
        }
        HttpServer serveur = HttpServer.create(new InetSocketAddress(adresse, port), 0);
        serveur.createContext("/", App::traiter);
        serveur.start();
        return serveur;
    }

    private static void traiter(HttpExchange echange) throws IOException {
        try {
            Reponse reponse = router(echange.getRequestMethod(),
                                     echange.getRequestURI().getPath());
            byte[] octets = reponse.corps().getBytes(StandardCharsets.UTF_8);
            echange.getResponseHeaders().set("Content-Type", reponse.typeContenu());
            // VAL-Z01..Z03 — aucun en-tête de sécurité n'est positionné ici.
            // Volontaire : c'est la matière du scénario DAST.
            if ("HEAD".equals(echange.getRequestMethod())) {
                echange.sendResponseHeaders(reponse.statut(), -1);
            } else {
                echange.sendResponseHeaders(reponse.statut(), octets.length);
                try (var sortie = echange.getResponseBody()) {
                    sortie.write(octets);
                }
            }
        } finally {
            echange.close();
        }
    }

    public static void main(String[] args) throws IOException {
        LOG.warning(() -> "AVERTISSEMENT — " + AVERTISSEMENT);
        String adresse = System.getProperty("app.bind", "127.0.0.1");
        int port = Integer.parseInt(System.getProperty("app.port", "8080"));
        HttpServer serveur = demarrer(adresse, port);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> serveur.stop(0)));
        LOG.info(() -> NOM_APPLICATION + " écoute sur " + adresse + ":" + port);
    }
}
