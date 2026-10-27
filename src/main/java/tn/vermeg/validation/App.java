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
        List<Contrat> contrats = CatalogueContrats.tous();
        long valeurTotale = CatalogueContrats.valeurTotaleCentimes();
        int partsTotales = contrats.stream().mapToInt(Contrat::parts).sum();
        StringBuilder lignes = new StringBuilder();
        for (Contrat c : contrats) {
            lignes.append("<tr><td class=\"id\">").append(EtiquetteHtml.echappe(c.id()))
                .append("</td><td>").append(EtiquetteHtml.echappe(c.libelle()))
                .append("</td><td>").append(EtiquetteHtml.echappe(c.souscripteur()))
                .append("</td><td class=\"num\">").append(montant(c.primeAnnuelleCentimes()))
                .append("</td><td class=\"num\">").append(c.parts())
                .append("</td><td class=\"num fort\">").append(montant(c.valeurTotaleCentimes()))
                .append("</td></tr>");
        }
        return PAGE_ACCUEIL
            .replace("{{VERSION}}", EtiquetteHtml.echappe(VERSION_APPLICATION))
            .replace("{{ENVIRONNEMENT}}", EtiquetteHtml.echappe(DescripteurYaml.texte("environnement", "banc-essai")))
            .replace("{{NOMBRE}}", String.valueOf(contrats.size()))
            .replace("{{VALEUR}}", montant(valeurTotale))
            .replace("{{PARTS}}", String.valueOf(partsTotales))
            .replace("{{LIGNES}}", lignes.toString());
    }

    /** Montant en centimes affiché « 12 345,67 » (séparateur de milliers : espace insécable). */
    static String montant(long centimes) {
        String entier = String.format(java.util.Locale.ROOT, "%,d", centimes / 100).replace(',', '\u00a0');
        return entier + "," + String.format(java.util.Locale.ROOT, "%02d", Math.abs(centimes % 100));
    }

    private static final String PAGE_ACCUEIL = """
        <!doctype html>
        <html lang="fr">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Projet de validation VERMEG — Portefeuille de contrats</title>
        <style>
          :root{--bleu:#0b2e59;--bleu2:#14549b;--accent:#e4002b;--fond:#f4f6fa;--carte:#fff;--texte:#1d2633;--doux:#5c6b7f;--bord:#dfe4ec;--vert:#1f8a4c}
          *{box-sizing:border-box}body{margin:0;font-family:"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--fond);color:var(--texte)}
          header{background:linear-gradient(120deg,var(--bleu),var(--bleu2));color:#fff;padding:28px 6vw 70px}
          .marque{display:flex;align-items:center;gap:14px;font-weight:700;letter-spacing:.14em;font-size:15px}
          .logo{width:38px;height:38px;border-radius:9px;background:#fff;color:var(--bleu);display:grid;place-items:center;font-size:20px;font-weight:800;letter-spacing:0}
          h1{margin:26px 0 8px;font-size:clamp(24px,3.4vw,36px);font-weight:600}
          .sous{margin:0;opacity:.85;font-size:15px;max-width:720px}
          .pastilles{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}
          .pastille{background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.28);border-radius:999px;padding:5px 13px;font-size:13px}
          .pastille.ok::before{content:"";display:inline-block;width:8px;height:8px;border-radius:50%;background:#4ade80;margin-right:7px}
          main{padding:0 6vw 40px;margin-top:-44px}
          .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
          .kpi{background:var(--carte);border-radius:12px;padding:20px 22px;box-shadow:0 6px 20px rgba(11,46,89,.08);border-top:4px solid var(--bleu2)}
          .kpi:nth-child(2){border-top-color:var(--accent)}.kpi:nth-child(3){border-top-color:var(--vert)}
          .kpi .lib{color:var(--doux);font-size:13px;text-transform:uppercase;letter-spacing:.06em}
          .kpi .val{font-size:28px;font-weight:700;margin-top:6px}
          section{background:var(--carte);border-radius:12px;box-shadow:0 6px 20px rgba(11,46,89,.06);margin-top:22px;padding:22px 24px}
          h2{margin:0 0 14px;font-size:18px;color:var(--bleu)}
          .table{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:14px}
          th{text-align:left;color:var(--doux);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em;padding:10px 12px;border-bottom:2px solid var(--bord)}
          td{padding:12px;border-bottom:1px solid var(--bord)}tr:hover td{background:#f8fafd}
          .num{text-align:right;font-variant-numeric:tabular-nums}.fort{font-weight:700;color:var(--bleu)}.id{font-family:Consolas,monospace;color:var(--bleu2)}
          .api{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
          .api a{display:block;border:1px solid var(--bord);border-radius:10px;padding:14px 16px;text-decoration:none;color:var(--texte)}
          .api a:hover{border-color:var(--bleu2);box-shadow:0 4px 14px rgba(20,84,155,.12)}
          .api code{color:var(--bleu2);font-weight:600}.api span{display:block;color:var(--doux);font-size:13px;margin-top:4px}
          .chaine{display:flex;flex-wrap:wrap;align-items:center;gap:8px;font-size:14px}
          .etape{background:#eef3fa;color:var(--bleu);border-radius:8px;padding:7px 12px;font-weight:600}.fleche{color:var(--doux)}
          footer{padding:18px 6vw 30px;color:var(--doux);font-size:12.5px}
          .avert{display:inline-block;margin-top:6px;color:var(--accent);font-weight:600}
        </style>
        </head>
        <body>
        <header>
          <div class="marque"><div class="logo">V</div>VERMEG · PROJET DE VALIDATION</div>
          <h1>Portefeuille de contrats d'assurance</h1>
          <p class="sous">Application de démonstration construite, analysée et déployée automatiquement par la plateforme DevSecOps.</p>
          <div class="pastilles">
            <span class="pastille ok">Service opérationnel</span>
            <span class="pastille">Version {{VERSION}}</span>
            <span class="pastille">Environnement : {{ENVIRONNEMENT}}</span>
            <span class="pastille">Azure Container Instances</span>
          </div>
        </header>
        <main>
          <div class="kpis">
            <div class="kpi"><div class="lib">Contrats</div><div class="val">{{NOMBRE}}</div></div>
            <div class="kpi"><div class="lib">Valeur du portefeuille</div><div class="val">{{VALEUR}}</div></div>
            <div class="kpi"><div class="lib">Parts détenues</div><div class="val">{{PARTS}}</div></div>
          </div>
          <section>
            <h2>Contrats en portefeuille</h2>
            <div class="table"><table>
              <thead><tr><th>Référence</th><th>Produit</th><th>Souscripteur</th><th class="num">Prime annuelle</th><th class="num">Parts</th><th class="num">Valeur</th></tr></thead>
              <tbody>{{LIGNES}}</tbody>
            </table></div>
          </section>
          <section>
            <h2>Points d'accès de l'API</h2>
            <div class="api">
              <a href="/health"><code>/health</code><span>Contrat de santé utilisé par le déploiement</span></a>
              <a href="/api/info"><code>/api/info</code><span>Version et environnement de l'application</span></a>
              <a href="/api/contrats"><code>/api/contrats</code><span>Portefeuille complet au format JSON</span></a>
              <a href="/api/contrats/CTR-0001"><code>/api/contrats/CTR-0001</code><span>Détail d'un contrat</span></a>
            </div>
          </section>
          <section>
            <h2>Chaîne de livraison</h2>
            <div class="chaine">
              <span class="etape">GitHub</span><span class="fleche">→</span><span class="etape">Jenkins</span><span class="fleche">→</span>
              <span class="etape">SonarQube · Trivy · OWASP · ZAP</span><span class="fleche">→</span><span class="etape">Azure Container Registry</span>
              <span class="fleche">→</span><span class="etape">Azure Container Instances</span>
            </div>
          </section>
        </main>
        <footer>
          Données synthétiques en mémoire — aucune donnée réelle.<br>
          <span class="avert">Application intentionnellement vulnérable — banc d'essai uniquement.</span>
        </footer>
        </body>
        </html>
        """;

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
