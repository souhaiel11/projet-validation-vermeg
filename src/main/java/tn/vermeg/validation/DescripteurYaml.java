package tn.vermeg.validation;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Lecture du descripteur de déploiement YAML — scénario VAL-D04.
 *
 * <p>Emploie {@code snakeyaml 1.33}, qui porte la CVE-2022-1471
 * (désérialisation non maîtrisée). Cette CVE n'est corrigée qu'en version
 * <b>2.0</b>, donc dans une majeure supérieure : la politique de sélection de
 * la plateforme ne retient qu'une version corrigée de même majeure et doit donc
 * <b>refuser</b> la correction avec le motif {@code CROSS_MAJOR_ONLY}.</p>
 *
 * <p><b>Périmètre de sûreté :</b> l'analyseur est construit avec un
 * {@link SafeConstructor}, qui interdit l'instanciation de types arbitraires —
 * c'est-à-dire précisément le mécanisme de la CVE. Le document lu est une
 * ressource embarquée dans le jar, jamais un document fourni par un appelant.
 * La dépendance vulnérable est présente et réellement utilisée ; la
 * configuration employée ferme le chemin d'exploitation.</p>
 *
 * <p><b>Note pour la démonstration :</b> {@code new SafeConstructor()} sans
 * argument n'existe plus en snakeyaml 2.0, où le constructeur exige un
 * {@code LoaderOptions}. Une montée de version majeure casserait donc la
 * compilation de cette classe. C'est l'illustration concrète de la raison pour
 * laquelle la plateforme refuse de franchir une majeure sans intervention
 * humaine.</p>
 */
public final class DescripteurYaml {

    private static final Logger LOG = Logger.getLogger(DescripteurYaml.class.getName());
    private static final String RESSOURCE = "/descripteur-deploiement.yaml";

    private DescripteurYaml() { }

    /**
     * Lit le descripteur embarqué.
     *
     * @return la table des clés lues, ou une table vide si la ressource est
     *         absente ou illisible. L'échec est journalisé, jamais masqué
     *         derrière des valeurs par défaut inventées.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> lire() {
        try (InputStream flux = DescripteurYaml.class.getResourceAsStream(RESSOURCE)) {
            if (flux == null) {
                LOG.warning(() -> "Descripteur absent de l'archive : " + RESSOURCE);
                return Collections.emptyMap();
            }
            Yaml yaml = new Yaml(new SafeConstructor());
            Object charge = yaml.load(new java.io.InputStreamReader(flux, StandardCharsets.UTF_8));
            if (charge instanceof Map<?, ?> table) {
                return (Map<String, Object>) table;
            }
            return Collections.emptyMap();
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Descripteur de déploiement illisible", e);
            return Collections.emptyMap();
        }
    }

    /** Valeur de chaîne du descripteur, ou la valeur de repli fournie. */
    public static String texte(String cle, String repli) {
        Object valeur = lire().get(cle);
        return valeur == null ? repli : String.valueOf(valeur);
    }
}
