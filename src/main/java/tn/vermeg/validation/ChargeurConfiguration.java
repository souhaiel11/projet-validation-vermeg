package tn.vermeg.validation;

import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.ex.ConfigurationException;

/**
 * Chargement de la configuration applicative — scénario VAL-D05.
 *
 * <p>Cette classe emploie {@code commons-configuration2 2.8.0}, qui entraîne
 * {@code commons-text 1.9} en dépendance <b>transitive</b>. C'est le vecteur par
 * lequel la CVE-2022-42889 (« Text4Shell ») entre dans le projet : la
 * plateforme doit la détecter, puis <b>refuser</b> de la corriger
 * automatiquement avec le motif {@code TRANSITIVE_NOT_AUTOFIXABLE_V1}.</p>
 *
 * <p><b>Périmètre de sûreté :</b> l'interpolation ne porte que sur des clés et
 * des valeurs définies ici, dans le code. Aucune valeur fournie par un appelant
 * n'est interpolée, et l'interpolateur étendu
 * ({@code StringSubstitutor.createInterpolator()}, porteur des recherches
 * {@code script:}, {@code dns:} et {@code url:}) n'est jamais invoqué. La
 * dépendance vulnérable est réellement présente et réellement utilisée ; le
 * chemin exploitable, lui, ne l'est pas.</p>
 */
public final class ChargeurConfiguration {

    private ChargeurConfiguration() { }

    /**
     * Construit la configuration d'exécution.
     *
     * <p>L'interpolation {@code ${...}} est exercée volontairement : c'est elle
     * qui met {@code commons-text} sur le chemin d'exécution réel, et non un
     * simple import décoratif.</p>
     */
    public static Map<String, String> configuration() throws ConfigurationException {
        PropertiesConfiguration conf = new PropertiesConfiguration();

        // Valeurs constantes, définies dans le code. Aucune entrée externe.
        conf.setProperty("application.nom", App.NOM_APPLICATION);
        conf.setProperty("application.version", App.VERSION_APPLICATION);
        conf.setProperty("application.environnement", "banc-essai");

        // Interpolation : commons-text résout ${application.nom} et
        // ${application.version}. C'est le seul usage de l'interpolateur.
        conf.setProperty("application.libelle",
            "${application.nom} v${application.version} (${application.environnement})");

        Map<String, String> resultat = new LinkedHashMap<>();
        conf.getKeys().forEachRemaining(cle -> resultat.put(cle, conf.getString(cle)));
        return resultat;
    }

    /** Libellé interpolé, utilisé par la route {@code /api/info}. */
    public static String libelle() {
        try {
            return configuration().getOrDefault("application.libelle", App.NOM_APPLICATION);
        } catch (ConfigurationException e) {
            return App.NOM_APPLICATION;
        }
    }
}
