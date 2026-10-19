package tn.vermeg.validation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Écriture JSON minimale, sans dépendance.
 *
 * <p>Choix délibéré : ajouter Jackson ou Gson introduirait des vulnérabilités
 * qui n'appartiennent pas aux scénarios de validation. Les seules dépendances
 * déclarées sont celles qui portent un scénario documenté dans
 * {@code docs/MATRICE_VALIDATION.md}.</p>
 */
public final class Json {

    private Json() { }

    /** Construit une table ordonnée à partir de couples clé / valeur. */
    public static Map<String, Object> ordered(Object... couples) {
        if (couples.length % 2 != 0) {
            throw new IllegalArgumentException("Nombre impair d'arguments : " + couples.length);
        }
        Map<String, Object> table = new LinkedHashMap<>();
        for (int i = 0; i < couples.length; i += 2) {
            table.put(String.valueOf(couples[i]), couples[i + 1]);
        }
        return table;
    }

    public static Map<String, Object> contrat(Contrat c) {
        return ordered(
            "id", c.id(),
            "libelle", c.libelle(),
            "souscripteur", c.souscripteur(),
            "primeAnnuelleCentimes", c.primeAnnuelleCentimes(),
            "parts", c.parts());
    }

    public static String write(Object valeur) {
        StringBuilder sb = new StringBuilder();
        ecrire(sb, valeur);
        return sb.toString();
    }

    private static void ecrire(StringBuilder sb, Object valeur) {
        if (valeur == null) {
            sb.append("null");
        } else if (valeur instanceof String s) {
            echapper(sb, s);
        } else if (valeur instanceof Number || valeur instanceof Boolean) {
            sb.append(valeur);
        } else if (valeur instanceof Map<?, ?> table) {
            sb.append('{');
            boolean premier = true;
            for (Map.Entry<?, ?> e : table.entrySet()) {
                if (!premier) sb.append(',');
                echapper(sb, String.valueOf(e.getKey()));
                sb.append(':');
                ecrire(sb, e.getValue());
                premier = false;
            }
            sb.append('}');
        } else if (valeur instanceof List<?> liste) {
            sb.append('[');
            for (int i = 0; i < liste.size(); i++) {
                if (i > 0) sb.append(',');
                ecrire(sb, liste.get(i));
            }
            sb.append(']');
        } else {
            echapper(sb, String.valueOf(valeur));
        }
    }

    /** Échappement conforme RFC 8259 pour les caractères que nous produisons. */
    private static void echapper(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    /** Liste mutable, utilisée par les appelants qui construisent une réponse. */
    public static <T> List<T> liste() {
        return new ArrayList<>();
    }
}
