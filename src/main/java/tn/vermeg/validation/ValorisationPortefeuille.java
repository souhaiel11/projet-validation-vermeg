package tn.vermeg.validation;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.OptionalLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Valorisation du portefeuille par agrégation SQL — scénario VAL-D01 (H2).
 *
 * <p><b>Périmètre de sûreté, intentionnel et vérifiable :</b></p>
 * <ul>
 *   <li>base strictement en mémoire, jamais persistée sur disque ;</li>
 *   <li>URL JDBC constante, jamais fournie par l'appelant ;</li>
 *   <li>console H2 jamais démarrée ;</li>
 *   <li>requêtes préparées uniquement, aucun SQL concaténé depuis une entrée ;</li>
 *   <li>connexion ouverte puis refermée dans la même méthode.</li>
 * </ul>
 *
 * <p>La dépendance est donc réellement exercée — le scanner la voit dans l'image
 * et le code l'utilise — sans qu'aucun chemin exploitable n'existe.</p>
 */
public final class ValorisationPortefeuille {

    private static final Logger LOG = Logger.getLogger(ValorisationPortefeuille.class.getName());

    /** URL constante. Aucune partie n'est construite à partir d'une entrée. */
    private static final String URL_MEMOIRE =
        "jdbc:h2:mem:validation;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=TRUE";

    private static final String CREATION =
        "CREATE TABLE IF NOT EXISTS contrat ("
        + "id VARCHAR(16) PRIMARY KEY, "
        + "prime_centimes INT NOT NULL, "
        + "parts INT NOT NULL)";

    private static final String INSERTION =
        "INSERT INTO contrat (id, prime_centimes, parts) VALUES (?, ?, ?)";

    private static final String AGREGATION =
        "SELECT SUM(CAST(prime_centimes AS BIGINT) * parts) FROM contrat";

    private ValorisationPortefeuille() { }

    /**
     * Charge les contrats dans une table en mémoire puis renvoie l'agrégat.
     *
     * @return la valeur totale, ou {@link OptionalLong#empty()} si la base n'a
     *         pas pu être interrogée. Un échec n'est jamais présenté comme zéro.
     */
    public static OptionalLong valeurTotaleCentimes(List<Contrat> contrats) {
        try (Connection cx = DriverManager.getConnection(URL_MEMOIRE)) {
            try (Statement st = cx.createStatement()) {
                st.execute("DROP TABLE IF EXISTS contrat");
                st.execute(CREATION);
            }
            try (PreparedStatement ps = cx.prepareStatement(INSERTION)) {
                for (Contrat c : contrats) {
                    ps.setString(1, c.id());
                    ps.setInt(2, c.primeAnnuelleCentimes());
                    ps.setInt(3, c.parts());
                    ps.addBatch();
                }
                ps.executeBatch();
            }
            try (PreparedStatement ps = cx.prepareStatement(AGREGATION);
                 ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    long total = rs.getLong(1);
                    return rs.wasNull() ? OptionalLong.empty() : OptionalLong.of(total);
                }
                return OptionalLong.empty();
            }
        } catch (SQLException e) {
            // L'indisponibilité est journalisée et remontée telle quelle.
            // La transformer en 0 masquerait une panne derrière une valeur
            // d'apparence normale — exactement l'erreur que la plateforme
            // reproche aux chaînes qu'elle remplace.
            LOG.log(Level.WARNING, "Agrégation SQL indisponible", e);
            return OptionalLong.empty();
        }
    }
}
