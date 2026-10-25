package tn.vermeg.validation;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Random;
import javax.crypto.Cipher;

/**
 * Porteur SUPPLÉMENTAIRE de défauts de code SonarQube — BANC D'ESSAI.
 *
 * <p>Cette classe élargit l'éventail de règles Sonar exercées par le projet,
 * pour montrer que la plateforme détecte et classe PLUSIEURS TYPES de constats
 * de code (secrets en dur, cryptographie faible, injection SQL, aléa non sûr,
 * mauvaises pratiques structurelles) en plus des dépendances vulnérables.
 *
 * <p>Chaque défaut porte un marqueur {@code VAL-Sxx}. Aucun de ces chemins
 * n'est appelé par l'application ni par les tests : ce sont des constats
 * d'analyse statique, pas des comportements exécutés. Ne pas corriger dans le
 * dépôt — la correction (ou la candidature assistée) est ce que la plateforme
 * doit produire d'elle-même.
 */
public class DefautsAnalyseCode {

  // VAL-S10 — java:S2068 : identifiant codé en dur.
  private static final String MOT_DE_PASSE = "Vermeg#Secret2026!";

  // VAL-S11 — java:S1313 : adresse IP codée en dur.
  private static final String HOTE_INTERNE = "10.42.17.3";

  // VAL-S12 — java:S1444 / java:S2386 : champ public statique mutable non final.
  public static String[] cacheEtiquettes = new String[16];

  // VAL-S13 — java:S1104 : champ d'instance public (encapsulation absente).
  public int compteurAcces;

  // VAL-S14 — java:S1068 : champ privé jamais lu.
  private final long horodatageInitial = System.currentTimeMillis();

  /**
   * VAL-S15 — java:S4790 : empreinte par MD5, algorithme de hachage faible.
   * VAL-S16 — java:S112 : lève une exception générique.
   */
  public byte[] empreinteFaible(String valeur) {
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      return md.digest(valeur.getBytes());
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * VAL-S17 — java:S5542 / java:S5547 : chiffrement par DES en mode ECB,
   * primitive et mode cryptographiquement faibles.
   */
  public Cipher chiffrementFaible() throws Exception {
    return Cipher.getInstance("DES/ECB/PKCS5Padding");
  }

  // VAL-S18 — java:S2245 : générateur pseudo-aléatoire non sûr pour un usage sensible.
  public String jetonSession() {
    Random alea = new Random();
    return Long.toHexString(alea.nextLong()) + MOT_DE_PASSE.hashCode();
  }

  /**
   * VAL-S19 — java:S3649 : requête SQL construite par concaténation d'une
   * entrée (injection SQL). Le chemin n'est jamais exécuté dans ce projet.
   *
   * <p>Le {@link Statement} est désormais libéré de façon déterministe :
   * il est marqué {@code closeOnCompletion()} afin d'être fermé avec le
   * {@link ResultSet} rendu à l'appelant, et fermé immédiatement si
   * l'exécution de la requête échoue.
   */
  public ResultSet rechercheContrat(Connection cx, String saisieUtilisateur) throws SQLException {
    String sql = "SELECT * FROM contrats WHERE libelle = '" + saisieUtilisateur + "'";
    Statement st = cx.createStatement();
    try {
      st.closeOnCompletion();
      return st.executeQuery(sql);
    } catch (SQLException e) {
      st.close();
      throw e;
    } catch (RuntimeException e) {
      st.close();
      throw e;
    }
  }

  /**
   * VAL-S20 — java:S3776 : complexité cognitive élevée (imbrications multiples).
   * VAL-S21 — java:S2589 : condition toujours vraie.
   */
  public String classer(int a, int b, int c, boolean actif) {
    String r = "";
    if (actif) {
      if (a > 0) {
        if (b > 0) {
          if (c > 0) {
            if (a > b) {
              if (b > c) {
                r = "decroissant";
              } else {
                r = "mixte";
              }
            } else if (a < b) {
              r = "croissant";
            }
          }
        }
      }
    }
    boolean toujoursVrai = (a == a);
    if (toujoursVrai) {
      r = r + "-ok";
    }
    return r;
  }

  /**
   * VAL-S22 — java:S1148 : pile d'appels imprimée directement.
   * VAL-S23 — java:S108 : bloc catch vide.
   * VAL-S24 — java:S106 : écriture directe sur la sortie standard.
   */
  public void traiter(String entree) {
    try {
      System.out.println("traitement de " + entree);
      Integer.parseInt(entree);
    } catch (NumberFormatException e) {
      e.printStackTrace();
    } catch (Exception ignore) {
    }
  }

  /**
   * VAL-S25 — java:S1698 : comparaison de chaînes avec «==» au lieu d'equals.
   * VAL-S26 — java:S1481 : variable locale jamais utilisée.
   * VAL-S27 — java:S1172 : paramètre jamais utilisé.
   */
  public boolean comparer(String gauche, String droite, String inutilise) {
    int tampon = gauche.length() + droite.length();
    return gauche == droite;
  }

  // VAL-S28 — java:S1186 : méthode vide sans commentaire explicatif.
  public void reinitialiser() {
  }

  // VAL-S29 — java:S125 : bloc de code commenté laissé dans la source.
  public int total(int[] valeurs) {
    int somme = 0;
    for (int v : valeurs) {
      somme += v;
    }
    // int moyenne = somme / valeurs.length;
    // if (moyenne > 100) { envoyerAlerte(moyenne); }
    // return moyenne;
    return somme;
  }

  // VAL-S30 — java:S00100 : nom de méthode non conforme à la convention.
  public void Calcule_Le_Resultat() {
    compteurAcces++;
  }
}
