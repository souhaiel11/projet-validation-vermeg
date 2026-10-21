package tn.vermeg.validation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;

/**
 * Inventaire d'une archive ZIP d'export du référentiel — scénario VAL-D07.
 *
 * <p>Emploie {@code commons-compress 1.21}, qui porte CVE-2024-25710 (boucle
 * infinie sur une archive tronquée) et CVE-2024-26308 (épuisement mémoire),
 * corrigées en 1.26.0 — même majeure, donc dans l'enveloppe auto-corrigeable
 * de la plateforme.</p>
 *
 * <p><b>Périmètre de sûreté :</b> aucune extraction sur disque. Les octets lus
 * proviennent d'un tableau fourni par le code appelant, jamais d'un flux
 * réseau ni d'un fichier désigné par un appelant HTTP, et seuls les noms
 * d'entrées sont retournés. Le chemin d'exploitation des deux CVE — faire
 * décompresser une archive hostile par le service — n'existe pas dans ce
 * projet.</p>
 */
public final class ArchiveReferentiel {

    /** Au-delà, l'inventaire est refusé : un export du référentiel reste petit. */
    private static final int MAX_ENTREES = 500;

    private ArchiveReferentiel() { }

    /**
     * Noms des entrées de l'archive, dans l'ordre de lecture, répertoires exclus.
     *
     * @throws IOException si les octets ne constituent pas une archive lisible
     */
    public static List<String> inventaire(byte[] octets) throws IOException {
        if (octets == null || octets.length == 0) {
            return List.of();
        }
        List<String> noms = new ArrayList<>();
        try (ZipArchiveInputStream flux =
                 new ZipArchiveInputStream(new ByteArrayInputStream(octets))) {
            ZipArchiveEntry entree;
            while ((entree = flux.getNextZipEntry()) != null) {
                if (entree.isDirectory()) {
                    continue;
                }
                if (noms.size() >= MAX_ENTREES) {
                    throw new IOException("Archive refusée : plus de " + MAX_ENTREES + " entrées.");
                }
                noms.add(entree.getName());
            }
        }
        return List.copyOf(noms);
    }

    /** Vrai si l'archive ne contient que des exports de contrats reconnus. */
    public static boolean contientUniquementDesExports(byte[] octets) throws IOException {
        List<String> noms = inventaire(octets);
        if (noms.isEmpty()) {
            return false;
        }
        return noms.stream().allMatch(ReferentielFichiers::estExportContrats);
    }
}
