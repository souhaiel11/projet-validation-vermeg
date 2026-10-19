# projet-validation-vermeg

> ## ⚠ APPLICATION INTENTIONNELLEMENT VULNÉRABLE — BANC D'ESSAI UNIQUEMENT
> Données synthétiques. Aucun identifiant réel. Ne jamais exposer sur un réseau
> public, ne jamais déployer en production, ne pas réutiliser comme base d'une
> application réelle. Voir [`docs/PERIMETRE_DE_SURETE.md`](docs/PERIMETRE_DE_SURETE.md).

Projet de validation de la plateforme DevSecOps assistée par IA développée dans
le cadre du projet de fin d'études. Il n'a qu'une raison d'être : **exercer
chaque capacité de la plateforme, et surtout chacune de ses limites**, de façon
reproductible et démontrable devant un jury.

## Ce que le projet déclenche

| Famille | Nombre | Dont auto-corrigeables | Dont refus attendus |
|---|---|---|---|
| Dépendances (Trivy + OWASP) | 6 scénarios | **3** | **3** |
| Code source (SonarQube) | 6 constats | 0 — candidature assistée seulement | — |
| Application en fonctionnement (ZAP) | 4 constats | 0 — détection seule | — |
| Dockerfile (optimiseur WF5) | 10 défauts | proposition sous porte déterministe | — |
| Jenkinsfile (optimiseur WF4) | 3 défauts | proposition sous porte déterministe | — |
| Contrôles négatifs | 5 | — | **5** |

La matrice complète, scénario par scénario, avec le code de refus attendu pour
chacun : [`docs/MATRICE_VALIDATION.md`](docs/MATRICE_VALIDATION.md).

## Le scénario le plus instructif

`commons-text 1.9` porte la CVE-2022-42889 (« Text4Shell », CVSS 9.8). Un
correctif existe en **1.10.0**, dans la **même majeure** — donc *a priori* dans
l'enveloppe auto-corrigeable de la plateforme.

La plateforme refuse quand même, avec le motif
`TRANSITIVE_NOT_AUTOFIXABLE_V1`, parce que la dépendance n'est pas déclarée par
le projet : elle arrive par `commons-configuration2:2.8.0`.

Le refus porte sur la **provenance de la déclaration**, pas sur la disponibilité
d'un correctif. C'est la démonstration la plus nette de ce que la plateforme
vérifie réellement.

## Architecture

Application Java 17 / Maven, un seul `pom.xml` à la racine, **sans parent** et
**sans framework**. Ces trois choix ne sont pas des simplifications :

- un **parent** introduirait une gestion de version par BOM, c'est-à-dire
  exactement la provenance que la plateforme refuse d'auto-corriger ;
- un **module enfant** sortirait du périmètre de l'adaptateur de cible, qui
  n'ancre que le descripteur racine ;
- un **framework** apporterait ses propres vulnérabilités et brouillerait les
  scénarios : on ne saurait plus quel constat appartient à quelle démonstration.

Le serveur HTTP repose sur `com.sun.net.httpserver`, fourni par le JDK. Les cinq
dépendances déclarées portent chacune un scénario documenté.

```
src/main/java/tn/vermeg/validation/
   App.java                      serveur HTTP, routage, en-têtes absents (VAL-Z)
   Json.java                     sérialisation sans dépendance
   Contrat.java                  modèle
   CatalogueContrats.java        commons-lang3 (VAL-D02) + code commenté (VAL-S02)
   ValorisationPortefeuille.java h2, agrégation SQL en mémoire (VAL-D01)
   ChargeurConfiguration.java    commons-configuration2 → commons-text (VAL-D05)
   ReferentielFichiers.java      commons-io (VAL-D03)
   DescripteurYaml.java          snakeyaml (VAL-D04)
   SignatureHeritee.java         porteur des défauts Sonar (VAL-S01, S03 à S06)
```

## Construire et exécuter

```bash
mvn -B -ntp clean verify     # 35 tests, couverture JaCoCo ≈ 79 %
java -cp target/projet-validation-vermeg-1.0.0.jar:'target/runtime/*' \
     tn.vermeg.validation.App
```

Puis :

```bash
curl -s http://127.0.0.1:8080/health       # {"status":"UP"}
curl -s http://127.0.0.1:8080/api/info
curl -s http://127.0.0.1:8080/api/contrats
```

En conteneur, port publié sur la boucle locale uniquement :

```bash
docker compose up --build -d
curl -s http://127.0.0.1:8085/health
```

## Mise en service dans la plateforme

Voir [`docs/CONFIGURATION_PLATEFORME.md`](docs/CONFIGURATION_PLATEFORME.md) :
dépôt, job Jenkins, projet SonarQube, fiche projet, cible ZAP, préparation Azure,
et la liste de vérification du premier build.

## Démonstration

Le déroulé minuté, les phrases clés et les questions probables du jury avec leur
réponse : [`docs/RUNBOOK_JURY.md`](docs/RUNBOOK_JURY.md).

## État de référence

L'étiquette Git `baseline-vulnerable` marque l'état initial. Après une
démonstration ayant produit des Pull Requests :

```bash
git checkout main && git reset --hard baseline-vulnerable && git push --force-with-lease
```

## Les défauts ne doivent pas être corrigés dans le dépôt

Chaque défaut porte un marqueur `VAL-xxx` et une explication. Leur correction est
précisément ce que la plateforme doit produire d'elle-même : la corriger à la
main viderait la démonstration de son objet.
