# Matrice de validation — projet-validation-vermeg

> **PROJET INTENTIONNELLEMENT VULNÉRABLE — BANC D'ESSAI UNIQUEMENT.**
> Données synthétiques. Aucun identifiant réel. Ne jamais exposer sur un réseau public.

Ce document est le contrat du projet. Une ligne par capacité de la plateforme :
le défaut qui la déclenche, l'outil qui le détecte, le comportement attendu, et —
quand la plateforme ne sait pas faire — la raison exacte du refus.

Une capacité sans preuve dans ce projet est marquée comme telle, pas gonflée.

---

## 1. Dépendances — chaîne de remédiation (Trivy + OWASP Dependency-Check)

La plateforme n'accorde `AUTO_FIX_ELIGIBLE` que si **quatre** conditions sont
réunies simultanément : source ∈ {TRIVY, OWASP}, écosystème Maven, triplet
`paquet + version installée + version corrigée` complet, et provenance ∈
{`DIRECT_EXPLICIT`, `PROPERTY_MANAGED`}. La version retenue est ensuite **la plus
basse version corrigée strictement supérieure et de même majeure**.

Le projet est construit autour de ces portes — et autour de leurs refus.

| Réf. | Dépendance | Version | Provenance | CVE attendue | Correction | Comportement attendu de la plateforme |
|---|---|---|---|---|---|---|
| **VAL-D01** | `com.h2database:h2` | 2.1.212 | `DIRECT_EXPLICIT` | CVE-2022-45868 (HIGH) | 2.2.220 | ✅ **Auto-corrigée.** Même majeure, provenance supportée. |
| **VAL-D02** | `org.apache.commons:commons-lang3` | 3.12.0 via `${commons-lang3.version}` | `PROPERTY_MANAGED` | CVE-2025-48924 (MEDIUM) | 3.18.0 | ✅ **Auto-corrigée.** La plateforme doit modifier **la propriété**, pas une version en dur. |
| **VAL-D03** | `commons-io:commons-io` | 2.6 | `DIRECT_EXPLICIT` | CVE-2021-29425 | 2.7 | ✅ **Auto-corrigée.** Troisième positif : prouve que la correction n'est pas câblée sur une dépendance particulière. |
| **VAL-D04** | `org.yaml:snakeyaml` | 1.33 | `DIRECT_EXPLICIT` | CVE-2022-1471 | **2.0 seulement** | ⛔ **Refus `CROSS_MAJOR_ONLY`.** Un correctif existe, mais il franchit une majeure. |
| **VAL-D05** | `org.apache.commons:commons-text` | 1.9, **transitive** via `commons-configuration2:2.8.0` | `TRANSITIVE` | CVE-2022-42889 « Text4Shell » (CRITICAL) | 1.10.0 | ⛔ **Refus `TRANSITIVE_NOT_AUTOFIXABLE_V1`.** Le correctif est de même majeure : le refus porte sur la **provenance**, pas sur la disponibilité. |
| **VAL-D07** | `org.apache.commons:commons-compress` | 1.21 | `DIRECT_EXPLICIT` | CVE-2024-25710 (boucle infinie), CVE-2024-26308 (épuisement mémoire) | 1.26.0 | ✅ **Auto-corrigée.** Même majeure, provenance supportée. Quatrième positif. |
| **VAL-D08** | `org.bouncycastle:bcprov-jdk18on` | 1.72 | `DIRECT_EXPLICIT` | CVE-2023-33201 (fuite via CertStore LDAP) | 1.73 | ✅ **Auto-corrigée.** Cinquième positif : prouve la correction sur une bibliothèque cryptographique. |
| **VAL-D09** | `org.jsoup:jsoup` | 1.14.3 | `DIRECT_EXPLICIT` | CVE-2022-36033 (contournement de l'assainissement HTML) | 1.15.3 | ✅ **Auto-corrigée.** Sixième positif. |
| **VAL-D06** | paquets système de l'image de base | Alpine de `eclipse-temurin:17.0.9_9` | — | CVE de paquets OS (zlib, busybox, openssl selon la base Trivy) | — | 🔍 **Détection seule.** La chaîne n'a aucune stratégie de version d'image. |

### Pourquoi VAL-D05 est le scénario le plus instructif

La même CVE, avec le même correctif disponible dans la même majeure, serait
**auto-corrigée** si `commons-text` était déclarée en dépendance directe. Elle est
refusée ici uniquement parce qu'elle arrive par transitivité. C'est la
démonstration la plus nette que la plateforme raisonne sur la **provenance** de la
déclaration, et non sur la seule existence d'un correctif.

### Vérification de l'arbre de dépendances

```
+- com.h2database:h2:jar:2.1.212:compile
+- org.apache.commons:commons-lang3:jar:3.12.0:compile
+- commons-io:commons-io:jar:2.6:compile
+- org.yaml:snakeyaml:jar:1.33:compile
+- org.apache.commons:commons-configuration2:jar:2.8.0:compile
|  +- org.apache.commons:commons-text:jar:1.9:compile      <-- VAL-D05, transitive
|  \- commons-logging:commons-logging:jar:1.2:compile
\- org.junit.jupiter:junit-jupiter:jar:5.10.2:test
```

Les sept jars d'exécution sont copiés dans l'image (`target/runtime/`). Trivy
scanne l'**image**, pas le dépôt : sans eux, son analyseur Java ne verrait rien.

---

## 2. Code source — SonarQube

L'étiquette affichée par la plateforme vient du classement de WF1 : tout constat
Sonar `MAJOR` ou `CRITICAL` rattaché à un fichier devient `AUTO_FIX_ELIGIBLE`,
sauf les règles de la liste d'exclusion. En dessous de `MAJOR`, le constat est
`DEVELOPER_ACTION_REQUIRED`.

Cette étiquette est une **prédiction**, pas une qualification : la décision finale
appartient au planificateur du parcours de correction assistée (WF2), qui peut
conclure `MANUAL_OR_SPECIALIST`. Le projet exerce les deux issues.

| Réf. | Règle | Sévérité | Fichier | Étiquette attendue | Issue attendue |
|---|---|---|---|---|---|
| **VAL-S01** | `java:S1068` — champ privé inutilisé | MAJOR (code smell) | `SignatureHeritee.java` | Correction assistée candidate | ✅ Cible connue de WF2 — candidat matérialisable |
| **VAL-S02** | `java:S125` — section de code en commentaire | MAJOR (code smell) | `CatalogueContrats.java` | Correction assistée candidate | ✅ Cible connue de WF2 — candidat matérialisable |
| **VAL-S03** | `java:S2068` — identifiant codé en dur | BLOCKER (vulnérabilité) | `SignatureHeritee.java` | Correction assistée candidate | ⚠️ Attendu `MANUAL_OR_SPECIALIST` : la correction suppose un choix de conception |
| **VAL-S04** | `java:S4790` — algorithme de hachage faible (MD5) | point chaud de sécurité | `SignatureHeritee.java` | Action développeur requise | 🔍 Détection seule — un point chaud se **revoit**, il ne se corrige pas automatiquement |
| **VAL-S05** | `java:S2245` — générateur pseudo-aléatoire | point chaud de sécurité | `SignatureHeritee.java` | Action développeur requise | 🔍 Détection seule |
| **VAL-S06** | `java:S1192` — littéral de chaîne dupliqué | CRITICAL (code smell) | `SignatureHeritee.java` | Correction assistée candidate | ⚠️ Issue variable selon le planificateur |

**Effet attendu sur le Quality Gate :** la présence d'un constat BLOCKER de type
vulnérabilité (VAL-S03) et de points chauds non revus fait passer le Quality Gate
en **ERREUR**. C'est voulu : cet état alimente la classe de gouvernance
`CRITICAL_RISK` côté plateforme et permet de démontrer le parcours d'autorisation
par dérogation.

**Couverture mesurée :** 78,9 % de lignes, 82,6 % d'instructions, 83 branches sur
106 (JaCoCo, 35 tests). Le rapport est importé par Sonar via
`sonar.coverage.jacoco.xmlReportPaths`.

### Un cas volontairement non couvert

`java:S3305` est la seule règle de la liste d'exclusion amont de WF1. Elle concerne
l'injection de dépendances par champ et ne peut pas se déclencher ici : le projet
n'emploie aucun framework d'injection, par construction (un parent Spring
introduirait une gestion de version par BOM, c'est-à-dire la provenance que la
plateforme refuse d'auto-corriger). Ce cas est donc **non démontrable sur ce
projet**, et c'est dit plutôt que simulé.

---

## 3. Application en fonctionnement — OWASP ZAP

L'application sert sa page d'accueil en HTML **sans aucun en-tête de sécurité**.
Les constats qui en découlent sont déterministes et reproductibles.

| Réf. | Constat ZAP attendu | Sévérité | Origine dans le code | Comportement de la plateforme |
|---|---|---|---|---|
| **VAL-Z01** | `10038` — Content Security Policy absente | Medium | `App.traiter()`, aucun en-tête posé | 🔍 Détection seule |
| **VAL-Z02** | `10020` — en-tête anti-clickjacking absent | Medium | idem | 🔍 Détection seule |
| **VAL-Z03** | `10021` — `X-Content-Type-Options` absent | Low | idem | 🔍 Détection seule |
| **VAL-Z04** | `10106` — site servi en HTTP seul | Medium | pas de TLS sur le banc d'essai | 🔍 Détection seule |

ZAP n'appartient pas aux sources de remédiation supportées : aucun composant de
rescan ZAP n'existe côté vérificateur de candidats, et aucun adaptateur de cible
ne sait désigner un fichier de configuration web. Ces constats sont affichés,
hiérarchisés, et **classés manuels**.

---

## 4. Dockerfile — optimiseur (WF5)

Onze défauts délibérés, chacun repéré par un marqueur `DÉFAUT VAL-Kxx` dans le
fichier.

| Réf. | Défaut | Pourquoi c'en est un |
|---|---|---|
| **VAL-K01** | Image de construction désignée par un tag, pas un digest | Un tag est mutable : le même commit peut produire deux images différentes |
| **VAL-K02** | `ADD` au lieu de `COPY` pour un contenu local | `ADD` extrait les archives et récupère des URL — comportements implicites non souhaités |
| **VAL-K03** | Le contexte entier est copié avant la résolution Maven | La couche de dépendances est invalidée à chaque changement de source |
| **VAL-K04** | `mvn package -DskipTests` dans l'étape de construction | Une image peut être produite depuis un code dont les tests échouent |
| **VAL-K05** | Image d'exécution périmée (octobre 2023) | Porte les CVE de paquets système de VAL-D06 |
| **VAL-K06** | Valeur sensible en `ENV` | Reste lisible dans l'historique de l'image — déjà signalé par le linter BuildKit |
| **VAL-K07** | `apk add` sans `--no-cache` | L'index des paquets reste dans l'image |
| **VAL-K08** | Deux `RUN` là où un seul suffirait | Deux couches pour un gain nul |
| **VAL-K09** | Aucune directive `USER` | Le conteneur s'exécute en root |
| **VAL-K10** | Aucune `HEALTHCHECK` | Alors que l'application expose `/health`, déterministe |
| **VAL-K11** | Le chemin COPY omet la version du JAR produit par Maven | La construction Docker échoue réellement : fichier source introuvable |

Le parcours d'application de WF5 passe par une **porte déterministe** avant
publication : l'analyse est produite par un modèle, mais la proposition n'est
écrite dans une branche qu'après ce contrôle.

---

## 5. Jenkinsfile — optimiseur (WF4)

> **Mise à jour (post-réécriture) :** le Jenkinsfile de ce projet a été
> déplié en pipeline scripté autonome, sans `@Library`, pour la
> présentation devant le jury (le fichier contient désormais la totalité
> du pipeline, lisible directement). Deux des trois défauts ci-dessous ne
> sont plus démontrables sur CE fichier, pour deux raisons différentes —
> ce tableau le dit plutôt que de le laisser périmé.

| Réf. | Défaut | Pourquoi c'en est un | État sur le Jenkinsfile actuel |
|---|---|---|---|
| **VAL-J01** | `@Library('pfe-devsecops')` sans version épinglée | Deux builds du même commit peuvent exécuter deux recettes différentes | ❌ **N/A** — il n'y a plus de `@Library` du tout, donc plus rien à épingler |
| **VAL-J02** | Aucun délai maximal ni politique de rétention déclarés | Un build bloqué peut occuper un exécuteur indéfiniment | ❌ **Résolu** — `timeout(time: TIMEOUT_PIPELINE_HOURS, unit: 'HOURS')` et `buildDiscarder(logRotator(numToKeepStr: '15'))` sont maintenant déclarés explicitement dans le fichier (ils existaient déjà, cachés dans la bibliothèque) |
| **VAL-J03** | Aucune étiquette d'agent déclarée | L'exécution dépend de la disponibilité des nœuds, pas d'un choix explicite | ✅ **Intact** — `node { ... }` reste sans étiquette |
| **VAL-J04** | Appel à un wrapper Maven absent du dépôt | `chmod +x mvnw` échoue avant la compilation | ✅ Défaut bloquant du scénario échec puis correction |

**État actuel :** VAL-J03 reste un constat d’architecture ; VAL-J04 est un défaut d’exécution délibéré et corrigeable par WF4. VAL-J01 et VAL-J02 restent non applicables/résolus après le passage au pipeline autonome. Le scénario de construction ne dépend pas du fait que les mauvaises pratiques d’architecture bloquent ou non Jenkins.

---

## 6. Contrôles négatifs

Un contrôle négatif prouve que la plateforme **refuse** quand elle doit refuser.
C'est la partie la plus importante de la démonstration : un système qui accepte
tout n'a rien vérifié.

| Réf. | Situation à provoquer | Résultat attendu |
|---|---|---|
| **NC-1** | Un candidat de correction casse la suite de tests | `BUILD FAILURE` côté vérificateur → candidat **rejeté**, aucune écriture Git, aucune PR |
| **NC-2** | Un candidat compile et passe les tests, mais le rescan voit toujours la CVE | Candidat **rejeté** — *build réussi n'est pas sécurité fermée* |
| **NC-3** | Deux remédiations lancées simultanément sur `pom.xml` | La première réserve la cible, la seconde reçoit **HTTP 409 `REMEDIATION_TARGET_ALREADY_IN_PROGRESS`** avec le lien vers la proposition qui détient le verrou |
| **NC-4** | Déploiement demandé sans provenance d'artefact enregistrée | Classe `TECHNICALLY_IMPOSSIBLE`, motif `DEPLOY_ARTIFACT_PROVENANCE_UNAVAILABLE`, **aucune dérogation possible, y compris administrateur** |
| **NC-5** | Accès à une route de données sans jeton | `HTTP 401` |

**NC-3 est garanti par construction :** les six scénarios auto-corrigeables
(VAL-D01, VAL-D02, VAL-D03, VAL-D07, VAL-D08, VAL-D09) visent tous le même fichier `pom.xml`, donc la même
clé de réservation. Lancer deux d'entre eux en parallèle produit nécessairement le
conflit.

**Comment produire NC-1 :** les tests de `ContratsDependancesTest` vérifient le
comportement dont l'application dépend, pas les numéros de version. Ils passent
après une montée de version légitime de même majeure, et échouent si le
comportement change. Pour forcer NC-1 lors de la démonstration, modifier
temporairement une assertion de ce fichier dans la branche candidate.

---

## 7. Couverture des fonctionnalités de la plateforme

| Fonctionnalité | Exercée par | Preuve attendue |
|---|---|---|
| Intégration Git / SCM | dépôt, branche `main` | dépôt et révision affichés sur la fiche projet |
| Intégration Jenkins | `Jenkinsfile` + bibliothèque partagée | étapes du pipeline restituées dans l'onglet Jenkins |
| Build Maven | `mvn clean verify` | `BUILD SUCCESS` |
| Tests unitaires | 44 tests JUnit 5 | `tests=44 failures=0 errors=0` |
| Couverture | JaCoCo + import Sonar | ≈ 79 % de lignes |
| Analyse qualité | SonarQube | six constats, Quality Gate en **ERREUR** |
| Analyse de composition | OWASP Dependency-Check | CVE des dépendances déclarées et transitives |
| Scan d'image | Trivy | CVE Java **et** CVE de paquets système |
| Analyse dynamique | OWASP ZAP | quatre constats d'en-têtes |
| Trois états de scan | tous | complet-avec-constats, complet-sans-constat, indisponible |
| Incident et analyses IA | WF1 | cause racine, risque, faisabilité, guide |
| Assistance conversationnelle | ChatOps | question sur l'état du projet |
| Remédiation déterministe | WF6 | VAL-D01, VAL-D02, VAL-D03, VAL-D07, VAL-D08, VAL-D09 (six positifs) |
| Refus de remédiation | WF6 | VAL-D04, VAL-D05, VAL-D06 |
| Vérification de candidat | candidate-verifier | compilation, tests, reconstruction d'image, rescan |
| Fermeture de sécurité | double rescan | la CVE visée disparaît **et** aucune régression |
| Écrivain unique | réservation de cible | NC-3 |
| Reprise de tentative | backend | identité de tentative régénérée, réservation retenue |
| Proposition Git | WF2 / WF6 | branche dédiée, un commit, PR ouverte — jamais de poussée sur `main` |
| Revalidation après PR | WF3 | résultat du build de validation rattaché à la bonne révision |
| Optimiseur Jenkinsfile | WF4 | VAL-J03 et VAL-J04 (VAL-J01/J02 non applicables/résolus) |
| Optimiseur Dockerfile | WF5 | VAL-K01 à VAL-K11 |
| Gouvernance du déploiement | backend | classe, contrôles détaillés, motifs bloquants |
| Provenance d'artefact | publication ACR | NC-4 tant que l'image n'est pas publiée avec sa provenance |
| Autorisation tracée | backend | motif, accusés, phrase de confirmation, usage unique |

---

## 8. Ce que ce projet ne démontre **pas**

Les lister est aussi important que lister le reste.

| Capacité | Statut | Raison |
|---|---|---|
| Correction automatique d'un défaut Sonar | détection et candidature seulement | aucune stratégie de remédiation de code source qualifiée dans WF6 |
| Correction automatique d'un constat ZAP | détection seule | ZAP absent des sources supportées, aucun rescan ZAP, aucun adaptateur de cible |
| Correction d'un paquet système | détection seule | aucune stratégie de version d'image |
| Montée de version majeure | non supporté | `CROSS_MAJOR_ONLY` — exige un humain |
| Dépendance transitive | non supporté | `TRANSITIVE_NOT_AUTOFIXABLE_V1` |
| Dépendance gérée par BOM ou par un parent | non supporté / partiel | `ADMIN_ACTION_REQUIRED` ; aucun parent dans ce projet, précisément pour éviter ce cas |
| Édition dans un module enfant | hors périmètre | l'adaptateur de cible n'ancre que le descripteur racine ; un seul `pom.xml` ici |
| Dépendance npm, Python ou Gradle | détection seulement | l'orchestrateur de remédiation est Maven |
| Règle Sonar `java:S3305` | non démontrable | aucun framework d'injection dans le projet |
| Déploiement Azure de la base vulnérable | non exécuté | une application volontairement vulnérable ne doit pas être exposée |

## Complément : défauts bloquants de construction

VAL-J04 (wrapper Maven absent) et VAL-K11 (chemin du JAR incorrect) provoquent des erreurs d’exécution réelles. Voir [le scénario de démonstration](SCENARIO_BUILD_ECHEC_PUIS_CORRECTION.md). VAL-J04 est le défaut de construction volontaire corrigeable par WF4.
