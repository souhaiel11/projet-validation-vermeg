# Déroulé de démonstration devant le jury

> Durée visée : 12 à 15 minutes. Chaque étape indique l'écran, le geste et ce qui
> doit s'afficher. Si une étape ne produit pas le résultat attendu, le dire —
> c'est un projet de validation, pas une vitrine.

## Avant la soutenance

| # | Vérification | Comment |
|---|---|---|
| 1 | Le dépôt est poussé et le projet créé dans la plateforme | voir `CONFIGURATION_PLATEFORME.md` |
| 2 | Un build Jenkins complet est passé | les trois rapports JSON existent pour ce numéro de build |
| 3 | L'analyse SonarQube est remontée | Quality Gate affiché en ERREUR |
| 4 | Les tâches de remédiation sont créées | six constats de dépendances au moins |
| 5 | La cible `pom.xml` n'est pas déjà réservée | sinon NC-3 ne pourra pas être rejoué |

---

## Acte 1 — « La chaîne produit des faits » (3 min)

**Écran : Projet → vue d'ensemble, puis onglet Jenkins.**

1. Montrer la fiche projet : dépôt, branche, dernier build, commit analysé.
2. Ouvrir l'onglet Jenkins : les étapes du pipeline, une par une.
3. Ouvrir l'onglet Tests : `35 tests, 0 échec`, couverture ≈ 79 %.

> **Phrase clé :** « Le build est réussi au sens de Jenkins. Ça ne veut pas dire
> que l'application est déployable — c'est exactement ce que la suite montre. »

---

## Acte 2 — « Les quatre scanners ne voient pas la même chose » (3 min)

**Écran : Projet → onglet Sécurité.**

4. Montrer les constats par source : Trivy, OWASP, SonarQube, ZAP.
5. Insister sur la **séparation des sources** : la même CVE peut apparaître dans
   Trivy *et* dans OWASP. Les colonnes ne s'additionnent pas.
6. Ouvrir un rapport JSON source et comparer l'empreinte SHA-256 affichée avec
   celle du fichier téléchargé.

> **Phrase clé :** « Chaque constat garde sa source. C'est ce qui permet de
> compter des constats sans prétendre compter des vulnérabilités uniques. »

---

## Acte 3 — « L'IA explique, elle ne décide pas » (2 min)

**Écran : Incidents → l'incident du dernier build → onglet Analyse IA.**

7. Montrer les quatre analyses : cause racine, risque, faisabilité, guide.
8. Montrer la recommandation et dire qu'elle est **calculée avant** l'appel au
   modèle : rejouer l'analyse redonne la même recommandation, formulée
   différemment.

---

## Acte 4 — « Remédiation automatique » (3 min)

**Écran : Projet → Trivy / OWASP.**

9. Sélectionner **VAL-D01** (`h2 2.1.212`) et lancer la remédiation contrôlée.
10. Suivre la tentative : préparation du candidat, compilation, 35 tests,
    reconstruction de l'image, double rescan, évaluation de fermeture.
11. Montrer la Pull Request produite : une branche dédiée, un commit,
    `2.1.212 → 2.2.220` dans `pom.xml`.

> **Phrase clé :** « La fermeture n'est pas déduite de l'absence du constat dans
> le nouveau rapport. Elle est prouvée positivement : l'artefact contient bien la
> version attendue et le rescan est complet. »

12. Montrer **VAL-D02** et souligner que la plateforme a modifié **la propriété**
    `${commons-lang3.version}`, pas une version écrite en dur.

---

## Acte 5 — « Et surtout, ce qu'elle refuse » (4 min)

C'est l'acte le plus important.

13. **VAL-D05 — refus de provenance.** Sélectionner la CVE Text4Shell sur
    `commons-text 1.9`. Montrer le refus `TRANSITIVE_NOT_AUTOFIXABLE_V1`.
    > « Le correctif existe, en 1.10.0, dans la même majeure. La plateforme
    > refuse quand même, parce que la dépendance arrive par
    > `commons-configuration2`. Corriger ici reviendrait à écrire une version
    > que le projet ne déclare pas. »

14. **VAL-D04 — refus de majeure.** Montrer `snakeyaml 1.33` et le refus
    `CROSS_MAJOR_ONLY`.
    > « Le correctif est en 2.0. Or en 2.0, le constructeur de `SafeConstructor`
    > change de signature : la montée casserait la compilation. C'est pourquoi un
    > franchissement de majeure demande un humain. » *(Ouvrir `DescripteurYaml.java`
    > si le jury veut la preuve.)*

15. **NC-3 — écrivain unique.** Lancer VAL-D03 pendant que VAL-D01 est encore en
    cours. Montrer le `HTTP 409 REMEDIATION_TARGET_ALREADY_IN_PROGRESS` et le lien
    vers la proposition qui détient le verrou.
    > « Les deux CVE n'ont rien à voir entre elles. Mais elles se corrigent dans
    > le même fichier. Le verrou est posé sur le fichier, pas sur la
    > vulnérabilité. »

16. **NC-4 — gouvernance du déploiement.** Onglet Déploiement. Montrer les
    contrôles évalués un par un, le motif bloquant
    `DEPLOY_ARTIFACT_PROVENANCE_UNAVAILABLE`, et la mention explicite qu'aucune
    acceptation de risque ne peut le contourner.
    > « Un défaut de qualité est un risque qu'une organisation peut choisir
    > d'assumer en le documentant. Un défaut d'identité n'est pas un risque :
    > c'est l'aveu qu'on ignore ce qu'on s'apprête à déployer. »

---

## Acte 6 — « Les optimiseurs » (2 min, si le temps le permet)

17. Lancer l'optimiseur Dockerfile (WF5) et montrer les constats VAL-K01 à
    VAL-K10, puis la proposition de correction et sa porte déterministe.
18. Lancer l'optimiseur Jenkinsfile (WF4) et montrer VAL-J01 — la bibliothèque
    non épinglée.

---

## Questions probables du jury, et la réponse

| Question | Réponse |
|---|---|
| « Pourquoi seulement Maven ? » | L'adaptateur de remédiation est spécialisé Maven. L'architecture prévoit d'autres écosystèmes, mais rien ne le démontre : je ne le revendique donc pas. |
| « Pourquoi la plateforme ne corrige-t-elle pas les défauts Sonar ? » | Elle les détecte et peut produire un **candidat** via le parcours assisté. Elle ne garantit pas la correction : la littérature montre qu'un correctif validé par les tests n'est pas nécessairement correct. |
| « Et si l'IA se trompe ? » | Elle ne décide de rien. La recommandation est calculée par du code déterministe avant l'appel au modèle, et aucune écriture distante ne dépend d'une sortie de modèle. |
| « Pourquoi autant de refus ? » | Parce que chaque étape impose une condition. Un système qui aurait produit une Pull Request pour chacun des six constats n'aurait rien vérifié. |
| « Le projet est-il représentatif ? » | Non, et c'est assumé : c'est un banc d'essai construit autour des capacités et des limites de la plateforme. Il sert à prouver des comportements, pas à mesurer une performance. |
| « Pourquoi une application volontairement vulnérable ? » | Pour provoquer des situations réelles sans risque. Les défauts sont des motifs détectables ; aucun n'ouvre un chemin exploitable, et c'est documenté classe par classe. |
