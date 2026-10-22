# Scénario de démonstration : échec réel puis correction

Ce scénario concerne uniquement le dépôt de validation. Aucun statut ne doit être simulé.

| Défaut | Échec attendu | Correction attendue |
|---|---|---|
| VAL-J04 : `chmod +x mvnw` puis `./mvnw` alors que le wrapper est absent | Build Maven : `cannot access mvnw` | WF4 remplace les appels au wrapper absent par le Maven configuré, sans inventer de wrapper. |
| VAL-K11 : `COPY` attend `projet-validation-vermeg.jar`, alors que Maven produit `projet-validation-vermeg-1.0.0.jar` | Construction Docker : source COPY introuvable | WF5 aligne uniquement le chemin de l’artefact sur `pom.xml`. |

Les étapes Build et Docker Build conservent leur gestion d’erreur pour poursuivre le diagnostic et le reporting, mais un échec réel de l’une de ces étapes marque désormais le build global FAILURE, plutôt que UNSTABLE.

## Déroulement

1. Construire la révision de démonstration et constater les deux erreurs dans les étapes concernées.
2. Analyser le Jenkinsfile dans WF4, sélectionner le défaut du wrapper absent et créer une PR.
3. Analyser le Dockerfile dans WF5, sélectionner l’incohérence du chemin du JAR et créer une PR.
4. Revalider chaque PR sur son SHA exact. Une PR qui corrige un seul fichier peut rester en échec global tant que l’autre défaut est présent : cela ne prouve pas à lui seul que son correctif est faux.
5. Après intégration des deux correctifs, revalider la construction. Les vulnérabilités Sonar, Trivy, OWASP et ZAP restent à traiter séparément et peuvent encore influencer le verdict global selon les contrôles exécutés.

Les dix mauvaises pratiques Dockerfile VAL-K01 à VAL-K10 ne garantissaient pas un échec de construction ; elles restent des constats d’analyse. Le nettoyage de commentaires du commit 17de4eb n’a pas modifié le code exécutable et n’a pas modifié Dockerfile.

## Réunir les correctifs avant la validation globale

Les deux défauts sont indépendants. Pour une démonstration complète avec les workflows spécialisés :

1. WF4 crée la branche/PR corrigeant Jenkinsfile, sans fusionner immédiatement dans main.
2. Pour WF5, renseigner comme branche cible la branche de correction WF4 : sa PR Dockerfile portera ainsi les deux correctifs dans son historique.
3. Revalider cette branche combinée sur son commit exact. Ne pas contourner les contrôles de fusion sur une PR qui contient encore l’autre défaut.
4. Intégrer la correction Dockerfile dans la branche WF4, puis revalider la PR complète vers main avant fusion.

Pour une démonstration indépendante de chaque workflow, utiliser deux variantes de test avec un seul défaut bloquant chacune. Ne jamais présenter une validation partielle comme un succès global.
