# Périmètre de sûreté

> Ce projet est **intentionnellement vulnérable**. Ce document explique
> précisément en quoi, et surtout ce qu'il n'est pas.

## Le principe suivi

Chaque défaut de ce projet est un **motif détectable**, pas une **vulnérabilité
exploitable**. Les dépendances vulnérables sont réellement présentes et réellement
utilisées — sans quoi les scanners ne les verraient pas et la démonstration
reposerait sur du décor — mais le chemin qui rend chaque CVE exploitable est
fermé par construction.

Cette distinction est tenable et vérifiable. Elle est détaillée ci-dessous,
dépendance par dépendance.

| Dépendance | Chemin d'exploitation de la CVE | Pourquoi il est fermé ici |
|---|---|---|
| `commons-text 1.9` (Text4Shell) | Interpoler une chaîne fournie par un attaquant avec `StringSubstitutor.createInterpolator()`, qui active les recherches `script:`, `dns:` et `url:` | L'interpolation ne porte que sur des clés et des valeurs écrites dans le code. L'interpolateur étendu n'est jamais construit. Aucune entrée d'appelant n'est interpolée. |
| `h2 2.1.212` | Console H2 exposée, ou URL JDBC influençable | Aucune console n'est démarrée. L'URL JDBC est une constante. La base est strictement en mémoire. Toutes les requêtes sont préparées ; aucun SQL n'est concaténé depuis une entrée. |
| `snakeyaml 1.33` | Charger un document YAML hostile avec le constructeur par défaut, qui instancie des types arbitraires | L'analyseur est construit avec un `SafeConstructor`, qui interdit cette instanciation. Le document lu est une ressource embarquée dans le jar, jamais un document fourni. |
| `commons-io 2.6` | Construire un chemin de fichier à partir d'une entrée puis y accéder | Aucune opération sur le système de fichiers. Les méthodes employées manipulent des chaînes et ne servent qu'à l'affichage. |
| `commons-lang3 3.12.0` | — | Usage de fonctions de chaînes uniquement. |

## Les défauts de code source

Ceux de `SignatureHeritee.java` sont des motifs que SonarQube doit lever :

- l'**identifiant codé en dur** est une constante factice qui n'ouvre aucun
  accès ; son résultat de comparaison n'est utilisé nulle part dans le routage ;
- l'**empreinte MD5** étiquette un export synthétique ; elle ne protège rien ;
- le **tirage pseudo-aléatoire** produit un numéro de lot d'affichage ; aucune
  décision de sécurité n'en dépend ;
- le **champ inutilisé**, le **code en commentaire** et le **littéral dupliqué**
  sont des défauts de qualité, sans effet d'exécution.

## Ce que le projet ne contient délibérément pas

Aucune injection SQL atteignable, aucune injection de commande, aucune
désérialisation d'entrée, aucune traversée de chemin réelle, aucun appel réseau
sortant, aucune écriture sur le système de fichiers, aucune authentification à
contourner, aucun identifiant réel.

Seules les méthodes `GET` et `HEAD` sont acceptées. L'application est en lecture
seule et sans état persistant.

## Les en-têtes de sécurité absents

C'est le seul défaut qui soit une vraie faiblesse de configuration, et il est
assumé : il fournit la matière de l'analyse dynamique. Sur une application réelle,
l'absence de `Content-Security-Policy` et de protection anti-clickjacking est un
défaut à corriger. Ici, l'application ne sert qu'une page statique sans script,
sans formulaire et sans session.

## Règles d'exploitation

1. Ne jamais exposer ce service sur un réseau public ni sur un port routable.
2. Ne jamais le déployer en production, ni sur un abonnement cloud partagé avec
   des charges réelles.
3. Conserver l'avertissement dans le `README`, le `pom.xml`, le `Dockerfile`,
   les étiquettes OCI de l'image et la réponse de `/api/info`.
4. Ne pas réutiliser ce code comme base d'une application réelle.
