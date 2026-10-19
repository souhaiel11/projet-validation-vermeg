# Mise en service du projet dans la plateforme

> À faire **une seule fois**, avant la première démonstration.
> Rien dans ce document n'est automatique : chaque étape est une action de votre part.

## 1. Dépôt Git

```bash
cd "projet validation vermeg"
git init
git add .
git commit -m "Projet de validation VERMEG — base vulnérable de référence"
git branch -M main
git remote add origin https://github.com/souhaiel11/projet-validation-vermeg.git
git push -u origin main
git tag baseline-vulnerable
git push origin baseline-vulnerable
```

L'étiquette `baseline-vulnerable` permet de revenir à l'état initial après une
démonstration qui a produit des Pull Requests :

```bash
git checkout main && git reset --hard baseline-vulnerable && git push --force-with-lease
```

## 2. Job Jenkins

Créer un job de type **Pipeline** nommé exactement `projet-validation-vermeg`
(le nom du job sert de clé de corrélation côté plateforme) :

- **Definition** : *Pipeline script from SCM*
- **SCM** : Git, URL du dépôt, identifiants GitHub existants
- **Branch** : `*/main`
- **Script Path** : `Jenkinsfile`

Vérifier que la bibliothèque partagée `pfe-devsecops` est bien déclarée dans la
configuration globale de Jenkins — le `Jenkinsfile` la charge par son nom.

## 3. Projet SonarQube

Créer un projet de clé `projet-validation-vermeg`. Aucun paramétrage
particulier : le Quality Gate par défaut suffit, et il doit passer en **ERREUR**
à la première analyse. C'est le comportement attendu, pas un incident.

## 4. Fiche projet dans la plateforme

Interface → **Projets** → *Nouveau projet*. Renseigner :

| Champ | Valeur |
|---|---|
| Nom | `projet-validation-vermeg` |
| Dépôt GitHub | `souhaiel11/projet-validation-vermeg` |
| Job Jenkins | `projet-validation-vermeg` |
| URL Jenkins | la même que pour les projets existants |
| Clé SonarQube | `projet-validation-vermeg` |
| URL SonarQube | la même que pour les projets existants |

Les jetons d'accès sont saisis une fois et ne sont jamais réaffichés par l'API.

## 5. Cible de l'analyse dynamique

Le `Jenkinsfile` déclare `zapTargetUrl = 'http://projet-validation-vermeg:8080'`.
Ce nom d'hôte doit être **résoluble depuis le conteneur ZAP**.

> ⚠️ **Piège connu de l'infrastructure :** adresser un service par son *nom de
> conteneur* plutôt que par son *alias réseau* produit un échec silencieux. Vérifier
> que l'application de validation est rattachée au même réseau que ZAP et qu'elle y
> porte bien l'alias `projet-validation-vermeg`.

Deux montages possibles :

- **Docker Compose** — utiliser le `compose.yaml` fourni et rattacher le service
  au réseau de l'outillage ;
- **minikube** — appliquer `k8s/zap-target.yaml`, qui publie un service
  ClusterIP du même nom.

Si la cible n'est pas joignable, ZAP produira un résultat **indisponible**. Ce
n'est pas une panne : c'est le troisième état de scan, et il est affiché comme
tel. Ne pas le confondre avec « aucune alerte ».

## 6. Préparation Azure (facultatif)

Pour exercer la gouvernance du déploiement jusqu'au bout, déclarer dans la
configuration du projet une cible de déploiement, un registre et un contrat de
santé :

| Champ | Valeur suggérée |
|---|---|
| Cible | `aci-projet-validation-vermeg` |
| Groupe de ressources | celui déjà utilisé par les autres projets |
| Chemin de santé | `/health` |
| Corps attendu | `{"status":"UP"}` |
| Port | `8080` |

> **Ne pas déployer réellement cette application.** Elle est volontairement
> vulnérable. Tant qu'aucune image n'est publiée avec sa provenance, la
> gouvernance répond `TECHNICALLY_IMPOSSIBLE` — ce qui est précisément le
> contrôle négatif NC-4 à montrer au jury.

## 7. Premier build

Lancer le job Jenkins. À la fin, vérifier dans la plateforme :

- [ ] un incident a été créé, rattaché au job, au numéro de build et au commit ;
- [ ] les quatre scanners ont un état propre (complet ou indisponible) ;
- [ ] les tâches de remédiation sont créées, une par constat, sans doublon ;
- [ ] le Quality Gate SonarQube est en **ERREUR** ;
- [ ] l'onglet Déploiement affiche `TECHNICALLY_IMPOSSIBLE`.

Si l'un de ces points manque, ne pas improviser devant le jury : le noter et le
présenter comme une limite constatée.
