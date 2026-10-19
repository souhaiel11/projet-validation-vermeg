// ════════════════════════════════════════════════════════════════════════════
//  PROJET DE VALIDATION VERMEG
//  APPLICATION INTENTIONNELLEMENT VULNÉRABLE — BANC D'ESSAI UNIQUEMENT.
//
//  Tout le pipeline — checkout, build, tests, SonarQube, Docker, Trivy, OWASP
//  Dependency-Check, ZAP, publication d'image et rappel vers la plateforme —
//  vit dans la bibliothèque partagée `pfe-devsecops`. Un projet ne recopie
//  rien : il se déclare.
//
//  ⚠ DÉFAUT DÉLIBÉRÉ VAL-J01 — la bibliothèque est chargée sans version
//  épinglée. `@Library('pfe-devsecops')` suit la branche par défaut : deux
//  builds du même commit peuvent donc exécuter deux recettes différentes.
//  La forme reproductible serait `@Library('pfe-devsecops@<tag ou SHA>')`.
//  C'est la matière du scénario VAL-J (optimiseur Jenkinsfile) ; l'optimiseur
//  récupère également pom.xml et Dockerfile comme contexte d'analyse.
//  Voir docs/MATRICE_VALIDATION.md.
// ════════════════════════════════════════════════════════════════════════════
@Library('pfe-devsecops') _

devSecOpsPipeline {
    applicationName = 'projet-validation-vermeg'

    // Déclaration sincère : les tests doivent réellement s'exécuter. Le
    // contrôle négatif NC-1 repose entièrement sur le fait qu'un candidat de
    // correction qui casse la suite soit rejeté avant toute écriture Git.
    skipTests       = false

    // Cible de l'analyse dynamique. Le nom d'hôte doit être résoluble depuis
    // le conteneur ZAP ; voir docs/CONFIGURATION_PLATEFORME.md.
    zapTargetUrl    = 'http://projet-validation-vermeg:8080'
}
