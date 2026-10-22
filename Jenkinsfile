// =============================================================================
// PROJET DE VALIDATION VERMEG — Jenkinsfile MINCE (banc d'essai WF4).
//
// Toute la plomberie plateforme (reporting n8n/WF1, provenance ACR, vérif
// candidat, télémétrie, scans Sonar/Trivy/OWASP/ZAP) vit dans la bibliothèque
// partagée `pfe-devsecops` — même contrat que les projets réels. Ne restent
// VISIBLES ici que ce qui doit être présenté et corrigé en démonstration :
// l'étape Build.
//
// DÉFAUT VAL-J04 (délibéré) : `chmod +x mvnw` puis `./mvnw` alors qu'AUCUN
// wrapper Maven n'est versionné -> le build échoue (« cannot access mvnw »).
// C'est précisément ce que WF4 doit corriger (remplacer par le `mvn` configuré).
// Le reste du pipeline DevSecOps s'exécute via la bibliothèque et s'affiche
// comme étapes nommées dans Jenkins.
// =============================================================================
@Library('pfe-devsecops') _

devSecOpsPipeline {
    applicationName = 'projet-validation-vermeg'
    skipTests       = false
    zapTargetUrl    = 'http://projet-validation-vermeg:8080'

    // Étape Build fournie par le projet, VISIBLE et corrigeable par WF4.
    buildStep = {
        sh '''
            set -e
            mvn clean package -B -DskipTests=false
        '''
    }
}
