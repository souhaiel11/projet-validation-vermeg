// =============================================================================
// PROJET DE VALIDATION VERMEG — Jenkinsfile MINCE (banc d'essai WF4).
//
// Toute la plomberie plateforme (reporting n8n/WF1, provenance ACR, verif
// candidat, telemetrie, scans Sonar/Trivy/OWASP/ZAP) vit dans la bibliotheque
// partagee `pfe-devsecops` — meme contrat que les projets reels. Ne reste
// VISIBLE ici que ce qui doit etre presente et corrige en demonstration :
// l'etape Build.
//
// DEFAUT VAL-J04 (delibere) : `chmod +x mvnw` puis `./mvnw` alors qu'AUCUN
// wrapper Maven n'est versionne -> le build echoue (« cannot access mvnw »).
// C'est precisement ce que WF4 doit corriger (remplacer par le `mvn` configure).
// Fichier volontairement court : WF4 le regenere de facon fiable.
// =============================================================================
@Library('pfe-devsecops') _

devSecOpsPipeline {
    applicationName = 'projet-validation-vermeg'
    skipTests       = false
    zapTargetUrl    = 'http://projet-validation-vermeg:8080'

    // Etape Build fournie par le projet, VISIBLE et corrigeable par WF4.
    buildCommand = """
        set -e
        mvn clean package -B -DskipTests=false
    """
}