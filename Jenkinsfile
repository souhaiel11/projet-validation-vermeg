// =============================================================================
// PROJET DE VALIDATION VERMEG — Jenkinsfile MINCE (banc d'essai WF4).
//
// Toute la plomberie plateforme (reporting n8n/WF1, provenance ACR, verif
// candidat, telemetrie, scans Sonar/Trivy/OWASP/ZAP) vit dans la bibliotheque
// partagee `pfe-devsecops` — meme contrat que les projets reels. Ne reste
// VISIBLE ici que ce qui doit etre presente et corrige en demonstration :
// l'etape Build.
//
// DEFAUT VAL-J04 (corrige) : `chmod +x mvnw` puis `./mvnw` remplace par `mvn`
// configure dans Jenkins — le build n'echoue plus sur l'absence du wrapper.
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