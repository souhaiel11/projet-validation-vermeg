// =============================================================================
// PROJET DE VALIDATION VERMEG — Jenkinsfile MINCE (banc d'essai WF4).
//
// Toute la plomberie plateforme (reporting n8n/WF1, provenance ACR, verif
// candidat, telemetrie, scans Sonar/Trivy/OWASP/ZAP) vit dans la bibliotheque
// partagee `pfe-devsecops` — meme contrat que les projets reels. Ne restent
// VISIBLES ici que les choix DevSecOps a presenter et corriger : l'etape Build.
//
// VALIDATION : buildCommand corrige (mvn) pour verifier la chaine complete.
// =============================================================================
@Library('pfe-devsecops') _

devSecOpsPipeline {
    applicationName = 'projet-validation-vermeg'
    skipTests       = false
    zapTargetUrl    = 'http://projet-validation-vermeg:8080'

    // Etape Build fournie par le projet, VISIBLE et corrigeable par WF4 (chaine).
    buildCommand = """
        set -e
        mvn clean package -B -DskipTests=false
    """
}
