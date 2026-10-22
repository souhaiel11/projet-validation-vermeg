
import groovy.transform.Field

@Field final String CRED_SONAR_TOKEN    = 'SONAR_TOKEN'
@Field final String CRED_N8N_API_KEY    = 'N8N_API_KEY'
@Field final String CRED_NVD_API_KEY    = 'NVD_API_KEY'
@Field final String CRED_ACR            = 'ACR_CREDENTIALS'
@Field final String CRED_INTERNAL_SECRET = 'N8N_INTERNAL_SECRET'

@Field final String SONAR_ENV_NAME = 'sq1'
@Field final String SONAR_HOST_URL = 'http://sonarqube:9000'
@Field final String SONAR_ANALYSIS_MODE = 'COMMUNITY_EXACT_SHA'

// Alias reseau, pas le nom du conteneur : `pfe-backend` ne se resout plus
// (conteneur arrete), et l'etape Publish Image (ACR) tombait sur son curl -f.
@Field final String BACKEND_URL     = 'http://backend:3001'
@Field final String N8N_WEBHOOK_URL = 'http://n8n:5678/webhook/jenkins-event'

@Field final String K8S_NAMESPACE    = 'pfe-devsecops'
@Field final String KUBECONFIG_PATH  = '/var/jenkins_home/.kube/config'
@Field final String ZAP_IMAGE        = 'zaproxy/zap-stable:latest'

@Field final String JENKINS_REPORT_ROOT = '/shared/reports'
@Field final String N8N_REPORT_ROOT     = '/home/node/.n8n-files/reports'

@Field final boolean SONAR_ENABLED = true
@Field final boolean TRIVY_ENABLED = true
@Field final boolean OWASP_ENABLED = true
@Field final boolean ZAP_ENABLED_ON_BRANCH_BUILDS = true
@Field final boolean ACR_PUBLISH_ENABLED = true

@Field final boolean DEFAULT_JENKINS_HARD_GATE = false
@Field final String DEFAULT_CVSS_FAIL_THRESHOLD = '9.0'

@Field final int TIMEOUT_PIPELINE_HOURS   = 3
@Field final int TIMEOUT_TRIVY_MINUTES    = 35
@Field final int TIMEOUT_OWASP_MINUTES    = 40
@Field final int TIMEOUT_ZAP_MINUTES      = 40
@Field final int TIMEOUT_POST_REPORT_MINUTES = 2

@Field final String OWASP_DC_VERSION  = '12.2.2'
@Field final String OWASP_DC_DATA_DIR = '/var/jenkins_home/dependency-check-data-v12'

@Field final String APPLICATION_NAME  = 'projet-validation-vermeg'
@Field final String IMAGE_NAME        = APPLICATION_NAME
@Field final String WORKING_DIRECTORY = null
@Field final String DOCKERFILE_PATH   = null
@Field final boolean CONFIGURED_SKIP_TESTS = false
@Field final String ZAP_TARGET_URL = "http://${APPLICATION_NAME}:8080"

Map prValidationContext(def rawContext) {
String encoded = String.valueOf(rawContext ?: '').trim()
if (!encoded) return [:]
try {
String json = new String(Base64.urlDecoder.decode(encoded), 'UTF-8')
Map value = (Map) new groovy.json.JsonSlurperClassic().parseText(json)
def required = ['validationRequestId','projectId','incidentId','fixRequestId','batchId','batchKey',
'attemptCount','repository','prNumber','prHeadBranch','expectedPrHeadSha','jenkinsJob','prValidationJob']
if (SONAR_ANALYSIS_MODE == 'COMMUNITY_EXACT_SHA') {
required = required + ['baseSonarProjectKey', 'validationSonarProjectKey']
}
if (required.any { value[it] == null || String.valueOf(value[it]).trim() == '' }) return [:]
return value
} catch (ignored) {
return [:]
}
}

properties([
disableConcurrentBuilds(),
buildDiscarder(logRotator(numToKeepStr: '15')),
parameters([
booleanParam(
name: 'JENKINS_HARD_GATE',
defaultValue: DEFAULT_JENKINS_HARD_GATE,
description: 'Si vrai, Jenkins fait échouer le build lui-même sur une vulnérabilité CVSS critique. Par défaut faux : l\'application de la politique est déléguée à la plateforme (WF1/backend).'
),
string(
name: 'CVSS_FAIL_THRESHOLD',
defaultValue: DEFAULT_CVSS_FAIL_THRESHOLD,
description: 'Seuil CVSS bloquant, utilisé uniquement quand JENKINS_HARD_GATE=true.'
),
string(
name: 'PFE_VALIDATION_CONTEXT',
defaultValue: '',
description: 'Corrélation de validation de PR, opaque et non secrète, fournie uniquement par la plateforme authentifiée.'
)
])
])

timeout(time: TIMEOUT_PIPELINE_HOURS, unit: 'HOURS') {
node {
Map buildStageStatus = [:]
Map docker = [
build_status: 'UNKNOWN', image_tag: null, push_status: 'NOT_ATTEMPTED',
provenance_status: 'NOT_ATTEMPTED', registry: null, repository: null,
published_tag: null, published_reference: null, digest: null
]
Map imagePublication = [published: false]
Map sonarTelemetry = [ceTaskId: null, analysisId: null]
Map tests = [status: 'UNKNOWN', total: null, failures: null, skipped: null, coverage: null]
Map semanticTestEvidence = null
String checkoutFullSha = null
String checkoutShortSha = null
String checkoutSourceUrl = null
Map prValidation = [:]
Map zap = [
launchAttempted: false, launchSucceeded: false, scanStarted: false,
podObserved: false, resultAvailable: false, technicalCode: null,
launchErrorType: null, launchExitCode: null, diagnosticMessage: null
]

Closure<String> zapStageStatus = { boolean stageEntered ->
if (!stageEntered) return 'NOT_RUN'
if (!zap.launchAttempted) return 'FAILED'
if (!zap.launchSucceeded) return 'FAILED'
if (!zap.resultAvailable) return 'FAILED'
return 'COMPLETED'
}

String imageTag = env.BUILD_NUMBER
boolean isPR = env.CHANGE_ID != null
String reportBase   = "${JENKINS_REPORT_ROOT}/${APPLICATION_NAME}/${env.BUILD_NUMBER}"
String n8nReportBase = "${N8N_REPORT_ROOT}/${APPLICATION_NAME}/${env.BUILD_NUMBER}"

boolean checkoutFailed = false
boolean zapStageEntered = false
boolean dockerfilePresent = false

prValidation = isPR ? prValidationContext(params.PFE_VALIDATION_CONTEXT) : [:]
if (isPR && !prValidation) {
error('PR_VALIDATION_CONTEXT_MISSING: lancez la validation de PR via l\'action authentifiée de la plateforme.')
}
boolean skipTests = isPR ? false : CONFIGURED_SKIP_TESTS

withCredentials([
string(credentialsId: CRED_SONAR_TOKEN, variable: 'SONAR_TOKEN'),
string(credentialsId: CRED_N8N_API_KEY, variable: 'N8N_API_KEY'),
string(credentialsId: CRED_NVD_API_KEY, variable: 'NVD_API_KEY')
]) {
stage('Init') {
env.PATH = "${tool 'M3'}/bin:${env.PATH}"
sh "mkdir -p '${reportBase}'"
                echo """============================================
 Job              : ${env.JOB_NAME}
 Build            : #${env.BUILD_NUMBER}
 App              : ${APPLICATION_NAME}
 Image            : ${IMAGE_NAME}:${imageTag}
 Is PR            : ${isPR}
 Jenkins reports  : ${reportBase}
============================================"""
}

try {
stage('Checkout') {
def scmVars = checkout(scm)
String capturedSha = sh(script: 'git rev-parse HEAD 2>/dev/null || true', returnStdout: true).trim()
checkoutFullSha = capturedSha ?: (scmVars?.GIT_COMMIT ?: null)
checkoutShortSha = checkoutFullSha ? checkoutFullSha.take(8) : null
checkoutSourceUrl = scmVars?.GIT_URL ?: null
if (isPR) {
String expected = (prValidation.expectedPrHeadSha ?: '').toString().toLowerCase()
if (!(expected ==~ /[a-f0-9]{40}/) || checkoutFullSha?.toLowerCase() != expected) {
error("PR_HEAD_SHA_MISMATCH: le checkout ne correspond pas à la cible de validation persistée")
}
}
echo "Commit: ${checkoutShortSha ?: 'unknown'}"
}
} catch (Throwable checkoutEx) {
checkoutFailed = true
currentBuild.result = 'FAILURE'
echo "Checkout failed: ${checkoutEx.message}"
}

Map stageFailure = null
if (!checkoutFailed) {
try {
Closure<Boolean> fileExistsRel = { String relativePath ->
String path = WORKING_DIRECTORY ? "${WORKING_DIRECTORY}/${relativePath}" : relativePath
return fileExists(path)
}
String buildType = null
if (fileExistsRel('pom.xml')) buildType = 'maven'
else if (fileExistsRel('build.gradle') || fileExistsRel('build.gradle.kts')) buildType = 'gradle'
else if (fileExistsRel('package.json')) buildType = 'node'
if (!buildType) {
error("Impossible de détecter un type de build supporté (pom.xml/build.gradle/package.json) sous '${WORKING_DIRECTORY ?: '.'}'.")
}

stage('Build') {
if (buildType != 'maven') {
error("buildType '${buildType}' n'est pas encore supporté par ce pipeline. Seuls les projets Maven sont pris en charge aujourd'hui.")
}
buildStageStatus['build'] = 'FAILED'
dir(WORKING_DIRECTORY ?: '.') {
catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                                sh """
                                    set -e
                                                                        mvn clean package -B -DskipTests=${skipTests}
                                """
buildStageStatus['build'] = 'SUCCESS'
}

if (skipTests) {
tests = [status: 'SKIPPED', total: 0, failures: 0, skipped: 0, coverage: null]
} else {
junit(testResults: 'target/surefire-reports/*.xml', allowEmptyResults: true)

List<Map> testcases = []
int total = 0, failuresCount = 0, errorsCount = 0, skippedCount = 0
boolean anyFileParsed = false

String listing = sh(
script: 'ls target/surefire-reports/TEST-*.xml 2>/dev/null || true',
returnStdout: true,
).trim()
if (listing) {
for (String path : listing.split('\n')) {
String trimmedPath = path?.trim()
if (!trimmedPath) continue
String xml
try { xml = readFile(trimmedPath) } catch (ignored) { continue }
def parsed
try { parsed = new XmlSlurper().parseText(xml) } catch (ignored) { continue }
anyFileParsed = true
total        += (parsed.@tests.text()    ?: '0') as Integer
failuresCount += (parsed.@failures.text()  ?: '0') as Integer
errorsCount   += (parsed.@errors.text()    ?: '0') as Integer
skippedCount  += (parsed.@skipped.text()   ?: '0') as Integer
parsed.testcase.each { tc ->
String status = 'PASS'
if (tc.failure.size() > 0) status = 'FAILURE'
else if (tc.error.size() > 0) status = 'ERROR'
else if (tc.skipped.size() > 0) status = 'SKIPPED'
testcases << [classname: tc.@classname.text(), name: tc.@name.text(), status: status]
}
}
}

if (anyFileParsed) {
int totalFailures = failuresCount + errorsCount
String rawCoverage = sh(
                                        script: '''
                                            set -e
                                            REPORT=target/site/jacoco/jacoco.xml
                                            [ -f "$REPORT" ] || exit 0
                                            grep -o '<counter type="LINE" missed="[0-9]*" covered="[0-9]*"/>' "$REPORT" \\
                                              | tail -1 \\
                                              | sed -E 's/.*missed="([0-9]+)" covered="([0-9]+)".*/\\1 \\2/'
                                        ''',
returnStdout: true
).trim()
Integer coverage = null
if (rawCoverage) {
def parts = rawCoverage.trim().tokenize(' \t')
if (parts.size() == 2) {
try {
int missed = parts[0] as Integer, covered = parts[1] as Integer
int lines = missed + covered
if (lines > 0) coverage = Math.round((covered * 100.0d) / lines) as Integer
} catch (ignored) {                           }
}
}
tests = [status: totalFailures > 0 ? 'FAILED' : 'SUCCESS', total: total, failures: totalFailures, skipped: skippedCount, coverage: coverage]
} else {
tests = [status: 'UNKNOWN', total: null, failures: null, skipped: null, coverage: null]
}
semanticTestEvidence = anyFileParsed ? [testcases: testcases] : null
}
}
}

if (SONAR_ENABLED) {
stage('SonarQube Analysis') {
buildStageStatus['sonar'] = 'FAILED'
dir(WORKING_DIRECTORY ?: '.') {
catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
withSonarQubeEnv(SONAR_ENV_NAME) {
String projectKey = APPLICATION_NAME
String prArgs = ''
if (isPR) {
String validationProjectKey = prValidation.validationSonarProjectKey
if (!validationProjectKey) error('SONAR_VALIDATION_PROJECT_KEY_MISSING')
projectKey = validationProjectKey
echo "SonarQube: mode COMMUNITY_EXACT_SHA, projet ${projectKey}"
} else {
echo 'SonarQube: mode branche standard'
}
                                        sh """
                                            set -e
                                            set +e
                                            mvn sonar:sonar -B \
                                              -DskipTests=true \
                                              -Djacoco.skip=true \
                                              -Dsonar.projectKey="${projectKey}" \
                                              -Dsonar.projectName="${projectKey}" \
                                              -Dsonar.host.url="${SONAR_HOST_URL}" \
                                              -Dsonar.token="\$SONAR_TOKEN" \
                                              ${prArgs} > sonar-analysis.log 2>&1
                                            SONAR_STATUS=\$?
                                            set -e
                                            cat sonar-analysis.log
                                            if [ "\$SONAR_STATUS" -ne 0 ]; then
                                              echo "SONAR_ANALYSIS_FAILED exit=\$SONAR_STATUS"
                                              exit "\$SONAR_STATUS"
                                            fi
                                        """
}
buildStageStatus['sonar'] = 'SUCCESS'
}
String ceTaskLine = sh(
script: "grep -oE 'ce/task\\?id=[A-Za-z0-9_-]+' sonar-analysis.log 2>/dev/null | tail -1 || true",
returnStdout: true
).trim()
if (ceTaskLine) {
sonarTelemetry.ceTaskId = ceTaskLine.replaceFirst(/^ce\/task\?id=/, '')
}
}
if (isPR) {
catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
String ceTaskId = String.valueOf(sonarTelemetry.ceTaskId ?: '')
if (!ceTaskId) error('SONAR_CE_TASK_ID_MISSING')
boolean resolved = false
for (int attempt = 1; attempt <= 60 && !resolved; attempt++) {
String raw = withEnv(["SONAR_CE_TASK_ID=${ceTaskId}", "SONAR_EXACT_HOST=${SONAR_HOST_URL}"]) {
sh(
                                                script: '''
                                                    set +x
                                                    curl -sf --max-time 10 -u "$SONAR_TOKEN:" \
                                                      "$SONAR_EXACT_HOST/api/ce/task?id=$SONAR_CE_TASK_ID"
                                                ''',
returnStdout: true
).trim()
}
Map task = ((Map) new groovy.json.JsonSlurperClassic().parseText(raw)).task as Map
String status = String.valueOf(task?.status ?: '').toUpperCase()
if (status == 'SUCCESS') {
String analysisId = String.valueOf(task.analysisId ?: '')
if (!analysisId) error('SONAR_ANALYSIS_ID_MISSING')
sonarTelemetry.analysisId = analysisId
resolved = true
} else if (['FAILED', 'CANCELED'].contains(status)) {
error("SONAR_CE_${status}")
} else {
sleep(time: 2, unit: 'SECONDS')
}
}
if (!resolved) error('SONAR_CE_TIMEOUT')
}
}
}
}

dockerfilePresent = DOCKERFILE_PATH ? fileExistsRel(DOCKERFILE_PATH) : fileExistsRel('Dockerfile')
if (dockerfilePresent) {
stage('Docker Build') {
docker.image_tag = "${IMAGE_NAME}:${imageTag}"
docker.build_status = 'FAILED'
dir(WORKING_DIRECTORY ?: '.') {
catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
if (!(checkoutFullSha ==~ /[a-fA-F0-9]{40}/)) {
error("OCI_REVISION_UNAVAILABLE: checkoutFullSha est absent ou n'est pas un SHA git complet sur 40 caractères -- refus de construire une image qualifiée de provenance.")
}
String fileArg = DOCKERFILE_PATH ? "-f '${DOCKERFILE_PATH}'" : ''
String safeSourceUrl = (checkoutSourceUrl ==~ /[A-Za-z0-9:\/._@-]{1,500}/) ? checkoutSourceUrl : null
String sourceLabelArg = safeSourceUrl ? "--label org.opencontainers.image.source=\"${safeSourceUrl}\" " : ''
                                    sh """
                                        set -e
                                        docker build ${fileArg} \\
                                            --label org.opencontainers.image.revision="${checkoutFullSha}" \\
                                            ${sourceLabelArg}--label org.opencontainers.image.created="\$(date -u +%Y-%m-%dT%H:%M:%SZ)" \\
                                            -t "${IMAGE_NAME}:${imageTag}" .
                                        docker tag "${IMAGE_NAME}:${imageTag}" "${IMAGE_NAME}:latest"

                                        echo "=== Docker image created ==="
                                        docker images | grep "${IMAGE_NAME}" || true
                                    """
docker.build_status = 'SUCCESS'
buildStageStatus['docker'] = 'SUCCESS'
}
docker.push_status = 'NOT_ATTEMPTED'
}
}
}

if (ACR_PUBLISH_ENABLED && dockerfilePresent && !isPR && docker.build_status == 'SUCCESS') {
stage('Publish Image (ACR)') {
boolean requirePublish = false
String commitSha = checkoutFullSha
if (!(commitSha ==~ /[a-fA-F0-9]{40}/)) {
docker.push_status = 'FAILED'
error('ACR_PUBLISH_REVISION_UNAVAILABLE: refus de publier un artefact dont le commit source ne peut pas être prouvé.')
}

Map lookup
try {
String response = withCredentials([string(credentialsId: CRED_INTERNAL_SECRET, variable: 'N8N_INTERNAL_SECRET')]) {
withEnv(["PFE_BACKEND_URL=${BACKEND_URL}", "PFE_JOB_NAME=${env.JOB_NAME}"]) {
sh(
returnStdout: true,
                                            script: '''
                                                set -e
                                                curl -sS -f --max-time 20 \
                                                  -H "X-Internal-Secret: $N8N_INTERNAL_SECRET" \
                                                  "$PFE_BACKEND_URL/api/projects/internal/by-job/$PFE_JOB_NAME"
                                            '''
)
}
}
def parsed = new groovy.json.JsonSlurperClassic().parseText((response ?: '[]').trim())
Map project = parsed instanceof List ? (parsed ? (parsed[0] as Map) : null) : (parsed instanceof Map ? (parsed as Map) : null)
lookup = [ok: true, value: project]
} catch (err) {
boolean credMissing = err.getClass().name.contains('CredentialNotFoundException') ||
String.valueOf(err?.message ?: '').contains('Could not find credentials')
if (!credMissing) throw err
lookup = [ok: false, reason: 'INTERNAL_SECRET_UNAVAILABLE']
}

Closure skipOrFail = { String reason, String explanation ->
if (requirePublish) {
docker.push_status = 'FAILED'
error("ACR_PUBLISH_REQUIRED_BUT_UNAVAILABLE (${reason}): ${explanation}.")
}
docker.push_status = 'NOT_CONFIGURED'
imagePublication = [published: false, reason: reason]
echo "Publication ACR ignorée (${reason}) : ${explanation}. Aucun registre ni credential n'est supposé à la place du projet."
}

if (!lookup.ok) {
skipOrFail(lookup.reason, 'le secret interne de la plateforme n\'est pas disponible sur ce contrôleur, la configuration du projet ne peut pas être lue')
} else {
Map project = lookup.value as Map
Map target = null
if (!project) {
target = [ok: false, reason: 'PROJECT_RECORD_UNAVAILABLE']
} else {
def azure = project.azureConfig
if (!(azure instanceof Map) || !azure) {
target = [ok: false, reason: 'ACR_NOT_CONFIGURED']
} else {
String registry = (azure.registry ?: '').toString().trim()
String repository = (azure.imageRepository ?: '').toString().trim()
String projectId = (project.id ?: '').toString().trim()
if (!registry || !repository) target = [ok: false, reason: 'ACR_NOT_CONFIGURED']
else if (!(registry ==~ /[A-Za-z0-9][A-Za-z0-9.-]{0,252}/)) target = [ok: false, reason: 'ACR_REGISTRY_INVALID']
else if (!(repository ==~ /[a-z0-9][a-z0-9._\/-]{0,254}/)) target = [ok: false, reason: 'ACR_REPOSITORY_INVALID']
else if (!(projectId ==~ /[0-9a-fA-F-]{36}/)) target = [ok: false, reason: 'PROJECT_ID_UNAVAILABLE']
else target = [ok: true, registry: registry, repository: repository, projectId: projectId]
}
}

if (!target.ok) {
skipOrFail(target.reason, 'aucun registre/dépôt ACR n\'est configuré pour ce projet')
} else {
String localRef = "${IMAGE_NAME}:${imageTag}"
String label = withEnv(["PFE_LOCAL_REF=${localRef}"]) {
sh(
returnStdout: true,
                                            script: '''
                                                set -e
                                                docker image inspect "$PFE_LOCAL_REF" \
                                                  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
                                            '''
)
}
String actualLabel = (label ?: '').trim()
if (!actualLabel) {
docker.push_status = 'FAILED'
error("ACR_PUBLISH_IMAGE_IDENTITY_REFUSED (LOCAL_IMAGE_REVISION_LABEL_MISSING): ${localRef} n'est pas prouvablement l'image construite par cette exécution.")
} else if (!actualLabel.equalsIgnoreCase(commitSha)) {
docker.push_status = 'FAILED'
error("ACR_PUBLISH_IMAGE_IDENTITY_REFUSED (LOCAL_IMAGE_REVISION_MISMATCH): label=${actualLabel}, attendu=${commitSha}.")
}

String build = (imageTag ?: '').trim()
String sha = commitSha.trim()
String tag = (build ==~ /\d{1,24}/) ? "${build}-${sha.substring(0, 12).toLowerCase()}" : null
if (!tag || !(tag ==~ /[A-Za-z0-9_][A-Za-z0-9._-]{0,127}/)) {
docker.push_status = 'FAILED'
error("ACR_PUBLISH_TAG_UNDERIVABLE: impossible de construire une étiquette unique à partir du build '${imageTag}' et de ce commit.")
}

Map pushed
try {
String remoteRef = "${target.registry}.azurecr.io/${target.repository}:${tag}"
int status = withCredentials([usernamePassword(credentialsId: CRED_ACR, usernameVariable: 'ACR_USERNAME', passwordVariable: 'ACR_PASSWORD')]) {
withEnv(["PFE_LOCAL_REF=${localRef}", "PFE_REMOTE_REF=${remoteRef}", "PFE_REGISTRY=${target.registry}"]) {
sh(
returnStatus: true,
                                                    script: '''
                                                        set -e
                                                        echo "$ACR_PASSWORD" | docker login "$PFE_REGISTRY.azurecr.io" \
                                                          --username "$ACR_USERNAME" --password-stdin >/dev/null 2>&1
                                                        docker tag "$PFE_LOCAL_REF" "$PFE_REMOTE_REF"
                                                        docker push "$PFE_REMOTE_REF"
                                                        docker logout "$PFE_REGISTRY.azurecr.io" >/dev/null 2>&1 || true
                                                    '''
)
}
}
pushed = [ok: true, value: status]
} catch (err) {
boolean credMissing = err.getClass().name.contains('CredentialNotFoundException') ||
String.valueOf(err?.message ?: '').contains('Could not find credentials')
if (!credMissing) throw err
pushed = [ok: false, reason: 'ACR_CREDENTIALS_UNAVAILABLE']
}

if (!pushed.ok) {
skipOrFail(pushed.reason, 'le credential ACR n\'est pas disponible sur ce contrôleur')
} else if (pushed.value != 0) {
docker.push_status = 'FAILED'
error("ACR_PUSH_FAILED: docker push vers ${target.registry}.azurecr.io/${target.repository}:${tag} a quitté avec le code ${pushed.value}.")
} else {
docker.push_status = 'SUCCESS'
docker.registry = target.registry
docker.repository = target.repository
docker.published_tag = tag
docker.published_reference = "${target.registry}.azurecr.io/${target.repository}:${tag}"
docker.provenance_status = 'PENDING'
echo "Image publiée : ${docker.published_reference} (enregistrement de la provenance différé jusqu'à ce que la plateforme ait ingéré ce build)"
imagePublication = [published: true, target: target, tag: tag, commitSha: commitSha, buildNumber: imageTag]
}
}
}
}
}

if (TRIVY_ENABLED && dockerfilePresent) {
stage('Trivy Scan') {
timeout(time: TIMEOUT_TRIVY_MINUTES, unit: 'MINUTES') {
catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
withEnv(["IMAGE_NAME=${IMAGE_NAME}", "IMAGE_TAG=${imageTag}", "REPORT_BASE=${reportBase}"]) {
                                        sh '''
                                            set -e
                                            BUILD="''' + env.BUILD_NUMBER + '''"
                                            TMP_DIR="/tmp/trivy-test-$BUILD"

                                            rm -rf "$TMP_DIR"
                                            mkdir -p "$TMP_DIR" "$REPORT_BASE"

                                            echo "=== Persistent Trivy cache ==="
                                            docker volume create trivy-cache >/dev/null || true

                                            echo "=== Exporting image ==="
                                            docker save "$IMAGE_NAME:$IMAGE_TAG" -o "$TMP_DIR/image.tar"

                                            echo "=== Updating Trivy DB ==="
                                            docker run --rm -v trivy-cache:/root/.cache \
                                              aquasec/trivy:latest image --download-db-only || true

                                            echo "=== Trivy container ==="
                                            TRIVY_CID=$(docker create -v trivy-cache:/root/.cache \
                                              --entrypoint sh aquasec/trivy:latest -c "sleep 1800")
                                            docker start "$TRIVY_CID" >/dev/null
                                            docker cp "$TMP_DIR/image.tar" "$TRIVY_CID:/image.tar"

                                            echo "=== Trivy scan ==="
                                            docker exec "$TRIVY_CID" trivy image \
                                              --input /image.tar \
                                              --scanners vuln,misconfig \
                                              --skip-db-update \
                                              --skip-java-db-update \
                                              --exit-code 0 \
                                              --format json \
                                              --severity CRITICAL,HIGH,MEDIUM \
                                              --no-progress \
                                              --timeout 30m \
                                              --output /trivy-report.json || true

                                            docker cp "$TRIVY_CID:/trivy-report.json" "$TMP_DIR/trivy-report.json" || true
                                            docker rm -f "$TRIVY_CID" >/dev/null 2>&1 || true

                                            if [ ! -s "$TMP_DIR/trivy-report.json" ]; then
                                              echo '{"SchemaVersion":2,"Results":[],"status":"trivy_report_missing"}' > "$TMP_DIR/trivy-report.json"
                                            fi

                                            cp "$TMP_DIR/trivy-report.json" "$REPORT_BASE/trivy-report.json"
                                            rm -rf "$TMP_DIR"

                                            echo "=== Final Trivy report ==="
                                            ls -lh "$REPORT_BASE/trivy-report.json" || true
                                        '''
}
}
}
}
}

if (OWASP_ENABLED) {
stage('OWASP Dependency Check') {
timeout(time: TIMEOUT_OWASP_MINUTES, unit: 'MINUTES') {
boolean owaspHardGate = params.JENKINS_HARD_GATE == null
? DEFAULT_JENKINS_HARD_GATE
: Boolean.valueOf(params.JENKINS_HARD_GATE.toString())
String owaspCvssThreshold = params.CVSS_FAIL_THRESHOLD?.toString()?.trim() ?: DEFAULT_CVSS_FAIL_THRESHOLD
String owaspWorkingDirectory = WORKING_DIRECTORY ?: '.'
String failCvss = owaspHardGate ? owaspCvssThreshold : '11'
echo "OWASP failBuildOnCVSS = ${failCvss}"
catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
dir(owaspWorkingDirectory) {
withEnv([
"REPORT_BASE=${reportBase}", "ODC_VERSION=${OWASP_DC_VERSION}",
"ODC_DATA=${OWASP_DC_DATA_DIR}", "FAIL_CVSS=${failCvss}"
]) {
                                            sh '''
                                                set -e
                                                mkdir -p "$REPORT_BASE" "$ODC_DATA"

                                                # Le secret ne doit JAMAIS atteindre un fichier : Jenkins exécute
                                                # ce script via `sh -xe`, qui écrit chaque commande DÉVELOPPÉE sur
                                                # stderr. Le settings.xml ci-dessous ne contient qu'une RÉFÉRENCE
                                                # (${env.NVD_API_KEY}), interpolée par Maven à l'exécution -- rien
                                                # de secret dans la ligne de commande, donc rien dans la trace, le
                                                # fichier, ni `ps`.
                                                SETTINGS_NVD="$REPORT_BASE/.odc-settings.xml"
                                                cat > "$SETTINGS_NVD" <<'ODC_SETTINGS'
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <profiles>
    <profile>
      <id>nvd-api-key-from-environment</id>
      <activation><activeByDefault>true</activeByDefault></activation>
      <properties>
        <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
      </properties>
    </profile>
  </profiles>
</settings>
ODC_SETTINGS

                                                # Fait brut, capturé sans condition : « l'étape a été atteinte »,
                                                # distinct de « un rapport existe » et de « le scan a réussi ».
                                                echo executed > "$REPORT_BASE/owasp.scanExecuted"

                                                set +e
                                                {
                                                  echo "=== Step 1: NVD update (clé API injectée via settings, jamais en ligne de commande) ==="
                                                  timeout 20m mvn org.owasp:dependency-check-maven:$ODC_VERSION:update-only \
                                                    -s "$SETTINGS_NVD" \
                                                    -DdataDirectory="$ODC_DATA" \
                                                    -DnvdApiDelay=2000 \
                                                    -DnvdMaxRetryCount=15 \
                                                    -DnvdValidForHours=168 \
                                                    -DretireJsAnalyzerEnabled=false \
                                                    -DnodeAuditAnalyzerEnabled=false \
                                                    -DossindexAnalyzerEnabled=false \
                                                    -B
                                                  echo $? > "$REPORT_BASE/owasp.nvdUpdate.exitcode"

                                                  echo "=== Step 2: dependency scan (cache local) ==="
                                                  timeout 20m mvn org.owasp:dependency-check-maven:$ODC_VERSION:check \
                                                    -Dformat=ALL \
                                                    -DfailBuildOnCVSS="$FAIL_CVSS" \
                                                    -DfailOnError=false \
                                                    -DdataDirectory="$ODC_DATA" \
                                                    -DautoUpdate=false \
                                                    -DretireJsAnalyzerEnabled=false \
                                                    -DnodeAuditAnalyzerEnabled=false \
                                                    -DossindexAnalyzerEnabled=false \
                                                    -B
                                                  echo $? > "$REPORT_BASE/owasp.exitcode"
                                                } > "$REPORT_BASE/owasp.log" 2>&1
                                                set -e

                                                echo "=== End of OWASP log ==="
                                                tail -80 "$REPORT_BASE/owasp.log" || true

                                                if [ -f target/dependency-check-report.json ]; then
                                                  cp target/dependency-check-report.json "$REPORT_BASE/dependency-check-report.json"
                                                else
                                                  echo '{"dependencies":[],"status":"owasp_report_missing"}' > "$REPORT_BASE/dependency-check-report.json"
                                                fi
                                                [ -f target/dependency-check-report.html ] && cp target/dependency-check-report.html "$REPORT_BASE/" || true
                                                [ -f target/dependency-check-report.xml ]  && cp target/dependency-check-report.xml  "$REPORT_BASE/" || true

                                                rm -f "$SETTINGS_NVD"

                                                echo "=== Final OWASP reports ==="
                                                ls -lh "$REPORT_BASE"/dependency-check-report.* || true
                                            '''
}
}
}
}
}
}

Closure<String> applicationServiceName = { String url ->
def m = (url =~ /^https?:\/\/([^:\/]+)/)
return m.find() ? m.group(1) : url
}
Closure checkKubernetesTarget = { String svcName ->
catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
withEnv(["KUBECONFIG=${KUBECONFIG_PATH}", "K8S_NAMESPACE=${K8S_NAMESPACE}", "ZAP_TARGET_SVC=${svcName}"]) {
                                sh '''
                                    set +e
                                    echo "=== kubectl (client) ==="
                                    kubectl version --client
                                    echo "=== Services ==="
                                    kubectl get svc  -n "$K8S_NAMESPACE"
                                    echo "=== Pods ==="
                                    kubectl get pods -n "$K8S_NAMESPACE"
                                    echo "=== Target service ==="
                                    kubectl get svc "$ZAP_TARGET_SVC" -n "$K8S_NAMESPACE"
                                    true
                                '''
}
}
}

if (!isPR && ZAP_ENABLED_ON_BRANCH_BUILDS) {
zapStageEntered = true
stage('Kubernetes Target Check') {
checkKubernetesTarget(applicationServiceName(ZAP_TARGET_URL))
}
stage('ZAP DAST Scan') {
timeout(time: TIMEOUT_ZAP_MINUTES, unit: 'MINUTES') {
catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
String zapPod = "zap-scan-${env.BUILD_NUMBER}"
withEnv([
"KUBECONFIG=${KUBECONFIG_PATH}", "K8S_NAMESPACE=${K8S_NAMESPACE}",
"REPORT_BASE=${reportBase}", "ZAP_POD=${zapPod}",
"ZAP_IMAGE=${ZAP_IMAGE}", "ZAP_TARGET_URL=${ZAP_TARGET_URL}"
]) {
sh 'mkdir -p "$REPORT_BASE"'

echo '=== Kubernetes access ==='
int k8sReachable = sh(returnStatus: true, script: 'kubectl get svc -n "$K8S_NAMESPACE" >/dev/null 2>&1')
if (k8sReachable != 0) {
sh 'echo \'{"site":[],"status":"zap_k8s_unreachable"}\' > "$REPORT_BASE/zap-report.json"'
zap.technicalCode = 'ZAP_K8S_UNREACHABLE'
zap.diagnosticMessage = 'Kubernetes API injoignable depuis Jenkins (kubectl get svc a échoué) -- le lancement de ZAP n\'a jamais été tenté.'
} else {
echo '=== Cleaning up previous pod ==='
sh 'kubectl delete pod "$ZAP_POD" -n "$K8S_NAMESPACE" --ignore-not-found=true || true'

echo '=== Launching ZAP pod (spider then active scan) ==='
zap.launchAttempted = true
                                            int launchExit = sh(returnStatus: true, script: '''
        set +e
        kubectl apply -n "$K8S_NAMESPACE" -f - > /tmp/zap-launch-stdout.log 2> /tmp/zap-launch-stderr.log <<PODSPEC_EOF
apiVersion: v1
kind: Pod
metadata:
  name: $ZAP_POD
  namespace: $K8S_NAMESPACE
spec:
  restartPolicy: Never
  containers:
    - name: $ZAP_POD
      image: $ZAP_IMAGE
      imagePullPolicy: IfNotPresent
      env:
        - name: ZAP_TARGET_URL
          value: "$ZAP_TARGET_URL"
      resources:
        requests:
          memory: "768Mi"
          cpu: "500m"
        limits:
          memory: "1536Mi"
          cpu: "1"
      command: ["sh", "-lc"]
      args:
        - |
          mkdir -p /zap/wrk && cd /zap/wrk

          # -silent : évite que ZAP 2.17.0 en mode -daemon ne bloque le thread
          # de démarrage en téléchargeant ~24 mises à jour d'add-ons avant que
          # l'API sur :8090 ne soit jamais liée (ZAP_NOT_READY_AFTER_720S).
          /zap/zap.sh -daemon -host 0.0.0.0 -port 8090 -silent \
            -config api.disablekey=true \
            -config api.addrs.addr.name=.* \
            -config api.addrs.addr.regex=true \
            -config database.recoverylog=false \
            > /zap/wrk/zap.log 2>&1 &

          python3 - <<PY
          import urllib.request, urllib.parse, time, json, sys, os

          base   = "http://127.0.0.1:8090"
          target = os.environ["ZAP_TARGET_URL"]

          def call(path, params=None, timeout=30):
              url = base + path
              if params:
                  url += "?" + urllib.parse.urlencode(params)
              return urllib.request.urlopen(url, timeout=timeout).read().decode()

          readiness_error = "no attempt made"
          for attempt in range(1, 241):
              try:
                  call("/JSON/core/view/version/", timeout=3)
                  print("ZAP_READY attempt=%d" % attempt); break
              except Exception as exc:
                  readiness_error = "%s: %s" % (type(exc).__name__, exc)
                  if attempt == 1 or attempt % 20 == 0:
                      print("ZAP_READINESS attempt=%d error=%s" % (attempt, readiness_error))
                  time.sleep(3)
          else:
              print("ZAP_NOT_READY_AFTER_720S last_error=%s" % readiness_error)
              log_tail = ""
              try:
                  log_tail = open("/zap/wrk/zap.log").read()[-2000:]
                  print("ZAP_LOG_TAIL:"); print(log_tail)
              except Exception as e2:
                  print("COULD_NOT_READ_LOG", e2)
              try:
                  open("/zap/wrk/zap.failed", "w").write(
                      "ZAP_NOT_READY_AFTER_720S last_error=%s\\n%s" % (readiness_error, log_tail))
              except Exception:
                  pass
              sys.exit(1)

          try:
              call("/JSON/core/action/accessUrl/", {"url": target, "followRedirects": "true"})
              print("TARGET_ACCESSED")
          except Exception as e:
              print("TARGET_ACCESS_ERROR", e)

          try:
              sid = json.loads(call("/JSON/spider/action/scan/", {"url": target, "recurse": "true"}))["scan"]
              while True:
                  st = json.loads(call("/JSON/spider/view/status/", {"scanId": sid}))["status"]
                  if int(st) >= 100: break
                  time.sleep(3)
              print("SPIDER_DONE")
          except Exception as e:
              print("SPIDER_ERROR", e)

          try:
              aid = json.loads(call("/JSON/ascan/action/scan/", {"url": target, "recurse": "true"}))["scan"]
              while True:
                  st = json.loads(call("/JSON/ascan/view/status/", {"scanId": aid}))["status"]
                  if int(st) >= 100: break
                  time.sleep(5)
              print("ACTIVE_SCAN_DONE")
          except Exception as e:
              print("ACTIVE_SCAN_ERROR", e)

          try:
              open("/zap/wrk/zap-report.json","w").write(call("/OTHER/core/other/jsonreport/", timeout=60))
              print("JSON_REPORT_CREATED")
          except Exception as e:
              print("JSON_REPORT_ERROR", e)
              open("/zap/wrk/zap-report.json","w").write(json.dumps({"site":[{"name":target,"alerts":[]}],"status":"zap_report_api_fallback"}))
          try:
              open("/zap/wrk/zap-report.html","w").write(call("/OTHER/core/other/htmlreport/", timeout=60))
              print("HTML_REPORT_CREATED")
          except Exception as e:
              print("HTML_REPORT_ERROR", e)

          try:
              if os.path.getsize("/zap/wrk/zap-report.json") > 0:
                  open("/zap/wrk/zap.done", "w").write("ok")
              else:
                  open("/zap/wrk/zap.failed", "w").write("ZAP_REPORT_EMPTY")
          except Exception as e:
              open("/zap/wrk/zap.failed", "w").write("ZAP_REPORT_MARKER_ERROR %s" % e)
          PY

          ls -lh /zap/wrk || true
          sleep 3600
PODSPEC_EOF
        exit $?
                                            ''')
zap.launchExitCode = launchExit

if (launchExit != 0) {
String stderrTail = sh(script: 'tail -c 2000 /tmp/zap-launch-stderr.log 2>/dev/null || true', returnStdout: true).trim()
zap.launchSucceeded = false
zap.launchErrorType = 'KUBECTL_RUN_FAILED'
zap.technicalCode = 'ZAP_POD_LAUNCH_FAILED'
zap.diagnosticMessage = stderrTail ?: "kubectl run exited ${launchExit}; voir la console Jenkins pour le détail."
echo "ZAP pod launch failed (exit ${launchExit}): ${stderrTail}"
sh 'echo \'{"site":[],"status":"zap_pod_launch_failed"}\' > "$REPORT_BASE/zap-report.json"'
sh 'kubectl delete pod "$ZAP_POD" -n "$K8S_NAMESPACE" --ignore-not-found=true || true'
} else {
zap.launchSucceeded = true
zap.scanStarted = true
zap.podObserved = true

echo '=== Waiting for ZAP report (up to 36 min) ==='
                                                sh '''
        set +e
        ZAP_OUTCOME="TIMEOUT"
        for i in $(seq 1 220); do
          if kubectl exec "$ZAP_POD" -n "$K8S_NAMESPACE" -- test -f /zap/wrk/zap.done 2>/dev/null; then
            echo "ZAP scan finished in-pod: report produced (zap.done)"; ZAP_OUTCOME="DONE"; break
          fi
          if kubectl exec "$ZAP_POD" -n "$K8S_NAMESPACE" -- test -f /zap/wrk/zap.failed 2>/dev/null; then
            echo "ZAP scan failed in-pod (zap.failed) -- NOT a completed scan"; ZAP_OUTCOME="FAILED"; break
          fi
          echo "Waiting for ZAP... $i"; sleep 10
        done
        echo "ZAP_INPOD_OUTCOME=$ZAP_OUTCOME"

        echo "=== ZAP logs ==="
        kubectl logs "$ZAP_POD" -n "$K8S_NAMESPACE" || true

        echo "=== In-pod failure marker (if any) ==="
        kubectl exec "$ZAP_POD" -n "$K8S_NAMESPACE" -- sh -c 'cat /zap/wrk/zap.failed 2>/dev/null' > "$REPORT_BASE/zap-inpod-failure.txt" 2>/dev/null || true
        cat "$REPORT_BASE/zap-inpod-failure.txt" 2>/dev/null || true

        echo "=== Retrieving reports ==="
        kubectl cp "$K8S_NAMESPACE/$ZAP_POD:/zap/wrk/zap-report.json" "$REPORT_BASE/zap-report.json" || true
        kubectl cp "$K8S_NAMESPACE/$ZAP_POD:/zap/wrk/zap-report.html" "$REPORT_BASE/zap-report.html" || true
        kubectl cp "$K8S_NAMESPACE/$ZAP_POD:/zap/wrk/zap.log"        "$REPORT_BASE/zap.log"        || true

        if [ ! -s "$REPORT_BASE/zap-report.json" ]; then
          echo '{"site":[],"status":"zap_report_missing"}' > "$REPORT_BASE/zap-report.json"
        fi
        true
                                                '''
boolean reportUsable = sh(
returnStatus: true,
script: 'test -s "$REPORT_BASE/zap-report.json" && ! grep -q "zap_report_missing\\|zap_k8s_unreachable\\|zap_pod_launch_failed" "$REPORT_BASE/zap-report.json"'
) == 0
zap.resultAvailable = reportUsable
if (!reportUsable) {
String inPodFailure = sh(script: 'cat "$REPORT_BASE/zap-inpod-failure.txt" 2>/dev/null || true', returnStdout: true).trim()
zap.technicalCode = 'ZAP_SCAN_POD_DISAPPEARED'
zap.diagnosticMessage = inPodFailure ?
('ZAP pod créé et scan lancé, mais aucun rapport exploitable produit. Marqueur d\'échec in-pod : ' + inPodFailure.replaceAll('\\s+', ' ').take(400)) :
'ZAP pod créé et scan lancé, mais aucun rapport exploitable récupéré et le pod n\'a laissé aucun marqueur d\'échec -- le pod n\'était plus joignable au moment de la récupération.'
}

echo '=== Cleaning up ZAP pod ==='
sh 'kubectl delete pod "$ZAP_POD" -n "$K8S_NAMESPACE" --ignore-not-found=true || true'
}
}
}
}
}
}
} else if (!isPR) {
stage('Kubernetes Target Check') {
checkKubernetesTarget(applicationServiceName(ZAP_TARGET_URL))
}
}
} catch (Throwable stageEx) {
currentBuild.result = 'FAILURE'
stageFailure = [technicalCode: 'PIPELINE_STAGE_ERROR', message: stageEx.message ?: stageEx.class.name]
echo "Stage execution failed: ${stageEx.message}"
}
}

try {
timeout(time: TIMEOUT_POST_REPORT_MINUTES, unit: 'MINUTES') {
try {
String buildStatus = currentBuild.currentResult ?: 'SUCCESS'
String event
if (isPR) {
event = 'pr_validation'
} else {
event = buildStatus == 'SUCCESS'  ? 'pipeline_success'
: buildStatus == 'UNSTABLE' ? 'pipeline_unstable'
:                             'pipeline_failed'
}

String branch = env.GIT_BRANCH?.replaceAll('origin/', '') ?: 'main'
String commit = checkoutShortSha ?: (env.GIT_COMMIT?.take(8)) ?: 'unknown'

Map technicalFailure = null
if (checkoutFailed) {
buildStageStatus = [build: 'NOT_REACHED', tests: 'NOT_REACHED', sonar: 'NOT_REACHED',
trivy: 'NOT_REACHED', owasp: 'NOT_REACHED', zap: 'NOT_REACHED', docker: 'NOT_REACHED']
tests = [status: 'NOT_REACHED', total: null, failures: null, skipped: null, coverage: null]
semanticTestEvidence = null
docker.build_status = 'NOT_REACHED'
technicalFailure = [
phase: 'SCM_CHECKOUT', technicalCode: 'SCM_CHECKOUT_NETWORK_FAILURE',
message: 'Git checkout did not complete -- see Jenkins console for the underlying git/network error.'
]
} else if (stageFailure) {
technicalFailure = [phase: 'PIPELINE_STAGE', technicalCode: stageFailure.technicalCode, message: stageFailure.message]
}

Closure<Boolean> reportAvailable = { String relativePath ->
if (!reportBase) return false
try { return sh(script: "test -s '${reportBase}/${relativePath}'", returnStatus: true) == 0 } catch (ignored) { return false }
}
Closure<String> readTextFile = { String filePath ->
try { return sh(script: "cat '${filePath}' 2>/dev/null || true", returnStdout: true).trim() } catch (ignored) { return '' }
}
Closure<Boolean> grepMarker = { String filePath, String pattern ->
if (!filePath) return false
try { return sh(script: "grep -q '${pattern}' '${filePath}'", returnStatus: true) == 0 } catch (ignored) { return false }
}

boolean trivyAvailable = reportAvailable('trivy-report.json')
boolean zapAvailable = reportAvailable('zap-report.json')
boolean owaspAvailable = reportAvailable('dependency-check-report.json')
boolean owaspScanExecuted = reportAvailable('owasp.scanExecuted')
String owaspExitRaw = readTextFile("${reportBase}/owasp.exitcode")
Integer owaspToolExitStatus = (owaspExitRaw ==~ /\d+/) ? (owaspExitRaw as Integer) : null
Boolean owaspPolicyPassed = owaspToolExitStatus == null ? null : (owaspToolExitStatus == 0)
String nvdExitRaw = readTextFile("${reportBase}/owasp.nvdUpdate.exitcode")
Integer nvdUpdateExitStatus = (nvdExitRaw ==~ /\d+/) ? (nvdExitRaw as Integer) : null
Boolean nvdUpdateSucceeded = nvdUpdateExitStatus == null ? null : (nvdUpdateExitStatus == 0)

if (!checkoutFailed) {
buildStageStatus['tests'] = tests.status
buildStageStatus['trivy'] = trivyAvailable ? 'COMPLETED' : 'UNKNOWN'
buildStageStatus['owasp'] = owaspAvailable ? 'COMPLETED' : 'UNKNOWN'
buildStageStatus['zap'] = zapStageStatus(zapStageEntered)
buildStageStatus['build'] = buildStageStatus['build'] ?: 'UNKNOWN'
buildStageStatus['sonar'] = buildStageStatus['sonar'] ?: 'UNKNOWN'
buildStageStatus['docker'] = docker.build_status
}

boolean criticalTrivy = trivyAvailable && grepMarker("${reportBase}/trivy-report.json", 'CRITICAL')
boolean criticalOwasp = owaspAvailable && grepMarker("${reportBase}/owasp.log", 'CVSS score greater than or equal to')
String severityHint = buildStatus == 'FAILURE'          ? 'HIGH'
: (criticalTrivy || criticalOwasp) ? 'HIGH'
: buildStatus == 'UNSTABLE'         ? 'MEDIUM'
:                                    'LOW'

Map payloadObject = [
event: event, job: env.JOB_NAME, build_number: env.BUILD_NUMBER, build_url: env.BUILD_URL,
logs_url: "${env.BUILD_URL}consoleText", branch: branch, commit: commit, status: buildStatus,
severity_hint: severityHint, duration_ms: currentBuild.duration,
buildStageStatus: buildStageStatus, technicalFailure: technicalFailure,
pull_request: env.CHANGE_ID ? [number: env.CHANGE_ID, branch: env.CHANGE_BRANCH, target: env.CHANGE_TARGET, url: env.CHANGE_URL, title: env.CHANGE_TITLE] : null,
reports: [
jenkinsBasePath: reportBase, basePath: n8nReportBase,
trivyPath: "${n8nReportBase}/trivy-report.json", zapPath: "${n8nReportBase}/zap-report.json",
owaspPath: "${n8nReportBase}/dependency-check-report.json",
available: [trivy: trivyAvailable, zap: zapAvailable, owasp: owaspAvailable]
],
tests: tests,
semanticEvidence: semanticTestEvidence ? [reportFormat: 'JUNIT_XML', payload: [testcases: semanticTestEvidence.testcases]] : null,
sonar: [project_key: APPLICATION_NAME, dashboard_url: "${SONAR_HOST_URL}/dashboard?id=${APPLICATION_NAME}", ceTaskId: sonarTelemetry.ceTaskId, analysisId: sonarTelemetry.analysisId],
docker: [
image: "${IMAGE_NAME}:${imageTag}", build_status: docker.build_status, image_tag: docker.image_tag,
push_status: docker.push_status, provenance_status: docker.provenance_status, registry: docker.registry,
repository: docker.repository, published_tag: docker.published_tag, published_reference: docker.published_reference,
digest: docker.digest
],
owasp: [scanExecuted: owaspScanExecuted, reportAvailable: owaspAvailable, toolExitStatus: owaspToolExitStatus, policyPassed: owaspPolicyPassed, nvdUpdateExitStatus: nvdUpdateExitStatus, nvdUpdateSucceeded: nvdUpdateSucceeded],
kubernetes: [namespace: K8S_NAMESPACE, target: ZAP_TARGET_URL],
zap: zapStageEntered ? zap : null
]

if (isPR) {
Closure<String> stageStatusOf = { String key ->
String value = String.valueOf(buildStageStatus[key] ?: (key == 'tests' ? tests.status : 'UNKNOWN')).toUpperCase()
return ['SUCCESS','COMPLETED','PASSED'].contains(value) ? 'PASSED' : value
}
payloadObject.requiredStages = [
[stage:'build', required:true, status:stageStatusOf('build')],
[stage:'tests', required:true, status:stageStatusOf('tests')],
[stage:'sonar', required:true, status:stageStatusOf('sonar')],
[stage:'docker', required:dockerfilePresent, status:stageStatusOf('docker')],
[stage:'trivy', required:dockerfilePresent && TRIVY_ENABLED, status:stageStatusOf('trivy')],
[stage:'owasp', required:OWASP_ENABLED, status:stageStatusOf('owasp')],
[stage:'zap', required:false, status:stageStatusOf('zap')]
]
}

if (event in ['pipeline_success', 'pipeline_unstable', 'pipeline_failed']) {
boolean exactShaValid = checkoutFullSha != null && (checkoutFullSha ==~ /[a-fA-F0-9]{40}/)
if (exactShaValid) {
payloadObject.commitSha = checkoutFullSha
} else {
payloadObject.commitSha = null
payloadObject.commitShaDiagnostic = 'APPLICATION_CHECKOUT_SHA_UNAVAILABLE_OR_INVALID'
}
}
if (isPR) {
payloadObject.putAll([
sonarAnalysisMode: SONAR_ANALYSIS_MODE,
baseSonarProjectKey: prValidation.baseSonarProjectKey,
validationSonarProjectKey: prValidation.validationSonarProjectKey,
validationRequestId: prValidation.validationRequestId, projectId: prValidation.projectId,
incidentId: prValidation.incidentId, fixRequestId: prValidation.fixRequestId,
requestId: prValidation.fixRequestId, batchId: prValidation.batchId, batchKey: prValidation.batchKey,
attemptCount: prValidation.attemptCount, repository: prValidation.repository,
prNumber: prValidation.prNumber, prHeadBranch: prValidation.prHeadBranch,
expectedPrHeadSha: prValidation.expectedPrHeadSha, checkoutSha: checkoutFullSha,
jenkinsJob: prValidation.jenkinsJob, prValidationJob: prValidation.prValidationJob,
jenkinsBuildNumber: env.BUILD_NUMBER, jenkinsBuildUrl: env.BUILD_URL, jenkinsStatus: buildStatus,
ceTaskId: sonarTelemetry.ceTaskId, analysisId: sonarTelemetry.analysisId
])
}

String payloadJson = groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(payloadObject))
writeFile file: 'jenkins-webhook-payload.json', text: payloadJson
if (reportBase) {
withEnv(["REPORT_BASE=${reportBase}"]) {
sh 'mkdir -p "$REPORT_BASE" && cp jenkins-webhook-payload.json "$REPORT_BASE/payload.json" || true'
}
}
boolean notified = false
for (int attempt = 1; attempt <= 3 && !notified; attempt++) {
echo "n8n notification: attempt ${attempt}/3"
int code = withEnv(["N8N_WEBHOOK_URL=${N8N_WEBHOOK_URL}"]) {
sh(
returnStatus: true,
                                    script: '''
                                        curl -sS -o /tmp/n8n_resp.txt -w "%{http_code}" \
                                          -X POST "$N8N_WEBHOOK_URL" \
                                          -H "Content-Type: application/json" \
                                          -H "X-API-Key: $N8N_API_KEY" \
                                          --data-binary @jenkins-webhook-payload.json \
                                          --max-time 20 > /tmp/n8n_code.txt 2>/tmp/n8n_err.txt
                                        CODE=$(cat /tmp/n8n_code.txt)
                                        echo "HTTP $CODE"
                                        case "$CODE" in 2*) exit 0 ;; *) exit 1 ;; esac
                                    '''
)
}
if (code == 0) {
notified = true
echo 'n8n notified successfully'
} else {
echo "Attempt ${attempt} failed"
sleep(time: 5, unit: 'SECONDS')
}
}
if (!notified) {
echo 'ERROR: n8n unreachable after 3 attempts.'
if (currentBuild.currentResult == 'SUCCESS') currentBuild.result = 'UNSTABLE'
}
} catch (ex) {
echo "Reporting failed (non-fatal, original build result preserved): ${ex.message}"
}
}
} finally {
try {
deleteDir()
} catch (cleanupEx) {
echo "Workspace cleanup skipped (non-fatal): ${cleanupEx.message}"
}
}
}
}
}
