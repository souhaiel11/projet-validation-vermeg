# ════════════════════════════════════════════════════════════════════════════
#  PROJET DE VALIDATION VERMEG — image de démonstration
#  APPLICATION INTENTIONNELLEMENT VULNÉRABLE — BANC D'ESSAI UNIQUEMENT.
#  Ne jamais publier ce service sur un port exposé à Internet.
#
#  ⚠ CE FICHIER CONTIENT DES DÉFAUTS DÉLIBÉRÉS.
#  Ils constituent la matière du scénario VAL-K (optimiseur Dockerfile).
#  Chacun est repéré par un marqueur « DÉFAUT VAL-Kxx » et recensé dans
#  docs/MATRICE_VALIDATION.md. Ne pas les corriger dans le dépôt : leur
#  correction est précisément ce que la plateforme doit proposer.
# ════════════════════════════════════════════════════════════════════════════

# ── Étape 1 — construction ──────────────────────────────────────────────────
# DÉFAUT VAL-K01 — image de base désignée par un TAG et non par un DIGEST.
# Un tag est mutable : le même commit peut produire deux images différentes à
# deux dates différentes, et les résultats de scan varient sans qu'aucune ligne
# de code n'ait changé.
FROM maven:3.9.5-eclipse-temurin-17 AS builder
WORKDIR /build

# DÉFAUT VAL-K02 — ADD au lieu de COPY pour un contenu local.
# ADD possède des comportements implicites (extraction d'archives, récupération
# d'URL) dont ce build n'a pas besoin. COPY exprime exactement l'intention.
#
# DÉFAUT VAL-K03 — le contexte entier est copié avant la résolution des
# dépendances. La couche de dépendances Maven est donc invalidée dès qu'un
# fichier source change, alors que copier pom.xml d'abord la garderait en cache.
COPY pom.xml /build/
RUN mvn -B dependency:go-offline
COPY src /build/src

# DÉFAUT VAL-K04 — l'image est construite à partir de code NON TESTÉ.
# `-DskipTests` permet de produire une image depuis un code dont la suite de
# tests échoue. `mvn -B -ntp clean verify` fermerait ce chemin.
RUN mvn -B -ntp clean verify

# ── Étape 2 — exécution ─────────────────────────────────────────────────────
# DÉFAUT VAL-K05 — image d'exécution périmée, désignée par un tag.
# 17.0.9_9 date d'octobre 2023 : sa couche Alpine porte des vulnérabilités de
# paquets système (zlib, busybox, openssl selon la base de Trivy). Ces constats
# sont en DÉTECTION SEULE pour la plateforme : la chaîne de remédiation n'a
# aucune stratégie de version d'image.
FROM eclipse-temurin:17.0.9_9-jre-alpine

LABEL org.opencontainers.image.title="projet-validation-vermeg" \
      org.opencontainers.image.description="PROJET DE VALIDATION INTENTIONNELLEMENT VULNERABLE — BANC D'ESSAI UNIQUEMENT ; donnees synthetiques" \
      org.opencontainers.image.vendor="PFE 2026 — validation de la plateforme DevSecOps"

WORKDIR /app

# DÉFAUT VAL-K06 — valeur sensible inscrite dans une couche d'image.
# Une variable d'environnement définie à la construction reste lisible dans
# l'historique de l'image par quiconque peut la tirer du registre, même si une
# couche ultérieure l'écrase. La valeur ci-dessous est factice et n'ouvre aucun
# accès ; le défaut porte sur le mécanisme, pas sur le secret.
ARG VALIDATION_API_TOKEN
ENV VALIDATION_API_TOKEN=${VALIDATION_API_TOKEN}

# DÉFAUT VAL-K07 — `apk add` sans `--no-cache` : l'index des paquets reste dans
# l'image et l'alourdit inutilement.
# DÉFAUT VAL-K08 — deux instructions RUN là où une seule suffirait : deux
# couches au lieu d'une, pour un gain nul.
RUN apk add --no-cache curl wget

# MÉCANISME, PAS DÉTAIL D'EMPAQUETAGE — ne pas retirer.
# Les jars de dépendances sont placés dans l'image parce que Trivy scanne
# l'IMAGE, pas le dépôt. Sans eux, son analyseur Java ne voit rien et la
# fermeture de sécurité confirmée par deux scanners devient indémontrable.
COPY --from=builder /build/target/runtime/ /app/dependencies/
# DÉFAUT VAL-K11 : le JAR Maven inclut la version 1.0.0 dans son nom.
COPY --from=builder /build/target/projet-validation-vermeg-1.0.0.jar /app/application.jar

EXPOSE 8080

# DÉFAUT VAL-K09 — aucune directive USER : le conteneur s'exécute en root.
# La bonne pratique est un identifiant numérique non privilégié, par exemple
# `USER 65532:65532`, qui ne dépend pas de l'existence d'un compte dans l'image.

# DÉFAUT VAL-K10 — aucune HEALTHCHECK, alors que l'application expose un
# contrat de santé déterministe sur /health.

RUN addgroup -S appgroup && adduser -S -D -G appgroup appuser
USER appuser
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:8080/actuator/health || exit 1
ENTRYPOINT ["java", "-Dapp.bind=0.0.0.0", \
            "-cp", "/app/application.jar:/app/dependencies/*", \
            "tn.vermeg.validation.App"]