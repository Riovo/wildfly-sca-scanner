# AGENTS.md

This file provides context for AI agents working in this repository. For full project documentation, see [README.md](README.md).

## Project Overview

This repository contains GitHub Actions workflows and supporting tools that perform daily SCA (Software Composition Analysis) scanning of WildFly application server distributions using OWASP Dependency Check and Trivy. The primary artifacts are workflow YAML files, shell scripts, a Java-based suppression management tool, and a canonical YAML suppression file.

## Repository Layout

```
.github/workflows/          GitHub Actions workflow definitions
scripts/                    Shell scripts for tool download and setup
suppressions-tool/          Java/Maven tool for suppression management
  src/main/java/            Source: model, validator, converters, resolver
  src/test/java/            JUnit 5 test suite
  pom.xml                   Maven build (Java 17, fat JAR via shade plugin)
suppressions/               Canonical YAML suppression rules
  suppressions.yaml         Source of truth for all suppression rules
  .trivyignore.yaml         Generated Trivy format (committed, kept in sync by CI)
owasp-suppressions/         OWASP Dependency Check suppression rules
  owasp-suppressions.xml    The original XML suppression file
```

## Key Concepts

- **Workflows** run daily in a timed sequence (tools → database → provisioning → scan). See the README for the full schedule and workflow descriptions.
- **Scanned versions** are defined in `matrix.version` arrays inside individual workflow YAML files — there is no central version list. The scan matrix in `scan-wildfly.yaml` must stay in sync with the provisioning workflows.
- **Tool versions** (Dependency Check, Galleon) are controlled via GitHub repository variables, not files in this repo.
- **Suppressions** are managed in `suppressions/suppressions.yaml` (the canonical source of truth). Scanner-specific formats (Trivy `.trivyignore.yaml`, OWASP DC XML) are generated from this file by the Java tool. CPE suppressions fix incorrect library-to-product mappings. CVE suppressions silence specific triaged vulnerabilities and typically carry an `until` date for periodic re-evaluation.
- **Two-pass Trivy scan**: A preliminary scan discovers packages, then the resolver matches suppression regex patterns against real PURLs to produce a resolved `.trivyignore.yaml` with exact PURLs (no global suppressions).

## Working on Suppressions

When adding or modifying suppressions:

1. Edit `suppressions/suppressions.yaml` (the canonical source).
2. Include `notes` explaining why the suppression is valid, with references to tracking issues (JIRA keys like `WFLY-*` or GitHub issue numbers).
3. For CVE suppressions, set an `until` date (typically 12 months out) so the suppression is periodically re-evaluated.
4. CPE suppressions that correct permanent GAV-to-CPE mismatches generally do not need an `until` date.
5. Regenerate derived files: `java -jar suppressions-tool/target/suppressions-tool-1.0.0-SNAPSHOT.jar convert-trivy` and `convert-owaspdc`.
6. CI validates the canonical YAML and checks that generated files are in sync on every push.

## Working on the Suppressions Tool

The Java tool under `suppressions-tool/` manages the canonical YAML format:

```bash
cd suppressions-tool && mvn package    # Build + test
java -jar target/suppressions-tool-1.0.0-SNAPSHOT.jar validate <yaml>
java -jar target/suppressions-tool-1.0.0-SNAPSHOT.jar convert-trivy <yaml> <output>
java -jar target/suppressions-tool-1.0.0-SNAPSHOT.jar convert-owaspdc <yaml> <output>
java -jar target/suppressions-tool-1.0.0-SNAPSHOT.jar resolve <yaml> <trivy.json> <output>
java -jar target/suppressions-tool-1.0.0-SNAPSHOT.jar check-drift <xml> <yaml>
java -jar target/suppressions-tool-1.0.0-SNAPSHOT.jar migrate <xml> <output-yaml>
```

## Working on Versions

When updating scanned WildFly versions, edit the `matrix.version` arrays in the relevant provisioning workflow files and `scan-wildfly.yaml`. See the "Adding or Removing WildFly Versions" section in the README for the full procedure and naming conventions.
