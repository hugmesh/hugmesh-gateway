# HugMesh Gateway — developer Makefile.
#
# `make pentest` runs the SAME OWASP pen-test posture the CI `pentest` stage
# runs (see .gitlab-ci.yml + the generator's tests/pentest/ci/pentest-stage.
# gitlab-ci.yml), but locally, so a dev can reproduce CI findings before push:
#   * SCA  : OWASP Dependency-Check over this repo (mirrors `pentest:sca`).
#   * DAST : delegates to the shared harness (run-pentest.sh, mirrors
#            `pentest:dast`) against $DAST_TARGET_URL when one is set.
# It is intentionally non-fatal when tooling / a target is missing, so it is
# safe to run on any machine.

# Path to the generator's pen-test harness checkout (override if vendored).
GENERATOR_DIR     ?= ../hugmesh-generator
PENTEST_HARNESS   ?= $(GENERATOR_DIR)/tests/pentest
# CVSS threshold mirrors the inline P2-1 self-scan posture.
SCA_FAIL_CVSS     ?= 9
# Java image used by CI to run the Maven dependency-check goal hermetically.
JDK_IMAGE         ?= eclipse-temurin:25-jdk-noble

.PHONY: pentest pentest-sca pentest-dast

## Run the local pen-test self-scan (SCA always; DAST when DAST_TARGET_URL set).
pentest: pentest-sca pentest-dast

## SCA: OWASP Dependency-Check over this repo (mirrors CI `pentest:sca`).
pentest-sca:
	@echo "==> pentest-sca: OWASP Dependency-Check (failOnCVSS=$(SCA_FAIL_CVSS))"
	@if command -v docker >/dev/null 2>&1; then \
		echo "    (running via $(JDK_IMAGE), matching CI)"; \
		docker run --rm \
			-v "$(CURDIR):/workspace" \
			-v "$(CURDIR)/.dep-check-data:/dep-check-data" \
			-w /workspace \
			--entrypoint "" \
			$(JDK_IMAGE) \
			./mvnw org.owasp:dependency-check-maven:check \
				-Dformat=HTML,JSON \
				-DfailBuildOnCVSS=$(SCA_FAIL_CVSS) \
				-DdataDirectory=/dep-check-data \
				-DautoUpdate=true \
				-B \
		|| echo "    !! Dependency-Check reported findings or failed; see target/dependency-check-report.html"; \
	elif [ -x ./mvnw ]; then \
		echo "    (docker not found; running ./mvnw directly)"; \
		./mvnw org.owasp:dependency-check-maven:check \
			-Dformat=HTML,JSON \
			-DfailBuildOnCVSS=$(SCA_FAIL_CVSS) \
			-DautoUpdate=true \
			-B \
		|| echo "    !! Dependency-Check reported findings or failed; see target/dependency-check-report.html"; \
	else \
		echo "    !! neither docker nor ./mvnw available; skipping SCA (install one to run it)."; \
	fi

# DAST: delegate to the shared harness, exactly as CI `pentest:dast` does
# (run-pentest.sh --env compose --scan baseline --pipeline main). The harness
# resolves its target from the env profile's ZAP_TARGET (the front door it
# stands up); set $DAST_TARGET_URL to override the profile host/port for a dev
# run (it is mapped onto the profile's host/port override knobs). Only attempt
# DAST when $DAST_TARGET_URL is set, since it needs a reachable stack.
pentest-dast:
	@echo "==> pentest-dast: ZAP DAST baseline via the shared harness"
	@if [ -z "$$DAST_TARGET_URL" ]; then \
		echo "    DAST_TARGET_URL not set; skipping DAST. To run it (mirrors CI pentest:dast):"; \
		echo "      DAST_TARGET_URL=https://branda.localtest.me:8443 make pentest-dast"; \
	elif [ -f "$(PENTEST_HARNESS)/run-pentest.sh" ]; then \
		echo "    delegating to $(PENTEST_HARNESS)/run-pentest.sh (ZAP_TARGET=$$DAST_TARGET_URL)"; \
		ZAP_TARGET="$$DAST_TARGET_URL" \
		bash "$(PENTEST_HARNESS)/run-pentest.sh" --env compose --scan baseline --pipeline main \
		|| echo "    !! DAST harness reported findings or failed; see out/pentest/."; \
	else \
		echo "    harness not found at $(PENTEST_HARNESS)/run-pentest.sh."; \
		echo "    Clone it, e.g.:"; \
		echo "      git clone https://github.com/hugmesh-net/hugmesh-generator $(GENERATOR_DIR)"; \
		echo "    then re-run, or point GENERATOR_DIR/PENTEST_HARNESS at your checkout. Equivalent command:"; \
		echo "      bash $(PENTEST_HARNESS)/run-pentest.sh --env compose --scan baseline --pipeline main"; \
	fi
