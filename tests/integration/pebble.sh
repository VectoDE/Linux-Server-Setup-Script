# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

# Pebble, the ACME test server of Let's Encrypt, inside the test target: the tls module gets real certificates from it
# without a public domain. PEBBLE_VA_ALWAYS_VALID skips the challenge check, so any host name works.
# Sourced by run.sh, which provides in_target. Every download is pinned by its SHA-256.

PEBBLE_VERSION=v2.10.1
# Commit of the tag v2.10.1, for the CA certificate and the TLS certificate of the server (test files of the release).
PEBBLE_COMMIT=b1e1ca4f3c30abb64111adaca4544bc5374cc306
PEBBLE_SHA256_amd64=4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed
PEBBLE_SHA256_arm64=b53fd072a69eb7692451de4e8b0667e0bdf5cccd7e36fc51b8eaf2fcc135ed9f
PEBBLE_FILES="0c502e52627ff7de972c7e9e065640103b4589b4e2d23d3fcf21bef1e3c8c67c test/certs/pebble.minica.pem
c87fb918d9bac8db11aa54493b5f0cf6e0725a3fe73f617d1c64737e1ab4caf9 test/certs/localhost/cert.pem
0977979255b0e0721c17335c056b627f66a43cf56e5a52f3cda81fb111ecf00e test/certs/localhost/key.pem"
# Where the target keeps Pebble; LSS_TLS_CA_BUNDLE in settings.conf points at the CA certificate here.
PEBBLE_DIR=/etc/lss-pebble
# The CA bundle LSS_TLS_CA_BUNDLE points at: the minica certificate of the API and the roots Pebble issues from.
PEBBLE_BUNDLE=${PEBBLE_DIR}/ca-bundle.pem

pebble_start() {
	local arch sum work file
	case $(in_target 'uname -m') in
	x86_64) arch=amd64 ;;
	aarch64) arch=arm64 ;;
	*)
		echo "Pebble has no build for $(in_target 'uname -m')." >&2
		return 1
		;;
	esac
	sum=PEBBLE_SHA256_${arch}
	work=$(mktemp -d)
	curl -fsSL --retry 3 -o "${work}/pebble.tar.gz" \
		"https://github.com/letsencrypt/pebble/releases/download/${PEBBLE_VERSION}/pebble-linux-${arch}.tar.gz"
	printf '%s  %s\n' "${!sum}" "${work}/pebble.tar.gz" | sha256sum --quiet -c -
	tar -xzf "${work}/pebble.tar.gz" -C "${work}"
	in_target "install -d -m 0755 ${PEBBLE_DIR} && cat > ${PEBBLE_DIR}/pebble && chmod 0755 ${PEBBLE_DIR}/pebble" \
		<"${work}/pebble-linux-${arch}/linux/${arch}/pebble"
	while read -r sum file; do
		curl -fsSL --retry 3 -o "${work}/${file##*/}" "https://raw.githubusercontent.com/letsencrypt/pebble/${PEBBLE_COMMIT}/${file}"
		printf '%s  %s\n' "${sum}" "${work}/${file##*/}" | sha256sum --quiet -c -
		in_target "cat > ${PEBBLE_DIR}/${file##*/}" <"${work}/${file##*/}"
	done <<<"${PEBBLE_FILES}"
	rm -rf -- "${work}"
	in_target "cat > ${PEBBLE_DIR}/config.json" <<EOF
{
  "pebble": {
    "listenAddress": "127.0.0.1:14000",
    "managementListenAddress": "127.0.0.1:15000",
    "certificate": "${PEBBLE_DIR}/cert.pem",
    "privateKey": "${PEBBLE_DIR}/key.pem",
    "httpPort": 80,
    "tlsPort": 443,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "keyAlgorithm": "ecdsa"
  }
}
EOF
	# A transient unit, so Pebble survives the shell of in_target and stops with the target.
	in_target "systemd-run --quiet --unit lss-pebble --setenv=PEBBLE_VA_ALWAYS_VALID=1 --setenv=PEBBLE_VA_NOSLEEP=1 \
		--setenv=PEBBLE_WFE_NONCEREJECT=0 ${PEBBLE_DIR}/pebble -config ${PEBBLE_DIR}/config.json
		for i in \$(seq 30); do curl -fsS --cacert ${PEBBLE_DIR}/pebble.minica.pem -o /dev/null https://localhost:14000/dir && exit 0; sleep 1; done
		journalctl -u lss-pebble --no-pager; exit 1"
	pebble_bundle
	return
}

# pebble_bundle: PEBBLE_BUNDLE, the CA bundle of settings.conf. Pebble serves its API with the minica certificate but
# signs the certificates it issues with a root it creates at every start; apps that check each other's certificates
# (Nextcloud and Collabora) need that root, as they would need the root of a step-ca. Roots of earlier starts stay in
# the bundle, so certificates issued before a restart keep their anchor.
pebble_bundle() {
	in_target "set -e
		[ -s ${PEBBLE_BUNDLE} ] || cp ${PEBBLE_DIR}/pebble.minica.pem ${PEBBLE_BUNDLE}
		curl -fsS --retry 3 --cacert ${PEBBLE_DIR}/pebble.minica.pem -o ${PEBBLE_DIR}/root.pem https://localhost:15000/roots/0
		grep -q 'BEGIN CERTIFICATE' ${PEBBLE_DIR}/root.pem
		grep -qxF \"\$(sed -n 2p ${PEBBLE_DIR}/root.pem)\" ${PEBBLE_BUNDLE} || { echo; cat ${PEBBLE_DIR}/root.pem; } >>${PEBBLE_BUNDLE}"
	return
}
