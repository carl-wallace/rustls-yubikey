#!/bin/sh
#
# Runs a simulated post-quantum derived PIV credential enrollment against an attached YubiKey,
# then validates every certificate it produced with PITTv3.
#
# Can be run from anywhere; it works from the root of the checkout it is in.
#
# WARNING: the flow RESETS the PIV applet before it starts. Every key and certificate on the
# device is destroyed and the PIN, PUK and management key go back to their defaults before a
# fresh management key is installed. Use a device dedicated to this. The attestation key in F9
# survives, since a reset does not clear it.
#
# Six algorithm pairs are run in turn -- RSA-2048/3072/4096, then ML-DSA-44/65/87 paired with
# ML-KEM-512/768/1024 -- each preceded by its own reset. Expect 10 to 15 minutes, nearly all of
# it RSA key generation; PQC_VARIANTS=mldsa44,mldsa65,mldsa87 runs only the post-quantum pairs.
#
# The device is left provisioned as the last variant leaves it: seven slots, a management key
# that is no longer the default.
#
#   PITTV3=/path/to/pittv3   the validator, if it is not on PATH as `pittv3`
#   PQC_VARIANTS=a,b         run only these variants (rsa2048 rsa3072 rsa4096 mldsa44 mldsa65 mldsa87)
#   YUBIKEY_SERIAL=12345678  pick a device when more than one is attached
#   RUST_LOG=trace           show the APDU exchange
#
# After each phase that touches the device, `yubico-piv-tool -a status` records what the applet
# reports: version, serial, and which slots hold keys.

set -eu

PITTV3="${PITTV3:-pittv3}"

# A relative PITTV3 path is taken from where the script was started, before the change of directory
# below.
case "$PITTV3" in
    /*) ;;
    */*) PITTV3="$PWD/$PITTV3" ;;
esac

cd "$(dirname "$0")/.."

ARTIFACTS="target/pqc-artifacts"

# Nothing here carries a CRL distribution point or an AIA -- not the made-up CA, and not a YubiKey
# attestation -- so revocation status can never be determined and PITTv3 refuses the path on that
# ground alone. The settings file turns the check off; everything else about validation, including
# every signature, is still enforced.
SETTINGS="scripts/pqc-flow-settings.json"

# The tests only install a logger when RUST_LOG is set, and without one a failed slot write
# reports `GenericError` with the status word discarded -- which is the difference between a full
# device and a rejected object. Errors cost nothing when the run succeeds.
RUST_LOG="${RUST_LOG:-error}"
export RUST_LOG

# Single-threaded and by name: the flow owns the device for its whole run, and the steps depend
# on each other's order.
run_test() {
    cargo test --test enrollment -- --ignored --test-threads=1 --nocapture "$1"
}

pass=0
fail=0

say() {
    printf '\n\033[1m%s\033[0m\n' "$*"
}

# Validates one certificate against the given anchor, and optionally an intermediate.
#   verify <description> <target> <anchor> [intermediate]
verify() {
    description="$1"
    target="$2"
    anchor="$3"
    intermediate="${4:-}"

    if [ ! -f "$target" ]; then
        printf '  \033[31mMISSING\033[0m  %s (%s)\n' "$description" "$target"
        fail=$((fail + 1))
        return
    fi

    if [ -n "$intermediate" ]; then
        output=$("$PITTV3" --settings "$SETTINGS" --ta "$anchor" --ca "$intermediate" --ee "$target" 2>&1) || true
    else
        output=$("$PITTV3" --settings "$SETTINGS" --ta "$anchor" --ee "$target" 2>&1) || true
    fi

    # PITTv3 reports per-target totals; a run that found no valid path says so explicitly.
    if printf '%s' "$output" | grep -q "Total valid paths found: [1-9]"; then
        printf '  \033[32mvalid\033[0m    %s\n' "$description"
        pass=$((pass + 1))
    else
        printf '  \033[31mINVALID\033[0m  %s\n' "$description"
        printf '%s\n' "$output" | sed 's/^/             /'
        fail=$((fail + 1))
    fi
}

# Reports what the applet says it holds. The tool predates this applet and prints every PQC key as
# "Unknown", which still shows which slots are occupied.
device_status() {
    say "Device status"
    yubico-piv-tool -a status 2>&1 | sed "s/^/  /"
}

if ! command -v "$PITTV3" >/dev/null; then
    printf 'pittv3 not found or not executable: %s\n' "$PITTV3" >&2
    printf 'Download it from https://github.com/carl-wallace/rust-pki/releases/tag/pittv3-v0.2.0-rc.2\n' >&2
    printf 'and put it on PATH, or set PITTV3 to its location.\n' >&2
    exit 1
fi

if ! command -v yubico-piv-tool >/dev/null; then
    printf "yubico-piv-tool not found on PATH\n" >&2
    exit 1
fi

#----------------------------------------------------------------------------------------
say "Collecting the attestation slot certificate"
#----------------------------------------------------------------------------------------
# Read first, while the device is still untouched. This is the issuer of every per-slot
# attestation, and yubico-piv-tool cannot fetch it -- it is ML-DSA-87 and overruns the ~3 KiB
# object buffers that tool inherited.
run_test pqc::capture_f9_attestation_cert
device_status

#----------------------------------------------------------------------------------------
say "Running the simulated enrollment matrix"
#----------------------------------------------------------------------------------------
# Six algorithm pairs, each preceded by its own device reset. Variants whose algorithms the applet
# does not implement fail here rather than being skipped: a quiet pass would be the worse outcome.
run_test pqc::derived_piv_enrollment_matrix || VARIANT_RUN_FAILED=1
device_status

for variant in rsa2048 rsa3072 rsa4096 mldsa44 mldsa65 mldsa87
do
    #------------------------------------------------------------------------------------
    say "$variant"
    #------------------------------------------------------------------------------------
    # The matrix honors PQC_VARIANTS; a variant left out of it has nothing to validate.
    if [ -n "${PQC_VARIANTS:-}" ]; then
        case ",$PQC_VARIANTS," in
            *",$variant,"*) ;;
            *)
                printf '  \033[2mnot selected\033[0m\n'
                continue
                ;;
        esac
    fi

    if [ ! -f "$ARTIFACTS/${variant}_01_preenroll_signing.der" ]; then
        printf '  \033[31mMISSING\033[0m  no artifacts -- the variant did not get far enough to produce any\n'
        fail=$((fail + 1))
        continue
    fi

    # The self-signed device certificate is its own anchor; the decryption certificate beside it
    # is signed by that key, which is the arrangement the pre-enroll payload carries.
    printf '  '
    "$PITTV3" --validate-self-signed --ee "$ARTIFACTS/${variant}_01_preenroll_signing.der"
    verify "pre-enroll signing certificate (self-signed)" \
        "$ARTIFACTS/${variant}_01_preenroll_signing.der" \
        "$ARTIFACTS/${variant}_01_preenroll_signing.der"
    verify "pre-enroll decryption certificate, issued by the device signing key" \
        "$ARTIFACTS/${variant}_03_preenroll_kem.der" \
        "$ARTIFACTS/${variant}_01_preenroll_signing.der"

    # Two-deep paths: end entity, intermediate, root.
    for entry in \
        "05_issued_device.der:device signing credential" \
        "06_issued_device_kem.der:device decryption credential" \
        "09_issued_signature.der:user signature credential" \
        "10_issued_piv.der:user PIV authentication credential" \
        "11_recovered_0.der:recovered decryption credential (current)" \
        "11_recovered_1.der:recovered decryption credential (historical 1)" \
        "11_recovered_2.der:recovered decryption credential (historical 2)"
    do
        file="${entry%%:*}"
        label="${entry#*:}"
        verify "$label" "$ARTIFACTS/${variant}_$file" \
            "$ARTIFACTS/${variant}_00_ta_root.der" "$ARTIFACTS/${variant}_00_ca.der"
    done

    # Anchored on the device's own attestation certificate rather than Yubico's root, which is not
    # published for the preview applet. This establishes that the attestation signature verifies
    # and that it names the slot it claims, not that the device chains to Yubico.
    for entry in \
        "01_preenroll_signing_attestation.der:pre-enroll signing key" \
        "03_preenroll_kem_attestation.der:pre-enroll decryption key" \
        "05_issued_device_attestation.der:issued device signing key" \
        "06_issued_device_kem_attestation.der:issued device decryption key" \
        "09_issued_signature_attestation.der:user signature key" \
        "10_issued_piv_attestation.der:user PIV authentication key"
    do
        file="${entry%%:*}"
        label="${entry#*:}"
        verify "attestation, $label" "$ARTIFACTS/${variant}_$file" \
            "$ARTIFACTS/yk_attestation_f9.der"
    done

    # Recovered keys were imported rather than generated, so the device has nothing to attest
    # about them. Their absence is the expected result.
    printf '  \033[2mskipped   attestation, recovered keys (imported, so not attestable)\033[0m\n'
done

#----------------------------------------------------------------------------------------
say "Summary"
#----------------------------------------------------------------------------------------
printf '  %d valid, %d failed\n' "$pass" "$fail"
if [ -n "${VARIANT_RUN_FAILED:-}" ]; then
    printf '  \033[31mat least one variant did not complete -- see the test output above\033[0m\n'
fi
printf '\n'
[ "$fail" -eq 0 ] && [ -z "${VARIANT_RUN_FAILED:-}" ]
