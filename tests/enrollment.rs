//! A simulated post-quantum derived PIV credential enrollment, run against an attached YubiKey.
//!
//! It exercises a simulated derived PIV credential enrollment rather than the yubikey crate
//! itself, and it resets the device it runs against. `scripts/run-pqc-flow.sh` runs it and
//! validates what it produces.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]

use cipher::common::{getrandom::SysRng, Generate};
use log::trace;
use once_cell::sync::Lazy;
use rsa::{pkcs1v15, PublicKey as RsaPublicKey};
use sha2::{Digest, Sha256};
use signature::hazmat::PrehashVerifier;
use std::{env, str::FromStr, sync::Mutex, time::Duration};

use std::time::Instant;

use x509_cert::{der::Encode, name::Name, serial_number::SerialNumber, time::Validity};
use yubikey::{
    certificate::{yubikey_signer, Certificate},
    piv::{self, AlgorithmId, Key, RetiredSlotId, SlotId},
    Error, MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey,
};

static YUBIKEY: Lazy<Mutex<YubiKey>> = Lazy::new(|| {
    // Only show logs if `RUST_LOG` is set
    if env::var("RUST_LOG").is_ok() {
        env_logger::builder().format_timestamp(None).init();
    }

    let yubikey = if let Ok(serial) = env::var("YUBIKEY_SERIAL") {
        let serial = Serial::from_str(&serial).unwrap();
        YubiKey::open_by_serial(serial).unwrap()
    } else {
        YubiKey::open().unwrap()
    };

    trace!("serial: {}", yubikey.serial());
    trace!("version: {}", yubikey.version());

    Mutex::new(yubikey)
});

/// The simulated post-quantum enrollment flow, and the machinery it needs.
mod pqc {
    use super::*;

    //
    // PQC support
    //

    use ml_dsa::{
        MlDsa44, MlDsa65, MlDsa87, Signature as MlDsaSoftSignature, SigningKey as MlDsaSigningKey,
        VerifyingKey as MlDsaVerifyingKey,
    };
    use ml_kem::{
        DecapsulationKey as MlKemDecapsulationKey, EncapsulationKey as MlKemEncapsulationKey,
        MlKem768,
    };
    use pkcs12_builder::{asn1_utils::parse_pkcs12, Pkcs12Builder};
    use rsa::pkcs8::{EncodePrivateKey, PrivateKeyInfoRef};
    use x509_cert::{
        builder::{profile::BuilderProfile, Builder, CertificateBuilder},
        certificate::Version,
        crl::{CertificateList, TbsCertList},
        der,
        der::flagset::FlagSet,
        der::{
            asn1::OctetString,
            asn1::Uint,
            oid::{
                db::{
                    fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768},
                    fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87},
                    rfc5280::{
                        ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS,
                        ID_CE_CERTIFICATE_POLICIES, ID_CE_CRL_NUMBER, ID_CE_KEY_USAGE,
                        ID_CE_SUBJECT_KEY_IDENTIFIER,
                    },
                    rfc5912::RSA_ENCRYPTION,
                },
                ObjectIdentifier,
            },
            referenced::OwnedToRef,
            Decode, Document,
        },
        ext::{
            pkix::{
                certpolicy::PolicyInformation, AuthorityKeyIdentifier, BasicConstraints,
                CertificatePolicies, CrlNumber, KeyUsage, KeyUsages, SubjectKeyIdentifier,
            },
            Extension,
        },
        request::{CertReq, CertReqInfo},
        spki::{
            self, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
            SignatureBitStringEncoding, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef,
        },
        time::Time,
        TbsCertificate,
    };
    use yubikey::certificate::CertInfo;

    /// An ML-DSA signature, as the applet returns it: raw FIPS 204 bytes with no wrapper.
    #[derive(Clone, Debug)]
    struct MlDsaSignature(Vec<u8>);

    impl TryFrom<&[u8]> for MlDsaSignature {
        type Error = signature::Error;

        fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
            if bytes.is_empty() {
                return Err(signature::Error::new());
            }
            Ok(Self(bytes.to_vec()))
        }
    }

    impl SignatureBitStringEncoding for MlDsaSignature {
        fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
            der::asn1::BitString::new(0, self.0.as_slice())
        }
    }

    /// An ML-DSA public key, kept in the SPKI form the YubiKey returned.
    ///
    /// No ML-DSA implementation is a dependency of this crate and these tests do not verify the
    /// signatures they produce, so there is nothing to parse the key into.
    #[derive(Clone, Debug)]
    struct MlDsaPublicKey(SubjectPublicKeyInfoOwned);

    impl TryFrom<SubjectPublicKeyInfoRef<'_>> for MlDsaPublicKey {
        type Error = spki::Error;

        fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
            Ok(Self(SubjectPublicKeyInfoOwned::from_der(&spki.to_der()?)?))
        }
    }

    impl EncodePublicKey for MlDsaPublicKey {
        fn to_public_key_der(&self) -> spki::Result<Document> {
            Ok(Document::try_from(self.0.to_der()?)?)
        }
    }

    impl DynSignatureAlgorithmIdentifier for MlDsaPublicKey {
        fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
            // Taken from the key rather than named here: FIPS 204 carries the parameter set in
            // the OID, so the SubjectPublicKeyInfo the applet returned already says which one,
            // and one signer type can serve ML-DSA-44, -65 and -87 alike.
            Ok(self.0.algorithm.clone())
        }
    }

    /// Defines a `KeyType` for one ML-DSA parameter set held in a PIV slot.
    ///
    /// The signature and public key types are shared across parameter sets: a signature is raw
    /// FIPS 204 bytes whatever its size, and the public key is kept as the SubjectPublicKeyInfo
    /// the applet returned, which already names the parameter set. Only the algorithm identifier
    /// sent to the card differs, and that is what this generates.
    ///
    /// Named apart from [`ml_dsa::MlDsa65`] and friends, which are the software parameter sets
    /// used by the stand-in CA; the two appear side by side throughout the enrollment flow.
    macro_rules! card_ml_dsa {
        ($name:ident, $algorithm:expr) => {
            struct $name;

            impl yubikey_signer::KeyType for $name {
                type Error = signature::Error;
                type Signature = MlDsaSignature;
                type VerifyingKey = MlDsaPublicKey;
                type PublicKey = MlDsaPublicKey;

                const ALGORITHM: AlgorithmId = $algorithm;

                /// ML-DSA signs the message, so there is no host-side digest step.
                fn prepare(input: &[u8]) -> Result<Vec<u8>, signature::Error> {
                    Ok(input.to_vec())
                }

                /// Pure ML-DSA has no prehash variant, so a prehashed message is refused rather
                /// than signed as though it were the message.
                fn prepare_prehash(_hashed: &[u8]) -> Result<Vec<u8>, signature::Error> {
                    Err(signature::Error::new())
                }

                fn read_signature(input: &[u8]) -> Result<Self::Signature, signature::Error> {
                    MlDsaSignature::try_from(input)
                }
            }
        };
    }

    card_ml_dsa!(CardMlDsa44, AlgorithmId::MlDsa44);
    card_ml_dsa!(CardMlDsa65, AlgorithmId::MlDsa65);
    card_ml_dsa!(CardMlDsa87, AlgorithmId::MlDsa87);

    /// Names issuer and subject outright, and adds subject and authority key identifiers to the
    /// extensions given.
    ///
    /// The crate's own `SelfSigned` profile cannot be constructed from outside the crate, and the
    /// ML-KEM certificate is issued rather than self-signed, so both go through this.
    struct IssuedBy {
        issuer: Name,
        subject: Name,
        extensions: Vec<Extension>,
    }

    impl BuilderProfile for IssuedBy {
        fn get_issuer(&self, _subject: &Name) -> Name {
            self.issuer.clone()
        }

        fn get_subject(&self) -> Name {
            self.subject.clone()
        }

        fn build_extensions(
            &self,
            spk: SubjectPublicKeyInfoRef<'_>,
            issuer_spk: SubjectPublicKeyInfoRef<'_>,
            _tbs: &TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            let mut extensions = self.extensions.clone();
            extensions.push(ext_subject_key_id(&spk));
            extensions.push(ext_authority_key_id(&issuer_spk));
            Ok(extensions)
        }
    }

    /// A `basicConstraints` marking the subject a CA, critical as RFC 5280 requires.
    fn ext_ca() -> Extension {
        let bc = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        Extension {
            extn_id: ID_CE_BASIC_CONSTRAINTS,
            critical: true,
            extn_value: OctetString::new(bc.to_der().expect("encode basicConstraints"))
                .expect("wrap basicConstraints"),
        }
    }

    /// The RFC 5280 method 1 key identifier: SHA-1 of the subjectPublicKey bits.
    fn key_id(spk: &SubjectPublicKeyInfoRef<'_>) -> OctetString {
        OctetString::new(sha1::Sha1::digest(spk.subject_public_key.raw_bytes()).to_vec())
            .expect("wrap key identifier")
    }

    fn ext_subject_key_id(spk: &SubjectPublicKeyInfoRef<'_>) -> Extension {
        let skid = SubjectKeyIdentifier(key_id(spk));
        Extension {
            extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(skid.to_der().expect("encode subjectKeyIdentifier"))
                .expect("wrap subjectKeyIdentifier"),
        }
    }

    fn ext_authority_key_id(issuer_spk: &SubjectPublicKeyInfoRef<'_>) -> Extension {
        let akid = AuthorityKeyIdentifier {
            key_identifier: Some(key_id(issuer_spk)),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        Extension {
            extn_id: ID_CE_AUTHORITY_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(akid.to_der().expect("encode authorityKeyIdentifier"))
                .expect("wrap authorityKeyIdentifier"),
        }
    }

    /// A `certificatePolicies` asserting the one policy given, with no qualifiers.
    fn ext_policy(policy: ObjectIdentifier) -> Extension {
        let policies = CertificatePolicies(vec![PolicyInformation {
            policy_identifier: policy,
            policy_qualifiers: None,
        }]);
        Extension {
            extn_id: ID_CE_CERTIFICATE_POLICIES,
            critical: false,
            extn_value: OctetString::new(policies.to_der().expect("encode certificatePolicies"))
                .expect("wrap certificatePolicies"),
        }
    }

    /// The policy the PIV authentication certificate asserts: a Red Hound test policy
    /// (id-rhs-testing-certPol1), standing in for a hardware-key policy.
    const TEST_HARDWARE_POLICY: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37623.2.1");

    /// How long the stand-in PKI's certificates and CRLs are valid, so a run's artifacts stay
    /// usable for testing relying parties.
    const FAKE_PKI_VALIDITY: Duration = Duration::from_secs(365 * 24 * 60 * 60);

    /// A critical `keyUsage` carrying exactly the bits given.
    fn ext_key_usage(usages: impl Into<FlagSet<KeyUsages>>) -> Extension {
        let ku = KeyUsage(usages.into());
        Extension {
            extn_id: ID_CE_KEY_USAGE,
            critical: true,
            extn_value: OctetString::new(ku.to_der().expect("encode keyUsage"))
                .expect("wrap keyUsage"),
        }
    }

    /// The stand-in PKI the enrollment steps issue from: a self-signed root and one intermediate.
    ///
    /// Both keys are ML-DSA-65 **in software**, so nothing here competes for a slot on the device.
    /// Held together because every issuing step needs the intermediate's key to sign with and its
    /// certificate to name as issuer.
    struct FakeCa {
        root_key: MlDsaSigningKey<MlDsa65>,
        root_cert: x509_cert::Certificate,
        ca_key: MlDsaSigningKey<MlDsa65>,
        ca_cert: x509_cert::Certificate,
    }

    impl FakeCa {
        /// Mints the root and the intermediate beneath it.
        ///
        /// Seeded rather than random so a failing run can be repeated against identical material;
        /// there is nothing to protect here, and reproducibility is worth more.
        fn new() -> Self {
            let root_key = MlDsaSigningKey::<MlDsa65>::from_seed(&[7u8; 32].into());
            let ca_key = MlDsaSigningKey::<MlDsa65>::from_seed(&[11u8; 32].into());

            let root_name = Name::from_str("CN=test root").expect("parse name");
            let ca_name = Name::from_str("CN=test CA").expect("parse name");

            // anyPolicy, so that a path to an end entity is valid for whatever policy it asserts.
            let ca_exts = vec![
                ext_ca(),
                ext_key_usage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
                ext_policy(ObjectIdentifier::new_unwrap("2.5.29.32.0")),
            ];

            let root_cert = issue(
                &root_key,
                IssuedBy {
                    issuer: root_name.clone(),
                    subject: root_name.clone(),
                    extensions: ca_exts.clone(),
                },
                spki_of(&signature::Keypair::verifying_key(&root_key)),
            );

            let ca_cert = issue(
                &root_key,
                IssuedBy {
                    issuer: root_name,
                    subject: ca_name,
                    extensions: ca_exts,
                },
                spki_of(&signature::Keypair::verifying_key(&ca_key)),
            );

            Self {
                root_key,
                root_cert,
                ca_key,
                ca_cert,
            }
        }

        /// An empty CRL from the root, covering the intermediate.
        fn root_crl(&self) -> CertificateList {
            empty_crl(&self.root_key, &self.root_cert)
        }

        /// An empty CRL from the intermediate, covering the end-entity certificates.
        fn ca_crl(&self) -> CertificateList {
            empty_crl(&self.ca_key, &self.ca_cert)
        }

        /// Issues an end-entity certificate for `spki` under the intermediate.
        fn issue_for(
            &self,
            subject: &str,
            spki: SubjectPublicKeyInfoOwned,
            extensions: Vec<Extension>,
        ) -> x509_cert::Certificate {
            issue(
                &self.ca_key,
                IssuedBy {
                    issuer: self.ca_cert.tbs_certificate().subject().clone(),
                    subject: Name::from_str(subject).expect("parse name"),
                    extensions,
                },
                spki,
            )
        }
    }

    /// The SubjectPublicKeyInfo for a software public key.
    fn spki_of<K: EncodePublicKey>(key: &K) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned::from_der(
            key.to_public_key_der()
                .expect("encode public key")
                .as_bytes(),
        )
        .expect("parse public key")
    }

    /// An empty v2 CRL signed by `key` for `issuer`, with an authority key identifier and a CRL
    /// number so that relying parties can match it to its issuer.
    fn empty_crl(
        key: &MlDsaSigningKey<MlDsa65>,
        issuer: &x509_cert::Certificate,
    ) -> CertificateList {
        let now = std::time::SystemTime::now();
        let issuer_spki = issuer.tbs_certificate().subject_public_key_info();
        let crl_number = CrlNumber(Uint::new(&[1]).expect("encode CRL number"));
        let tbs = TbsCertList {
            version: Version::V2,
            signature: issuer.signature_algorithm().clone(),
            issuer: issuer.tbs_certificate().subject().clone(),
            this_update: Time::try_from(now).expect("this update"),
            next_update: Some(Time::try_from(now + FAKE_PKI_VALIDITY).expect("next update")),
            revoked_certificates: None,
            crl_extensions: Some(vec![
                ext_authority_key_id(&issuer_spki.owned_to_ref()),
                Extension {
                    extn_id: ID_CE_CRL_NUMBER,
                    critical: false,
                    extn_value: OctetString::new(crl_number.to_der().expect("encode cRLNumber"))
                        .expect("wrap cRLNumber"),
                },
            ]),
        };
        let signature: MlDsaSoftSignature<MlDsa65> =
            signature::Signer::sign(key, &tbs.to_der().expect("encode TBSCertList"));
        CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: issuer.signature_algorithm().clone(),
            signature: signature.to_bitstring().expect("encode CRL signature"),
        }
    }

    /// Builds and signs a certificate with a software ML-DSA key.
    fn issue(
        key: &MlDsaSigningKey<MlDsa65>,
        profile: IssuedBy,
        spki: SubjectPublicKeyInfoOwned,
    ) -> x509_cert::Certificate {
        let serial = <[u8; 19]>::generate();
        let serial =
            SerialNumber::new(&serial[..]).expect("serial can't be more than 20 bytes long");
        let validity = Validity::from_now(FAKE_PKI_VALIDITY).unwrap();

        CertificateBuilder::new(profile, serial, validity, spki)
            .expect("certificate builder")
            .build::<_, MlDsaSoftSignature<MlDsa65>>(key)
            .expect("sign certificate")
    }

    /// Takes the YubiKey, tolerating a mutex poisoned by an earlier test.
    ///
    /// A poisoned mutex means some other test panicked while holding the device, and `unwrap` here
    /// would report that instead of whatever this test was doing — which hides the original failure
    /// behind an unrelated one. The device itself is unaffected by another test's panic.
    fn lock_yubikey() -> std::sync::MutexGuard<'static, YubiKey> {
        match YUBIKEY.lock() {
            Ok(yubikey) => yubikey,
            Err(poison) => poison.into_inner(),
        }
    }

    /// Writes a DER artifact where it can be read after the run and reports where it went.
    ///
    /// A passing assertion here says the applet answered, not that it answered correctly, so the
    /// material is the output that matters. It goes under `target/` rather than the system temporary
    /// directory: same place every run, already ignored by git, and `cargo clean` takes it away.
    fn capture(name: &str, der: &[u8]) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/pqc-artifacts");
        std::fs::create_dir_all(&dir).expect("create artifact directory");
        let path = dir.join(name);
        std::fs::write(&path, der).expect("write artifact");
        eprintln!("{}: {} bytes", path.display(), der.len());
    }

    /// Captures the attestation slot's own certificate, the issuer of every per-slot attestation this
    /// device produces.
    ///
    /// Its own test because `yubico-piv-tool -a read-certificate -s f9` cannot fetch it from the
    /// preview applet: that certificate is ML-DSA-87 and overruns the ~3 KiB PIV object buffers, the
    /// same ceiling this crate had to raise. Needed on disk to validate an attestation, since it is the
    /// issuer named in one.
    #[test]
    #[ignore]
    fn capture_f9_attestation_cert() {
        let mut yubikey = lock_yubikey();
        let cert =
            Certificate::read(&mut yubikey, SlotId::Attestation).expect("read F9 certificate");
        capture(
            "yk_attestation_f9.der",
            &cert.cert.to_der().expect("serialize certificate"),
        );
    }

    /// The stand-in PKI's material, checked and captured without a device: key identifiers chain
    /// from the root to an end entity, and each CRL is signed by its issuer and names it by key
    /// identifier. The end entity's key is a software ML-DSA-65 key from seed `[13; 32]`, so a
    /// relying party can be tested with it alongside the card's own certificates.
    #[test]
    fn fake_ca_material() {
        fn extension(extensions: Option<&Vec<Extension>>, oid: ObjectIdentifier) -> &[u8] {
            extensions
                .and_then(|exts| exts.iter().find(|ext| ext.extn_id == oid))
                .unwrap_or_else(|| panic!("no {oid} extension"))
                .extn_value
                .as_bytes()
        }
        fn skid(cert: &x509_cert::Certificate) -> OctetString {
            let value = extension(
                cert.tbs_certificate().extensions(),
                ID_CE_SUBJECT_KEY_IDENTIFIER,
            );
            SubjectKeyIdentifier::from_der(value)
                .expect("decode subjectKeyIdentifier")
                .0
        }
        fn akid(extensions: Option<&Vec<Extension>>) -> OctetString {
            let value = extension(extensions, ID_CE_AUTHORITY_KEY_IDENTIFIER);
            AuthorityKeyIdentifier::from_der(value)
                .expect("decode authorityKeyIdentifier")
                .key_identifier
                .expect("authorityKeyIdentifier has a key identifier")
        }
        fn verify_crl(crl: &CertificateList, issuer: &x509_cert::Certificate) {
            let spki = issuer
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .expect("encode SPKI");
            let spki = SubjectPublicKeyInfoRef::from_der(&spki).expect("parse SPKI");
            let key = MlDsaVerifyingKey::<MlDsa65>::try_from(spki).expect("ML-DSA-65 public key");
            let encoded = ml_dsa::EncodedSignature::<MlDsa65>::try_from(crl.signature.raw_bytes())
                .expect("ML-DSA-65 signature size");
            let signature =
                MlDsaSoftSignature::<MlDsa65>::decode(&encoded).expect("decode signature");
            let tbs = crl.tbs_cert_list.to_der().expect("encode TBSCertList");
            signature::Verifier::verify(&key, &tbs, &signature).expect("CRL signature verifies");
        }

        let ca = FakeCa::new();
        let user_key = MlDsaSigningKey::<MlDsa65>::from_seed(&[13u8; 32].into());
        let user = ca.issue_for(
            "CN=test software user",
            spki_of(&signature::Keypair::verifying_key(&user_key)),
            vec![
                ext_key_usage(KeyUsages::DigitalSignature),
                ext_policy(TEST_HARDWARE_POLICY),
            ],
        );
        let (root_crl, ca_crl) = (ca.root_crl(), ca.ca_crl());

        assert_eq!(
            akid(ca.ca_cert.tbs_certificate().extensions()),
            skid(&ca.root_cert)
        );
        assert_eq!(akid(user.tbs_certificate().extensions()), skid(&ca.ca_cert));
        assert_eq!(
            akid(root_crl.tbs_cert_list.crl_extensions.as_ref()),
            skid(&ca.root_cert)
        );
        assert_eq!(
            akid(ca_crl.tbs_cert_list.crl_extensions.as_ref()),
            skid(&ca.ca_cert)
        );
        verify_crl(&root_crl, &ca.root_cert);
        verify_crl(&ca_crl, &ca.ca_cert);

        capture(
            "fakeca_root.der",
            &ca.root_cert.to_der().expect("encode root"),
        );
        capture("fakeca_ca.der", &ca.ca_cert.to_der().expect("encode CA"));
        capture(
            "fakeca_root.crl",
            &root_crl.to_der().expect("encode root CRL"),
        );
        capture("fakeca_ca.crl", &ca_crl.to_der().expect("encode CA CRL"));
        capture("fakeca_user.der", &user.to_der().expect("encode user"));
    }

    //
    // Simulated derived PIV credential enrollment flow
    //
    // The sequence a derived PIV credential enrollment puts a device through, staged so each step
    // leaves behind the artifacts the next one -- or pittv3 afterwards -- consumes. One test rather
    // than sixteen because the steps share slots and depend on each other's order: step 5 replaces
    // what step 1 installed, step 8 needs the key step 6 issued for, and an attestation has to be
    // captured before a later step overwrites the slot it describes.

    /// Device signing credential, in the slot that holds the device certificate.
    const SLOT_DEVICE_SIGNING: SlotId = SlotId::CardAuthentication;

    /// Device decryption credential. This is the half that splits off the card authentication slot
    /// now that one key can no longer both sign and decrypt.
    const SLOT_DEVICE_KEM: SlotId = SlotId::Retired(RetiredSlotId::R20);

    /// User signature credential.
    const SLOT_SIGNATURE: SlotId = SlotId::Signature;

    /// User PIV authentication credential.
    const SLOT_PIV_AUTH: SlotId = SlotId::Authentication;

    /// Recovered decryption keys, in the order a real enrollment places them: index 0 is the current
    /// key and lands in the key management slot, the rest are historical and fill the retired slots
    /// from the bottom.
    const SLOTS_RECOVERED: [SlotId; 3] = [
        SlotId::KeyManagement,
        SlotId::Retired(RetiredSlotId::R1),
        SlotId::Retired(RetiredSlotId::R2),
    ];

    /// The device's PIN: the factory default, which the reset before each variant restores.
    const PIN: &[u8] = b"123456";

    /// Password on the PKCS #12 files the recovered-key steps build and read back.
    const P12_PASSWORD: &str = "ykpqc";

    /// The management key currently installed on the device, if it is not the factory default.
    ///
    /// Held here rather than threaded through every helper that touches the card: the flow is a
    /// single sequential run, and the alternative is an extra parameter on all of them.
    ///
    /// Cleared by [`reset_device`] rather than write-once, because a reset puts the factory key
    /// back and each variant of the matrix installs its own afterwards. Keeping a stale key here
    /// would authenticate every later variant with the wrong one.
    static MGM_KEY: Mutex<Option<MgmKey>> = Mutex::new(None);

    /// Wall-clock time for each card operation in the variant currently running.
    ///
    /// Collected rather than printed as it goes so the numbers arrive as one table, which is the
    /// only form in which they can be compared across algorithms.
    static TIMINGS: Mutex<Vec<(String, Duration)>> = Mutex::new(Vec::new());

    /// Times one card operation and records it under `label`.
    fn timed<T>(label: String, operation: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let value = operation();
        let elapsed = start.elapsed();
        TIMINGS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push((label, elapsed));
        value
    }

    /// Prints the timing table when it goes out of scope, however the variant ends.
    ///
    /// A guard rather than a call at the end of the flow: a variant that fails part way through
    /// is exactly the one whose timings are worth seeing, and a plain call at the bottom is the
    /// one thing a panic guarantees will not run.
    struct TimingReport(String);

    impl Drop for TimingReport {
        fn drop(&mut self) {
            report_timings(&self.0);
        }
    }

    /// Prints what each card operation cost, then clears the record for the next variant.
    fn report_timings(variant: &str) {
        let mut timings = TIMINGS.lock().unwrap_or_else(|poison| poison.into_inner());
        let total: Duration = timings.iter().map(|(_, d)| *d).sum();

        eprintln!("\n  {variant} timings (card operations only)");
        for (label, elapsed) in timings.iter() {
            eprintln!("    {:>9.3?}  {label}", elapsed);
        }
        eprintln!(
            "    {:>9.3?}  total across {} operations",
            total,
            timings.len()
        );

        timings.clear();
    }

    /// Blocks the PIN by exhausting its retry counter.
    fn block_pin(yubikey: &mut YubiKey) {
        for _ in 0..16 {
            match yubikey.verify_pin(b"00000000") {
                Ok(()) => panic!("the wrong PIN was accepted"),
                Err(Error::WrongPin { tries: 0 }) => return,
                Err(Error::WrongPin { .. }) => continue,
                Err(e) => panic!("blocking the PIN: {e:?}"),
            }
        }
        panic!("the PIN retry counter never reached zero");
    }

    /// Wipes the PIV applet so the flow starts from a device with nothing on it.
    ///
    /// **Destructive.** Every key and certificate is destroyed and the PIN, PUK and management
    /// key return to their defaults. The attestation key in F9 survives; it is not cleared by a
    /// reset, which is what lets the attestations produced later still chain.
    ///
    /// A reset is only offered once both the PIN and the PUK are blocked -- the applet's guard
    /// against reset being a way around the PIN -- so both are exhausted first.
    fn reset_device(yubikey: &mut YubiKey) {
        block_pin(yubikey);
        yubikey.block_puk().expect("block the PUK");
        yubikey.reset_device().expect("reset the device");

        // The factory management key is back, so anything remembered from before the reset is
        // now wrong.
        *MGM_KEY.lock().unwrap_or_else(|poison| poison.into_inner()) = None;

        eprintln!("device reset: PIV applet wiped, credentials back to defaults");
    }

    /// Replaces the factory management key, as an enrollment does.
    ///
    /// Set `YK_MGM_KEY` to 48 hex characters to install a particular key -- a deployment's, to
    /// make the run match what a real enrollment leaves behind. Unset, a random key is generated, so
    /// the deployment key does not have to live in this source to run the tests.
    ///
    /// The algorithm follows the device rather than being chosen here: this applet is treated as
    /// 6.0.0 and takes AES-192, where a pre-5.7 YubiKey would take 3DES.
    fn install_management_key(yubikey: &mut YubiKey) {
        let default_key = MgmKey::get_default(yubikey).expect("default management key");
        yubikey.verify_pin(PIN).expect("verify PIN");
        yubikey
            .authenticate(&default_key)
            .expect("authenticate with the default management key");

        let mgm = match env::var("YK_MGM_KEY") {
            Ok(hex) => {
                let bytes = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                    .collect::<Result<Vec<u8>, _>>()
                    .expect("YK_MGM_KEY must be hexadecimal");
                let algorithm = MgmKey::get_default(yubikey)
                    .expect("default management key")
                    .algorithm_id();
                eprintln!("installing the management key from YK_MGM_KEY ({algorithm:?})");
                MgmKey::from_bytes(bytes.as_slice(), Some(algorithm))
                    .expect("YK_MGM_KEY is not a usable management key")
            }
            Err(_) => {
                eprintln!("YK_MGM_KEY unset: generating a random management key");
                MgmKey::generate_for(yubikey, &mut SysRng).expect("generate a management key")
            }
        };
        mgm.set_manual(yubikey, false)
            .expect("install the management key");

        *MGM_KEY.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(mgm);

        // Asserted rather than assumed: if the default still authenticates, the new key did not
        // take and every later step would keep working for the wrong reason.
        assert!(
            yubikey.authenticate(&default_key).is_err(),
            "the default management key still authenticates after being replaced"
        );
        eprintln!("management key replaced");
    }

    /// Verifies the PIN and authenticates with whichever management key is current.
    fn authenticate(yubikey: &mut YubiKey) {
        yubikey.verify_pin(PIN).expect("verify PIN");
        let installed = MGM_KEY.lock().unwrap_or_else(|poison| poison.into_inner());
        match installed.as_ref() {
            Some(key) => yubikey
                .authenticate(key)
                .expect("authenticate with the flow's management key"),
            None => {
                let key = MgmKey::get_default(yubikey).expect("default management key");
                yubikey
                    .authenticate(&key)
                    .expect("authenticate with the default management key")
            }
        }
    }

    /// Generates a key in `slot`, returning its public half.
    fn generate_key(
        yubikey: &mut YubiKey,
        slot: SlotId,
        algorithm: AlgorithmId,
    ) -> SubjectPublicKeyInfoOwned {
        authenticate(yubikey);
        timed(format!("generate {algorithm:?} in {slot}"), || {
            piv::generate(
                yubikey,
                slot,
                algorithm,
                PinPolicy::Default,
                TouchPolicy::Default,
            )
            .unwrap_or_else(|e| panic!("generate {algorithm:?} in {slot}: {e:?}"))
        })
    }

    /// Builds a certificate for `subject_spki`, signed by the ML-DSA key in `signing_slot`.
    fn sign_cert_on_card<KT: yubikey_signer::KeyType>(
        yubikey: &mut YubiKey,
        signing_slot: SlotId,
        signing_spki: &SubjectPublicKeyInfoOwned,
        profile: IssuedBy,
        subject_spki: SubjectPublicKeyInfoOwned,
    ) -> x509_cert::Certificate {
        let serial = <[u8; 19]>::generate();
        let serial =
            SerialNumber::new(&serial[..]).expect("serial can't be more than 20 bytes long");
        let validity = Validity::from_now(Duration::new(500000, 0)).unwrap();

        let builder = CertificateBuilder::new(profile, serial, validity, subject_spki)
            .expect("certificate builder");

        authenticate(yubikey);
        let signer = yubikey_signer::Signer::<'_, KT>::new(
            yubikey,
            signing_slot,
            signing_spki.owned_to_ref(),
        )
        .expect("card signer");

        timed(format!("sign a certificate with {signing_slot}"), || {
            builder
                .build::<_, KT::Signature>(&signer)
                .expect("sign certificate on the card")
        })
    }

    /// Writes a certificate into a slot, clearing whatever was there first.
    ///
    /// The delete is not ceremony: 9E and the device decryption slot are each written twice in a
    /// run -- once at pre-enroll, once with the CA-issued replacement -- and if the applet does
    /// not reclaim a superseded object on overwrite, those two orphans are pure loss. At
    /// ML-DSA-87 sizes that is around 13 KiB, which is the difference between the seven-slot
    /// layout fitting and not.
    ///
    /// Set `PQC_NO_DELETE` to skip it and see whether that is what the ceiling is made of.
    fn install(yubikey: &mut YubiKey, slot: SlotId, cert: &x509_cert::Certificate) {
        if env::var("PQC_NO_DELETE").is_err() {
            authenticate(yubikey);
            // An empty slot is the common case on a freshly reset device, so a failure here is
            // not interesting enough to stop for.
            let _ = Certificate::delete(yubikey, slot);
        }

        authenticate(yubikey);
        let der_len = cert.to_der().map(|d| d.len()).unwrap_or_default();
        timed(
            format!("write a {der_len}-byte certificate to {slot}"),
            || {
                Certificate { cert: cert.clone() }
                    .write(yubikey, slot, CertInfo::Uncompressed)
                    .unwrap_or_else(|e| panic!("write certificate to {slot}: {e:?}"))
            },
        );
    }

    /// Builds a PKCS #10 request for the key in `slot` and signs it **on the card**.
    ///
    /// This is the proof of possession the real flow relies on, and it is only available to signing
    /// keys: the ML-KEM steps have to be issued without one.
    fn csr_on_card<KT: yubikey_signer::KeyType>(
        yubikey: &mut YubiKey,
        slot: SlotId,
        spki: &SubjectPublicKeyInfoOwned,
        subject: &str,
    ) -> CertReq {
        let info = CertReqInfo {
            version: Default::default(),
            subject: Name::from_str(subject).expect("parse name"),
            public_key: spki.clone(),
            attributes: Default::default(),
        };
        let enc_info = info.to_der().expect("encode CertReqInfo");

        authenticate(yubikey);
        let signer = yubikey_signer::Signer::<'_, KT>::new(yubikey, slot, spki.owned_to_ref())
            .expect("card signer");
        let signature =
            signature::Signer::try_sign(&signer, &enc_info).expect("sign the certificate request");

        CertReq {
            info,
            // The key's own algorithm identifier, for the reason given on `MlDsaPublicKey`.
            algorithm: spki.algorithm.clone(),
            signature: signature.to_bitstring().expect("encode signature"),
        }
    }

    /// Captures the attestation for `slot` using a YubiKey the caller already holds.
    ///
    /// Separate from [`capture_attestation`], which takes the lock itself: the enrollment flow holds
    /// it for the whole run, and a second acquisition would deadlock.
    fn capture_attestation_held(
        yubikey: &mut YubiKey,
        name: &str,
        slot: SlotId,
        attested: &SubjectPublicKeyInfoOwned,
    ) {
        let attestation =
            piv::attest(yubikey, slot).unwrap_or_else(|e| panic!("attest {slot}: {e:?}"));
        capture(name, &attestation);

        // Validating the attestation's signature establishes that this device issued it. It does
        // not establish which key it describes -- and that binding is the whole point. Without
        // this comparison an attestation for any key on the device would satisfy the check, so a
        // slot could be provisioned with one key and vouched for with another.
        let parsed = x509_cert::Certificate::from_der(&attestation)
            .unwrap_or_else(|e| panic!("parse the attestation for {slot}: {e:?}"));
        let attested_key = parsed.tbs_certificate().subject_public_key_info();

        assert_eq!(
            attested_key, attested,
            "the attestation for {slot} describes a different key than the one provisioned there"
        );
    }

    /// Runs the whole simulated enrollment against one pair of algorithms.
    ///
    /// Generic over the signing key type because the card signer is chosen at compile time; the
    /// decryption algorithm is a value, since nothing about it needs a type.
    fn enrollment_flow<KT: yubikey_signer::KeyType>(variant: &str, decryption: AlgorithmId) {
        // Step 0: the stand-in PKI everything from step 5 on is issued under.
        let ca = FakeCa::new();
        capture(
            &format!("{variant}_00_ta_root.der"),
            &ca.root_cert.to_der().expect("encode root"),
        );
        capture(
            &format!("{variant}_00_ca.der"),
            &ca.ca_cert.to_der().expect("encode CA"),
        );
        capture(
            &format!("{variant}_00_root.crl"),
            &ca.root_crl().to_der().expect("encode root CRL"),
        );
        capture(
            &format!("{variant}_00_ca.crl"),
            &ca.ca_crl().to_der().expect("encode CA CRL"),
        );

        // Prints the timings on the way out, including out through a panic.
        let _timings = TimingReport(variant.to_string());

        let mut yubikey = lock_yubikey();
        let device = "CN=test device";

        // Start from a wiped device and a management key of our own, as an enrollment does. This
        // is also what makes the run reproducible: every step below sees the same starting state
        // rather than whatever the last run left behind.
        reset_device(&mut yubikey);
        install_management_key(&mut yubikey);

        //----------------------------------------------------------------------------------
        // Pre-enroll
        //----------------------------------------------------------------------------------

        // Step 1: device signing key, self-signed.
        let device_spki = generate_key(&mut yubikey, SLOT_DEVICE_SIGNING, KT::ALGORITHM);
        let preenroll_signing = sign_cert_on_card::<KT>(
            &mut yubikey,
            SLOT_DEVICE_SIGNING,
            &device_spki,
            IssuedBy {
                issuer: Name::from_str(device).expect("parse name"),
                subject: Name::from_str(device).expect("parse name"),
                extensions: vec![ext_key_usage(KeyUsages::DigitalSignature)],
            },
            device_spki.clone(),
        );
        install(&mut yubikey, SLOT_DEVICE_SIGNING, &preenroll_signing);
        capture(
            &format!("{variant}_01_preenroll_signing.der"),
            &preenroll_signing.to_der().expect("encode certificate"),
        );
        capture_attestation_held(
            &mut yubikey,
            &format!("{variant}_01_preenroll_signing_attestation.der"),
            SLOT_DEVICE_SIGNING,
            &device_spki,
        );

        // Step 3: device KEM key, certified by the signing key above. A KEM key cannot self-sign,
        // which is the whole reason the pre-enroll payload carries two certificates.
        let device_kem_spki = generate_key(&mut yubikey, SLOT_DEVICE_KEM, decryption);
        let preenroll_kem = sign_cert_on_card::<KT>(
            &mut yubikey,
            SLOT_DEVICE_SIGNING,
            &device_spki,
            IssuedBy {
                issuer: Name::from_str(device).expect("parse name"),
                subject: Name::from_str("CN=test device encryption").expect("parse name"),
                extensions: vec![ext_key_usage(KeyUsages::KeyEncipherment)],
            },
            device_kem_spki.clone(),
        );
        install(&mut yubikey, SLOT_DEVICE_KEM, &preenroll_kem);
        capture(
            &format!("{variant}_03_preenroll_kem.der"),
            &preenroll_kem.to_der().expect("encode certificate"),
        );
        capture_attestation_held(
            &mut yubikey,
            &format!("{variant}_03_preenroll_kem_attestation.der"),
            SLOT_DEVICE_KEM,
            &device_kem_spki,
        );

        // The pre-enroll KEM key is what the issuer encrypts its enrollment response to, so it has
        // to decapsulate before step 6 replaces it. Exercised here rather than later for that
        // reason: after step 6 this key no longer exists.
        round_trip_decryption(
            &mut yubikey,
            SLOT_DEVICE_KEM,
            &device_kem_spki,
            "pre-enroll KEM (enrollment response)",
        );

        //----------------------------------------------------------------------------------
        // Issuance
        //----------------------------------------------------------------------------------

        // Step 5: a fresh device signing key, this time certified by the CA off a request the card
        // signed. The self-signed certificate from step 1 is replaced in the slot.
        let device_spki = generate_key(&mut yubikey, SLOT_DEVICE_SIGNING, KT::ALGORITHM);
        let csr = csr_on_card::<KT>(&mut yubikey, SLOT_DEVICE_SIGNING, &device_spki, device);
        capture(
            &format!("{variant}_05_device_csr.der"),
            &csr.to_der().expect("encode CSR"),
        );
        let issued_device = ca.issue_for(
            device,
            csr.info.public_key.clone(),
            vec![ext_key_usage(KeyUsages::DigitalSignature)],
        );
        install(&mut yubikey, SLOT_DEVICE_SIGNING, &issued_device);
        capture(
            &format!("{variant}_05_issued_device.der"),
            &issued_device.to_der().expect("encode certificate"),
        );
        capture_attestation_held(
            &mut yubikey,
            &format!("{variant}_05_issued_device_attestation.der"),
            SLOT_DEVICE_SIGNING,
            &device_spki,
        );

        // Step 6: a fresh device KEM key, certified with no proof of possession -- the gap a KEM key
        // leaves in any request protocol built around a self-signed PKCS #10.
        let device_kem_spki = generate_key(&mut yubikey, SLOT_DEVICE_KEM, decryption);
        let issued_device_kem = ca.issue_for(
            "CN=test device encryption",
            device_kem_spki.clone(),
            vec![ext_key_usage(KeyUsages::KeyEncipherment)],
        );
        install(&mut yubikey, SLOT_DEVICE_KEM, &issued_device_kem);
        capture(
            &format!("{variant}_06_issued_device_kem.der"),
            &issued_device_kem.to_der().expect("encode certificate"),
        );
        capture_attestation_held(
            &mut yubikey,
            &format!("{variant}_06_issued_device_kem_attestation.der"),
            SLOT_DEVICE_KEM,
            &device_kem_spki,
        );

        // Steps 7 and 8: encapsulate to that key off the card, decapsulate on it, and require the
        // shared secrets to agree.
        round_trip_decryption(&mut yubikey, SLOT_DEVICE_KEM, &device_kem_spki, "step 6");

        // Step 9: user signature credential.
        let signature_spki = generate_key(&mut yubikey, SLOT_SIGNATURE, KT::ALGORITHM);
        let signature_subject = "CN=test user signature";
        let csr = csr_on_card::<KT>(
            &mut yubikey,
            SLOT_SIGNATURE,
            &signature_spki,
            signature_subject,
        );
        let issued_signature = ca.issue_for(
            signature_subject,
            csr.info.public_key.clone(),
            vec![ext_key_usage(
                KeyUsages::DigitalSignature | KeyUsages::NonRepudiation,
            )],
        );
        install(&mut yubikey, SLOT_SIGNATURE, &issued_signature);
        capture(
            &format!("{variant}_09_issued_signature.der"),
            &issued_signature.to_der().expect("encode certificate"),
        );
        capture_attestation_held(
            &mut yubikey,
            &format!("{variant}_09_issued_signature_attestation.der"),
            SLOT_SIGNATURE,
            &signature_spki,
        );

        // Step 10: user PIV authentication credential.
        let piv_spki = generate_key(&mut yubikey, SLOT_PIV_AUTH, KT::ALGORITHM);
        let piv_subject = "CN=test user authentication";
        let csr = csr_on_card::<KT>(&mut yubikey, SLOT_PIV_AUTH, &piv_spki, piv_subject);
        let issued_piv = ca.issue_for(
            piv_subject,
            csr.info.public_key.clone(),
            vec![
                ext_key_usage(KeyUsages::DigitalSignature),
                ext_policy(TEST_HARDWARE_POLICY),
            ],
        );
        install(&mut yubikey, SLOT_PIV_AUTH, &issued_piv);
        capture(
            &format!("{variant}_10_issued_piv.der"),
            &issued_piv.to_der().expect("encode certificate"),
        );
        capture_attestation_held(
            &mut yubikey,
            &format!("{variant}_10_issued_piv_attestation.der"),
            SLOT_PIV_AUTH,
            &piv_spki,
        );

        //----------------------------------------------------------------------------------
        // Recovered decryption keys
        //----------------------------------------------------------------------------------

        // Steps 11 and 11b: three keys the issuer generated and escrowed, delivered as PKCS #12
        // and imported. Index 0 is the current decryption credential and lands in the key
        // management slot; the rest are historical and fill retired slots.
        for (index, slot) in SLOTS_RECOVERED.iter().copied().enumerate() {
            let label = if index == 0 {
                "current".to_string()
            } else {
                format!("historical {index}")
            };
            let subject = format!("CN=test user encryption {index}");

            // Generated off the card, because a recovered key by definition was not generated
            // on it.
            let recovered_key = generate_recovered_key(decryption, index);
            let cert = ca.issue_for(
                &subject,
                recovered_key.spki.clone(),
                vec![ext_key_usage(KeyUsages::KeyEncipherment)],
            );

            // Out through a PKCS #12 and back in, rather than handing the in-memory key straight
            // to the card: the delivery format is part of what is being tested.
            let p12 = Pkcs12Builder::new()
                .build_with_rng(
                    &cert,
                    &recovered_key.key_der,
                    P12_PASSWORD,
                    &mut rand::rng(),
                )
                .expect("build PKCS #12");
            capture(&format!("{variant}_11_recovered_{index}.p12"), &p12);

            let recovered = parse_pkcs12(&p12, P12_PASSWORD).expect("parse PKCS #12");
            let recovered_cert = x509_cert::Certificate::from_der(&recovered.certificate.der)
                .expect("parse certificate");

            import_recovered_key(
                &mut yubikey,
                slot,
                decryption,
                &recovered.key_der,
                &format!("the {label} recovered key"),
            );

            install(&mut yubikey, slot, &recovered_cert);
            capture(
                &format!("{variant}_11_recovered_{index}.der"),
                &recovered_cert.to_der().expect("encode certificate"),
            );

            // Step 15: an imported key is only provisioned if it actually decapsulates. There is
            // no attestation to fall back on -- attestation covers keys the device generated.
            round_trip_decryption(
                &mut yubikey,
                slot,
                recovered_cert.tbs_certificate().subject_public_key_info(),
                &format!("recovered {label}"),
            );
        }

        //----------------------------------------------------------------------------------
        // Use the keys
        //----------------------------------------------------------------------------------

        // Steps 13, 14 and 15: use every credential the enrollment installed, now that all seven
        // slots are populated.
        exercise_provisioned_credentials::<KT>(&mut yubikey);

        //----------------------------------------------------------------------------------
        // Provisioned state
        //----------------------------------------------------------------------------------

        // Step 16: what the device says it is holding, from this crate rather than from
        // yubico-piv-tool, which cannot read certificates this size.
        report_provisioned_state(&mut yubikey);
    }

    /// Encapsulates off the card and decapsulates on it, for one ML-KEM parameter set.
    ///
    /// A macro rather than a generic function: `ml-kem` does not export the trait that bounds its
    /// parameter sets, so there is nothing to write the bound against.
    macro_rules! kem_round_trip {
        ($params:ty, $yubikey:expr, $slot:expr, $spki:expr, $algorithm:expr) => {{
            let encapsulation_key = MlKemEncapsulationKey::<$params>::try_from($spki)
                .unwrap_or_else(|_| panic!("parse the ML-KEM public key in {}", $slot));

            // Deterministic: there is nothing to protect in a test vector, and a failure
            // reproduces exactly.
            let (ciphertext, expected) =
                encapsulation_key.encapsulate_deterministic(&[3u8; 32].into());

            authenticate($yubikey);
            let shared = timed(format!("decapsulate in {}", $slot), || {
                piv::decapsulate($yubikey, ciphertext.as_slice(), $algorithm, $slot)
                    .unwrap_or_else(|e| panic!("decapsulate in {}: {e:?}", $slot))
            });

            (expected.as_slice().to_vec(), shared.as_slice().to_vec())
        }};
    }

    /// Establishes a secret with the key in `slot` off the card, recovers it on the card, and
    /// requires the two to agree.
    ///
    /// How that is done follows the key: ML-KEM encapsulates and decapsulates, RSA encrypts and
    /// decrypts. Dispatching on the certificate's own algorithm rather than on a parameter means
    /// the caller does not have to know, and a slot whose key is not what was expected fails here
    /// with a message that says so.
    fn round_trip_decryption(
        yubikey: &mut YubiKey,
        slot: SlotId,
        spki: &SubjectPublicKeyInfoOwned,
        label: &str,
    ) {
        let enc_spki = spki.to_der().expect("encode public key");
        let spki_ref = SubjectPublicKeyInfoRef::from_der(&enc_spki).expect("parse public key");

        let (established, recovered) = match spki.algorithm.oid {
            oid if oid == ID_ALG_ML_KEM_512 => {
                kem_round_trip!(
                    ml_kem::MlKem512,
                    yubikey,
                    slot,
                    spki_ref,
                    AlgorithmId::MlKem512
                )
            }
            oid if oid == ID_ALG_ML_KEM_768 => {
                kem_round_trip!(MlKem768, yubikey, slot, spki_ref, AlgorithmId::MlKem768)
            }
            oid if oid == ID_ALG_ML_KEM_1024 => {
                kem_round_trip!(
                    ml_kem::MlKem1024,
                    yubikey,
                    slot,
                    spki_ref,
                    AlgorithmId::MlKem1024
                )
            }
            oid if oid == RSA_ENCRYPTION => rsa_round_trip(yubikey, slot, spki_ref),
            other => panic!("{label}: no decryption round trip for {other}"),
        };

        assert_eq!(
            established, recovered,
            "{label}: the card did not recover the secret that was sent to it"
        );
        eprintln!(
            "{label}: secret established and recovered ({} bytes)",
            established.len()
        );
    }

    /// Encrypts a secret to the card's RSA key and decrypts it there.
    ///
    /// This is the arrangement post-quantum enrollment replaces: one RSA key that both signs and
    /// decrypts, so the slot holding the signing credential is also the one that opens traffic.
    fn rsa_round_trip(
        yubikey: &mut YubiKey,
        slot: SlotId,
        spki: SubjectPublicKeyInfoRef<'_>,
    ) -> (Vec<u8>, Vec<u8>) {
        let public_key =
            RsaPublicKey::try_from(spki).unwrap_or_else(|_| panic!("parse the RSA key in {slot}"));
        let algorithm = match rsa::traits::PublicKeyParts::n(&public_key).bits_precision() {
            2048 => AlgorithmId::Rsa2048,
            3072 => AlgorithmId::Rsa3072,
            4096 => AlgorithmId::Rsa4096,
            bits => panic!("unsupported RSA modulus size in {slot}: {bits}"),
        };

        let secret = [7u8; 32];
        let ciphertext = public_key
            .encrypt(&mut rand::rng(), rsa::Pkcs1v15Encrypt, &secret)
            .expect("encrypt to the card's RSA key");

        authenticate(yubikey);
        let plain = timed(format!("decrypt in {slot}"), || {
            piv::decrypt_data(yubikey, &ciphertext, algorithm, slot)
                .unwrap_or_else(|e| panic!("decrypt in {slot}: {e:?}"))
        });

        // The card returns the padded block; the message is what follows the first zero after the
        // leading 0x00 0x02.
        let recovered = match plain.iter().skip(2).position(|b| *b == 0) {
            Some(offset) => plain[offset + 3..].to_vec(),
            None => panic!("no PKCS #1 v1.5 padding separator in the decrypted block"),
        };

        (secret.to_vec(), recovered)
    }

    /// Verifies an ML-DSA signature off the card, for one parameter set.
    ///
    /// A macro for the same reason as [`kem_round_trip`]: the parameter set is a type, and the
    /// three differ only in that type.
    macro_rules! ml_dsa_verify {
        ($params:ty, $spki:expr, $message:expr, $signature:expr, $label:expr) => {{
            let verifying_key = MlDsaVerifyingKey::<$params>::try_from($spki)
                .unwrap_or_else(|_| panic!("{}: parse the ML-DSA public key", $label));
            let encoded = ml_dsa::EncodedSignature::<$params>::try_from($signature)
                .unwrap_or_else(|_| panic!("{}: unexpected ML-DSA signature size", $label));
            let parsed = MlDsaSoftSignature::<$params>::decode(&encoded)
                .unwrap_or_else(|| panic!("{}: malformed ML-DSA signature", $label));
            signature::Verifier::verify(&verifying_key, $message, &parsed)
                .unwrap_or_else(|e| panic!("{}: verify ML-DSA signature: {e:?}", $label));
        }};
    }

    /// Signs a fixed message with the key in `slot` and verifies it against `spki` off the card.
    ///
    /// The verification follows the key's own algorithm, so one call covers every signing family
    /// the matrix exercises.
    fn sign_and_verify<KT: yubikey_signer::KeyType>(
        yubikey: &mut YubiKey,
        slot: SlotId,
        spki: &SubjectPublicKeyInfoOwned,
        label: &str,
    ) {
        const MESSAGE: &[u8] = b"ykpqc enrollment flow";

        authenticate(yubikey);
        let signer = yubikey_signer::Signer::<'_, KT>::new(yubikey, slot, spki.owned_to_ref())
            .unwrap_or_else(|e| panic!("{label}: create a card signer: {e:?}"));
        let signature = timed(format!("sign a message with {slot}"), || {
            signature::Signer::try_sign(&signer, MESSAGE)
                .unwrap_or_else(|e| panic!("{label}: sign: {e:?}"))
        });

        // The signer holds the YubiKey for its lifetime; release it before anything else runs.
        drop(signer);

        // Via the BIT STRING encoding because it is the one representation every signature type
        // here shares -- RSA and ML-DSA have nothing else in common.
        let bitstring = signature
            .to_bitstring()
            .unwrap_or_else(|e| panic!("{label}: encode signature: {e:?}"));
        let raw = bitstring.raw_bytes();

        let enc_spki = spki.to_der().expect("encode public key");
        let spki_ref = SubjectPublicKeyInfoRef::from_der(&enc_spki).expect("parse public key");

        match spki.algorithm.oid {
            oid if oid == ID_ML_DSA_44 => ml_dsa_verify!(MlDsa44, spki_ref, MESSAGE, raw, label),
            oid if oid == ID_ML_DSA_65 => ml_dsa_verify!(MlDsa65, spki_ref, MESSAGE, raw, label),
            oid if oid == ID_ML_DSA_87 => ml_dsa_verify!(MlDsa87, spki_ref, MESSAGE, raw, label),
            oid if oid == RSA_ENCRYPTION => {
                let public_key = RsaPublicKey::try_from(spki_ref)
                    .unwrap_or_else(|_| panic!("{label}: parse the RSA public key"));
                let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
                let parsed = pkcs1v15::Signature::try_from(raw)
                    .unwrap_or_else(|e| panic!("{label}: malformed RSA signature: {e:?}"));
                verifying_key
                    .verify_prehash(&Sha256::digest(MESSAGE), &parsed)
                    .unwrap_or_else(|e| panic!("{label}: verify RSA signature: {e:?}"));
            }
            other => panic!("{label}: no off-card verification for {other}"),
        }

        eprintln!("{label}: signature verified off the card");
    }

    /// Signs or decapsulates with every credential the enrollment installed.
    ///
    /// Keyed off the certificate **read back out of each slot**, not off anything held from when
    /// the key was generated: that is the difference between "this key works" and "the credential
    /// on this device works". A slot holding a certificate whose key is not the one beside it
    /// fails here and nowhere else.
    ///
    /// Run once at the end rather than inline, so a credential that worked when installed but
    /// stopped working as the rest of the provisioning went in is caught too.
    fn exercise_provisioned_credentials<KT: yubikey_signer::KeyType>(yubikey: &mut YubiKey) {
        for (label, slot) in [
            ("device signing", SLOT_DEVICE_SIGNING),
            ("user signature", SLOT_SIGNATURE),
            ("user PIV authentication", SLOT_PIV_AUTH),
        ] {
            let cert = Certificate::read(yubikey, slot)
                .unwrap_or_else(|e| panic!("read the certificate in {slot}: {e:?}"));
            let spki = cert
                .cert
                .tbs_certificate()
                .subject_public_key_info()
                .clone();
            sign_and_verify::<KT>(yubikey, slot, &spki, label);
        }

        let mut kem_slots = vec![("device KEM".to_string(), SLOT_DEVICE_KEM)];
        for (index, slot) in SLOTS_RECOVERED.iter().copied().enumerate() {
            let label = if index == 0 {
                "recovered encryption (current)".to_string()
            } else {
                format!("recovered encryption (historical {index})")
            };
            kem_slots.push((label, slot));
        }

        for (label, slot) in kem_slots {
            let cert = Certificate::read(yubikey, slot)
                .unwrap_or_else(|e| panic!("read the certificate in {slot}: {e:?}"));
            let spki = cert
                .cert
                .tbs_certificate()
                .subject_public_key_info()
                .clone();
            round_trip_decryption(yubikey, slot, &spki, &label);
        }
    }

    /// A decryption key the issuer generated and escrowed, before it reaches the device.
    struct RecoveredKey {
        /// PKCS #8 encoding of the private key, which is how it travels inside a PKCS #12.
        key_der: Vec<u8>,
        /// The public half, for the certificate the CA issues over it.
        spki: SubjectPublicKeyInfoOwned,
    }

    /// Generates a recovered decryption key off the card, in whichever family the variant uses.
    ///
    /// Seeded from `index` rather than random so a failing run repeats against identical
    /// material. RSA is generated rather than seeded -- key generation there is a search, and
    /// there is no seed to fix.
    fn generate_recovered_key(algorithm: AlgorithmId, index: usize) -> RecoveredKey {
        match algorithm {
            AlgorithmId::MlKem512 | AlgorithmId::MlKem768 | AlgorithmId::MlKem1024 => {
                /// Builds a recovered key for one ML-KEM parameter set.
                ///
                /// The seed is 64 octets whichever parameter set is in play, so a mismatch here
                /// survives generation, survives import, and only surfaces when the ciphertext
                /// turns out to be the wrong length for the key in the slot.
                macro_rules! recovered_ml_kem {
                    ($params:ty, $seed:expr) => {{
                        let key = MlKemDecapsulationKey::<$params>::from_seed($seed);
                        RecoveredKey {
                            key_der: key
                                .to_pkcs8_der()
                                .expect("encode decapsulation key")
                                .as_bytes()
                                .to_vec(),
                            spki: spki_of(key.encapsulation_key()),
                        }
                    }};
                }

                let seed: ml_kem::Seed = [(index as u8) + 0x40; 64].into();
                match algorithm {
                    AlgorithmId::MlKem512 => recovered_ml_kem!(ml_kem::MlKem512, seed),
                    AlgorithmId::MlKem768 => recovered_ml_kem!(MlKem768, seed),
                    _ => recovered_ml_kem!(ml_kem::MlKem1024, seed),
                }
            }
            AlgorithmId::Rsa2048 | AlgorithmId::Rsa3072 | AlgorithmId::Rsa4096 => {
                let bits = match algorithm {
                    AlgorithmId::Rsa2048 => 2048,
                    AlgorithmId::Rsa3072 => 3072,
                    _ => 4096,
                };
                let key =
                    rsa::PrivateKey::new(&mut rand::rng(), bits).expect("generate an RSA key");
                RecoveredKey {
                    key_der: key
                        .to_pkcs8_der()
                        .expect("encode RSA key")
                        .as_bytes()
                        .to_vec(),
                    spki: spki_of(&key.to_public_key()),
                }
            }
            other => panic!("no recovered-key generation for {other:?}"),
        }
    }

    /// Imports a recovered private key, recovered from the PKCS #12 it arrived in.
    ///
    /// The two families want quite different things: ML-KEM takes the generating seed, while RSA
    /// takes its secret primes and the applet derives the rest. Both go through `write_key`, so
    /// this is what exercises the element lengths and parameter tags for each.
    fn import_recovered_key(
        yubikey: &mut YubiKey,
        slot: SlotId,
        algorithm: AlgorithmId,
        key_der: &[u8],
        label: &str,
    ) {
        authenticate(yubikey);

        match algorithm {
            AlgorithmId::MlKem512 | AlgorithmId::MlKem768 | AlgorithmId::MlKem1024 => {
                /// Recovers the seed from a PKCS #8 decapsulation key, for one parameter set.
                macro_rules! seed_of {
                    ($params:ty) => {{
                        let key = MlKemDecapsulationKey::<$params>::try_from(
                            PrivateKeyInfoRef::from_der(key_der).expect("parse PKCS #8"),
                        )
                        .expect("parse decapsulation key");
                        key.to_seed().expect("decapsulation key carries a seed")
                    }};
                }

                let seed = match algorithm {
                    AlgorithmId::MlKem512 => seed_of!(ml_kem::MlKem512),
                    AlgorithmId::MlKem768 => seed_of!(MlKem768),
                    _ => seed_of!(ml_kem::MlKem1024),
                };

                timed(format!("import {algorithm:?} into {slot}"), || {
                    piv::import_pqc_key(
                        yubikey,
                        slot,
                        algorithm,
                        seed.as_slice(),
                        TouchPolicy::Default,
                        PinPolicy::Default,
                    )
                    .unwrap_or_else(|e| panic!("import {label} into {slot}: {e:?}"))
                });
            }
            AlgorithmId::Rsa2048 | AlgorithmId::Rsa3072 | AlgorithmId::Rsa4096 => {
                let key =
                    <rsa::PrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_der(key_der)
                        .expect("parse RSA key");
                let primes = rsa::traits::PrivateKeyParts::primes(&key);
                assert_eq!(primes.len(), 2, "{label}: expected a two-prime RSA key");

                let key_data =
                    piv::RsaKeyData::new(&primes[0].to_be_bytes(), &primes[1].to_be_bytes())
                        .expect("build RSA key data");

                timed(format!("import {algorithm:?} into {slot}"), || {
                    piv::import_rsa_key(
                        yubikey,
                        slot,
                        algorithm,
                        key_data,
                        TouchPolicy::Default,
                        PinPolicy::Default,
                    )
                    .unwrap_or_else(|e| panic!("import {label} into {slot}: {e:?}"))
                });
            }
            other => panic!("no key import for {other:?}"),
        }
    }

    /// Reports what each provisioned slot holds.
    fn report_provisioned_state(yubikey: &mut YubiKey) {
        let mut slots: Vec<(String, SlotId)> = vec![
            ("device signing".to_string(), SLOT_DEVICE_SIGNING),
            ("device KEM".to_string(), SLOT_DEVICE_KEM),
            ("signature".to_string(), SLOT_SIGNATURE),
            ("PIV authentication".to_string(), SLOT_PIV_AUTH),
        ];
        for (index, slot) in SLOTS_RECOVERED.iter().copied().enumerate() {
            let label = if index == 0 {
                "recovered encryption (current)".to_string()
            } else {
                format!("recovered encryption (historical {index})")
            };
            slots.push((label, slot));
        }

        // Every slot the enrollment touched has to answer. A missing certificate here means an
        // earlier step reported success over a write that did not land.
        for (label, slot) in &slots {
            match Certificate::read(yubikey, *slot) {
                Ok(cert) => eprintln!(
                    "{label} ({slot}): {}",
                    cert.cert.tbs_certificate().subject()
                ),
                Err(e) => panic!("{label} ({slot}) has no certificate: {e:?}"),
            }
        }

        // Keys, separately from certificates: `Key::list` reports what the device holds rather
        // than what was written to it, so a slot with a certificate but no key shows up here.
        match Key::list(yubikey) {
            Ok(keys) => eprintln!("{} keys present", keys.len()),
            Err(e) => panic!("failed to list keys: {e:?}"),
        }

        assert_eq!(
            slots.len(),
            7,
            "the end state is seven slots: two device credentials, signature, PIV, and three recovered"
        );
    }

    /// One row of the algorithm matrix.
    struct Variant {
        /// Short name, used to prefix this variant's artifacts.
        name: &'static str,
        /// Algorithm for the three signing credentials.
        signing: AlgorithmId,
        /// Algorithm for the device and recovered decryption credentials.
        decryption: AlgorithmId,
    }

    /// Every combination the simulated enrollment is run against.
    ///
    /// The RSA rows are the model post-quantum enrollment replaces, where a single algorithm both
    /// signs and decrypts; they are here because the crate changes for ML-DSA and ML-KEM sit on
    /// paths RSA shares, and because derived PIV credentials are issued with RSA today.
    const VARIANTS: [Variant; 6] = [
        Variant {
            name: "rsa2048",
            signing: AlgorithmId::Rsa2048,
            decryption: AlgorithmId::Rsa2048,
        },
        Variant {
            name: "rsa3072",
            signing: AlgorithmId::Rsa3072,
            decryption: AlgorithmId::Rsa3072,
        },
        Variant {
            name: "rsa4096",
            signing: AlgorithmId::Rsa4096,
            decryption: AlgorithmId::Rsa4096,
        },
        Variant {
            name: "mldsa44",
            signing: AlgorithmId::MlDsa44,
            decryption: AlgorithmId::MlKem512,
        },
        Variant {
            name: "mldsa65",
            signing: AlgorithmId::MlDsa65,
            decryption: AlgorithmId::MlKem768,
        },
        Variant {
            name: "mldsa87",
            signing: AlgorithmId::MlDsa87,
            decryption: AlgorithmId::MlKem1024,
        },
    ];

    /// Runs one variant, choosing the card signer its algorithm needs.
    fn run_variant(variant: &Variant) {
        use yubikey_signer::{Rsa2048, Rsa3072, Rsa4096, YubiRsa};

        match variant.signing {
            AlgorithmId::Rsa2048 => {
                enrollment_flow::<YubiRsa<Rsa2048>>(variant.name, variant.decryption)
            }
            AlgorithmId::Rsa3072 => {
                enrollment_flow::<YubiRsa<Rsa3072>>(variant.name, variant.decryption)
            }
            AlgorithmId::Rsa4096 => {
                enrollment_flow::<YubiRsa<Rsa4096>>(variant.name, variant.decryption)
            }
            AlgorithmId::MlDsa44 => {
                enrollment_flow::<CardMlDsa44>(variant.name, variant.decryption)
            }
            AlgorithmId::MlDsa65 => {
                enrollment_flow::<CardMlDsa65>(variant.name, variant.decryption)
            }
            AlgorithmId::MlDsa87 => {
                enrollment_flow::<CardMlDsa87>(variant.name, variant.decryption)
            }
            other => panic!("no card signer for {other:?}"),
        }
    }

    /// Runs the simulated enrollment against every algorithm pair in [`VARIANTS`].
    ///
    /// Each variant resets the device first, so they do not interfere and the order does not
    /// matter. A variant whose algorithms this applet does not implement still runs and still
    /// fails -- what it cannot do is pass quietly, which is the outcome that would matter.
    #[test]
    #[ignore]
    fn derived_piv_enrollment_matrix() {
        let selected = env::var("PQC_VARIANTS").unwrap_or_default();

        for variant in &VARIANTS {
            // Unset runs everything; otherwise a comma-separated list picks rows out of the
            // matrix, which is what makes re-testing one algorithm pair affordable.
            if !selected.is_empty() && !selected.split(',').any(|name| name == variant.name) {
                continue;
            }

            eprintln!(
                "\n=== {} : {:?} signing, {:?} decryption ===",
                variant.name, variant.signing, variant.decryption
            );
            run_variant(variant);
        }
    }

    /// Runs the simulated enrollment against ML-DSA-65 and ML-KEM-768 only.
    ///
    /// The pair this applet actually implements, for when the whole matrix is more than the
    /// question at hand warrants.
    #[test]
    #[ignore]
    fn derived_piv_enrollment_flow() {
        enrollment_flow::<CardMlDsa65>("mldsa65", AlgorithmId::MlKem768);
    }
}
