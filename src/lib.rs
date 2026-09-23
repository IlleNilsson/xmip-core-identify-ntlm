#![forbid(unsafe_code)]

//! Identify by ntlm: the user and domain of an NTLM AUTHENTICATE message,
//! read and not verified.
//!
//! MS-NLMP runs in three messages: the client's NEGOTIATE (type 1), the
//! server's CHALLENGE (type 2), and the client's AUTHENTICATE (type 3),
//! which names the user, the domain and the workstation in the clear and
//! carries the `NTLMv2` response over the challenge. This identifier reads
//! the names out of a type 3 and calls the user the claim: the domain and
//! workstation ride beside it as evidence, and the whole message rides as
//! proof for `authenticate/ntlm` to check the response against the stored
//! hash. Nothing here checks it. A type 1 claims nothing yet and presents
//! nothing; a type 2 is the server's and cannot be a credential.
//!
//! RFC 4559 carries the message as `Authorization: NTLM <base64>`, and the
//! `Negotiate` scheme carries the same bytes when the client chose NTLM
//! under SPNEGO — the `NTLMSSP` signature tells. A `Negotiate` value that
//! is not NTLMSSP is `kerberos`'s business and presents nothing here.
//!
//! What this reads and writes:
//!
//! ```text
//! http.header.authorization   NTLM <base64> or Negotiate <base64>   the property
//! ntlm.domain                 the DomainName field                  evidence, where present
//! ntlm.workstation            the Workstation field                 evidence, where present
//! principal.user              the user within the domain            evidence, where a domain
//! ntlm.target                 the target name, as the client wrote it    evidence
//! ntlm.target.untrusted       true                                  evidence, where flagged
//! principal.service           the target, canonical                 evidence, where trusted
//! ntlm.authenticate           the type 3 message, base64            proof
//! ntlm.negotiate              the type 1 message, base64            proof, where the transport
//! ntlm.challenge              the type 2 message, base64            proof, where the transport
//! ```
//!
//! The last two are not the client's to send again: they are the first two
//! legs of this connection's handshake, which only the transport saw. A
//! transport that keeps them writes them as the properties `ntlm.negotiate`
//! and `ntlm.challenge`, and they ride on as proofs of the same names so the
//! second gate can check the MIC the client computed over all three messages
//! ([MS-NLMP] 3.1.5.1.2). Where the transport writes neither, neither rides.
//!
//! Where the message names a domain, the user and the domain together are a
//! user principal name, written as `principal.user` in the capability's
//! canonical form (ADR-0054); the claim stays the user. The service the
//! client meant to reach rides inside the `NTLMv2` response, among its
//! attribute and value pairs, read by the capability's
//! `identify::ntlm::ClientChallenge` because both gates need it: it is
//! written as the client wrote it, and as `principal.service` where it is a
//! service principal name and the client does not flag it as taken from an
//! untrusted source, which [MS-NLMP] 3.2.5.1.2 has a server treat as no name.
//! The response's proof covers those pairs, so the second gate's verdict
//! covers the target too; here it is read and not believed.
//!
//! Only a pushed arrival carries a passed claim.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use identify::authorization::{self, AUTHORIZATION};
use identify::ntlm::ClientChallenge;
use identify::{
    IdentifyError, Presented, ServicePrincipalName, StreamArrival, TransportIdentifier,
    UserPrincipalName, principal,
};
use xcore::{Arriving, Mechanism};

/// The evidence name carrying the domain.
pub const DOMAIN: &str = "ntlm.domain";
/// The evidence name carrying the workstation.
pub const WORKSTATION: &str = "ntlm.workstation";
/// The proof name the base64 message rides under.
pub const AUTHENTICATE_PROOF: &str = "ntlm.authenticate";
/// The property a transport writes the handshake's type 1 message under, and
/// the proof it rides on as.
pub const NEGOTIATE_PROOF: &str = "ntlm.negotiate";
/// The same for the type 2 message the node answered with.
pub const CHALLENGE_PROOF: &str = "ntlm.challenge";
/// The evidence name carrying the target name, as the client wrote it.
pub const TARGET: &str = "ntlm.target";
/// The evidence name saying the client took the target from an untrusted source.
pub const TARGET_UNTRUSTED: &str = "ntlm.target.untrusted";

const SIGNATURE: &[u8] = b"NTLMSSP\0";
const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
const DOMAIN_FIELDS: usize = 28;
const USER_FIELDS: usize = 36;
const WORKSTATION_FIELDS: usize = 44;
const FLAGS: usize = 60;
const NT_RESPONSE_FIELDS: usize = 20;
const PROOF: usize = 16;

/// The names an AUTHENTICATE message carries in the clear.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authenticate {
    pub user: String,
    pub domain: String,
    pub workstation: String,
}

impl Authenticate {
    /// Read the names out of an NTLMSSP message.
    ///
    /// `None` for a NEGOTIATE, which claims nothing yet.
    ///
    /// # Errors
    ///
    /// Where the bytes are not an NTLMSSP message, are a CHALLENGE, are
    /// truncated, or name no user.
    pub fn parse(bytes: &[u8]) -> Result<Option<Self>, IdentifyError> {
        if !bytes.starts_with(SIGNATURE) || bytes.len() < 12 {
            return Err(IdentifyError::new(
                "the NTLM message has no NTLMSSP signature",
            ));
        }
        match u32_at(bytes, 8) {
            Some(1) => return Ok(None),
            Some(2) => {
                return Err(IdentifyError::new(
                    "the NTLM message is a CHALLENGE: the server's, not a credential",
                ));
            }
            Some(3) => {}
            _ => return Err(IdentifyError::new("the NTLM message type is not 1, 2 or 3")),
        }
        let Some(flags) = u32_at(bytes, FLAGS) else {
            return Err(IdentifyError::new(
                "the NTLM AUTHENTICATE message is truncated before its flags",
            ));
        };
        let unicode = flags & NEGOTIATE_UNICODE != 0;

        let user = field(bytes, USER_FIELDS, unicode, "UserName")?;
        if user.is_empty() {
            return Err(IdentifyError::new(
                "the NTLM AUTHENTICATE message names no user",
            ));
        }
        Ok(Some(Self {
            user,
            domain: field(bytes, DOMAIN_FIELDS, unicode, "DomainName")?,
            workstation: field(bytes, WORKSTATION_FIELDS, unicode, "Workstation")?,
        }))
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|quad| u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

/// One `Len, MaxLen, BufferOffset` field, and the text it points at.
fn field(bytes: &[u8], at: usize, unicode: bool, name: &str) -> Result<String, IdentifyError> {
    let (Some(length), Some(offset)) = (u16_at(bytes, at), u32_at(bytes, at + 4)) else {
        return Err(IdentifyError::new(format!(
            "the NTLM AUTHENTICATE message is truncated before its {name} field"
        )));
    };
    let (length, offset) = (usize::from(length), offset as usize);
    let Some(payload) = bytes.get(offset..offset + length) else {
        return Err(IdentifyError::new(format!(
            "the NTLM AUTHENTICATE message's {name} points outside the message"
        )));
    };

    if unicode {
        let units: Vec<u16> = payload
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        String::from_utf16(&units)
            .map_err(|_| IdentifyError::new(format!("the NTLM {name} is not UTF-16")))
    } else {
        Ok(payload.iter().map(|byte| char::from(*byte)).collect())
    }
}

/// The client's half of the NT response, where the message carries an
/// `NTLMv2` one: what follows the sixteen bytes of proof.
fn client_challenge(bytes: &[u8]) -> Result<Option<ClientChallenge>, IdentifyError> {
    let (Some(length), Some(offset)) = (
        u16_at(bytes, NT_RESPONSE_FIELDS),
        u32_at(bytes, NT_RESPONSE_FIELDS + 4),
    ) else {
        return Ok(None);
    };
    let (length, offset) = (usize::from(length), offset as usize);

    if length <= PROOF {
        return Ok(None);
    }

    let Some(response) = bytes.get(offset..offset.saturating_add(length)) else {
        return Err(IdentifyError::new(
            "the NTLM AUTHENTICATE message's NtChallengeResponse points outside the message",
        ));
    };

    ClientChallenge::read(&response[PROOF..])
}

/// Reads the names out of the AUTHENTICATE message the client sent.
#[derive(Clone, Copy, Debug, Default)]
pub struct Ntlm;

impl TransportIdentifier for Ntlm {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::ntlm()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }
        let Some((scheme, encoded)) = arrival.property(AUTHORIZATION).map(authorization::scheme)
        else {
            return Ok(None);
        };
        let negotiate = scheme.eq_ignore_ascii_case("negotiate");
        if !negotiate && !scheme.eq_ignore_ascii_case("ntlm") {
            return Ok(None);
        }

        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| IdentifyError::new("the NTLM message is not base64"))?;
        if negotiate && !bytes.starts_with(SIGNATURE) {
            return Ok(None);
        }

        let Some(authenticate) = Authenticate::parse(&bytes)? else {
            return Ok(None);
        };
        let principal = UserPrincipalName::of(&authenticate.user, &authenticate.domain);
        let mut claim = Presented::passed(self.mechanism(), authenticate.user);
        if !authenticate.domain.is_empty() {
            claim = claim.with_evidence(DOMAIN, authenticate.domain);
        }
        if !authenticate.workstation.is_empty() {
            claim = claim.with_evidence(WORKSTATION, authenticate.workstation);
        }
        if let Some(principal) = principal {
            claim = claim.with_evidence(principal::USER, principal.to_string());
        }
        if let Some(read) = client_challenge(&bytes)?
            && let Some(name) = read.target.as_deref()
        {
            claim = claim.with_evidence(TARGET, name);

            if read.untrusted {
                claim = claim.with_evidence(TARGET_UNTRUSTED, "true");
            }
            if let Some(service) = read.supplied_target().and_then(ServicePrincipalName::parse) {
                claim = claim.with_evidence(principal::SERVICE, service.to_string());
            }
        }
        for leg in [NEGOTIATE_PROOF, CHALLENGE_PROOF] {
            if let Some(message) = arrival.property(leg) {
                claim = claim.with_proof(leg, message.trim());
            }
        }
        Ok(Some(claim.with_proof(AUTHENTICATE_PROOF, encoded)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stream::Stream;
    use xcore::{Established, Layer, StreamId};

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// An AUTHENTICATE message with the three names, Unicode, and empty
    /// responses: the shape MS-NLMP 2.2.1.3 gives it.
    fn authenticate(user: &str, domain: &str, workstation: &str) -> Vec<u8> {
        authenticate_answering(user, domain, workstation, Vec::new())
    }

    /// An `NTLMv2` response: sixteen bytes of proof, then the client's blob.
    fn answering(target: Option<&str>, flags: u32) -> Vec<u8> {
        let mut response = vec![0xAB; PROOF];
        response.extend(identify::ntlm::blob_for(1_800_000_000, target, flags));
        response
    }

    /// The same message carrying an NT response.
    fn authenticate_answering(
        user: &str,
        domain: &str,
        workstation: &str,
        nt_response: Vec<u8>,
    ) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(SIGNATURE);
        message.extend_from_slice(&3u32.to_le_bytes());
        let payloads = [
            Vec::new(),
            nt_response,
            utf16(domain),
            utf16(user),
            utf16(workstation),
            Vec::new(),
        ];
        let mut offset = 64u32;
        for payload in &payloads {
            let length = u16::try_from(payload.len()).expect("short");
            message.extend_from_slice(&length.to_le_bytes());
            message.extend_from_slice(&length.to_le_bytes());
            message.extend_from_slice(&offset.to_le_bytes());
            offset += u32::from(length);
        }
        message.extend_from_slice(&NEGOTIATE_UNICODE.to_le_bytes());
        for payload in &payloads {
            message.extend_from_slice(payload);
        }
        message
    }

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"<order/>".to_vec(), None)
    }

    fn authorization(scheme: &str, bytes: &[u8]) -> Vec<(String, String)> {
        vec![(
            AUTHORIZATION.to_string(),
            format!("{scheme} {}", STANDARD.encode(bytes)),
        )]
    }

    #[test]
    fn a_type_3_is_presented_by_its_user_with_domain_and_workstation_beside() {
        let stream = stream();
        let properties = authorization("NTLM", &authenticate("jane", "PARTNERX", "WS01"));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = Ntlm.identify(&arrival).expect("read").expect("a claim");

        assert_eq!(claim.value, "jane");
        assert_eq!(claim.established, Established::Passed);
        assert_eq!(claim.layer(), Layer::Transport);
        assert_eq!(claim.mechanism.name(), "ntlm");
        assert_eq!(
            claim.evidence,
            vec![
                (DOMAIN.to_string(), "PARTNERX".to_string()),
                (WORKSTATION.to_string(), "WS01".to_string()),
                (principal::USER.to_string(), "jane@partnerx".to_string()),
            ]
        );
        let proof = claim.proof(AUTHENTICATE_PROOF).expect("proof");
        assert_eq!(properties[0].1, format!("NTLM {proof}"));
    }

    #[test]
    fn a_type_3_under_negotiate_reads_the_same_and_a_kerberos_token_does_not() {
        let stream = stream();
        let properties = authorization("Negotiate", &authenticate("jane", "", ""));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = Ntlm.identify(&arrival).expect("read").expect("a claim");
        assert_eq!(claim.value, "jane");
        assert!(claim.evidence.is_empty());

        let properties = authorization("Negotiate", &[0x60, 0x06, 0x06, 0x04, 0x2b, 0x06]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);
        assert!(Ntlm.identify(&arrival).expect("read").is_none());
    }

    #[test]
    fn the_user_within_the_domain_is_written_as_a_principal_name_in_canonical_form() {
        let stream = stream();
        let properties = authorization("NTLM", &authenticate("Jane", "Partner-X.Example", ""));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = Ntlm.identify(&arrival).expect("read").expect("a claim");

        assert_eq!(claim.value, "Jane", "the value stays the user");
        assert_eq!(
            claim.evidence,
            vec![
                (DOMAIN.to_string(), "Partner-X.Example".to_string()),
                (
                    principal::USER.to_string(),
                    "Jane@partner-x.example".to_string()
                ),
            ]
        );
    }

    #[test]
    fn a_user_without_a_domain_or_within_no_real_one_gains_no_principal_evidence() {
        let stream = stream();

        for domain in ["", "not a domain"] {
            let properties = authorization("NTLM", &authenticate("jane", domain, "WS01"));
            let arrival =
                StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

            let claim = Ntlm.identify(&arrival).expect("read").expect("a claim");

            assert!(
                claim
                    .evidence
                    .iter()
                    .all(|(name, _)| name != principal::USER && name != principal::SERVICE),
                "{domain}"
            );
        }
    }

    #[test]
    fn the_target_the_client_named_is_written_as_a_service_principal_name() {
        // MS-NLMP 2.2.2.1: MsvAvTargetName, among the pairs of the response.
        let stream = stream();
        let bytes = authenticate_answering(
            "jane",
            "PARTNERX",
            "WS01",
            answering(Some("HTTP/Xmip.Example"), 0x2),
        );
        let properties = authorization("NTLM", &bytes);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = Ntlm.identify(&arrival).expect("read").expect("a claim");
        let said = |name: &str| {
            claim
                .evidence
                .iter()
                .find(|(evidence, _)| evidence == name)
                .map(|(_, value)| value.as_str())
        };

        assert_eq!(claim.value, "jane");
        assert_eq!(said(TARGET), Some("HTTP/Xmip.Example"));
        assert_eq!(said(principal::SERVICE), Some("HTTP/xmip.example"));
        assert_eq!(said(principal::USER), Some("jane@partnerx"));
        assert_eq!(said(TARGET_UNTRUSTED), None);
    }

    #[test]
    fn a_target_from_an_untrusted_source_is_written_and_not_as_a_principal_name() {
        let stream = stream();
        let bytes = authenticate_answering(
            "jane",
            "PARTNERX",
            "WS01",
            answering(Some("HTTP/xmip.example"), 0x2 | 0x4),
        );
        let properties = authorization("NTLM", &bytes);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = Ntlm.identify(&arrival).expect("read").expect("a claim");
        let names: Vec<&str> = claim
            .evidence
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();

        assert!(names.contains(&TARGET), "{names:?}");
        assert!(names.contains(&TARGET_UNTRUSTED), "{names:?}");
        assert!(!names.contains(&principal::SERVICE), "{names:?}");
    }

    #[test]
    fn an_ntlmv1_response_names_no_target_and_one_outside_the_message_is_an_error() {
        let stream = stream();
        let older = authenticate_answering("jane", "PARTNERX", "WS01", vec![0x5A; 24]);
        let properties = authorization("NTLM", &older);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);
        let claim = Ntlm.identify(&arrival).expect("read").expect("a claim");
        assert!(claim.evidence.iter().all(|(name, _)| name != TARGET));

        // The names read whole; only the NT response is made to point away.
        let mut astray = authenticate_answering("jane", "PARTNERX", "WS01", answering(None, 0));
        astray[NT_RESPONSE_FIELDS + 4..NT_RESPONSE_FIELDS + 8]
            .copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        let properties = authorization("NTLM", &astray);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);
        let failure = Ntlm.identify(&arrival).expect_err("astray");
        assert!(failure.message.contains("NtChallengeResponse"), "{failure}");
    }

    #[test]
    fn the_handshakes_first_two_legs_ride_on_as_proofs_where_the_transport_kept_them() {
        let stream = stream();
        let mut properties = authorization("NTLM", &authenticate("jane", "PARTNERX", "WS01"));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);
        let claim = Ntlm.identify(&arrival).expect("read").expect("a claim");
        assert_eq!(claim.proof(NEGOTIATE_PROOF), None);

        properties.push((NEGOTIATE_PROOF.to_string(), "TlRMTVNTUAAB".to_string()));
        properties.push((CHALLENGE_PROOF.to_string(), " TlRMTVNTUAAC ".to_string()));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);
        let claim = Ntlm.identify(&arrival).expect("read").expect("a claim");

        assert_eq!(claim.proof(NEGOTIATE_PROOF), Some("TlRMTVNTUAAB"));
        assert_eq!(claim.proof(CHALLENGE_PROOF), Some("TlRMTVNTUAAC"));
        assert!(claim.proof(AUTHENTICATE_PROOF).is_some());
    }

    #[test]
    fn a_type_1_claims_nothing_yet_and_another_scheme_is_not_this_mechanism() {
        let stream = stream();
        let mut negotiate = SIGNATURE.to_vec();
        negotiate.extend_from_slice(&1u32.to_le_bytes());
        negotiate.extend_from_slice(&[0; 20]);
        let properties = authorization("NTLM", &negotiate);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);
        assert!(Ntlm.identify(&arrival).expect("read").is_none());

        let properties = [(AUTHORIZATION.to_string(), "Bearer abc".to_string())];
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);
        assert!(Ntlm.identify(&arrival).expect("read").is_none());
    }

    #[test]
    fn a_truncated_type_3_is_an_error_naming_where_it_stopped() {
        let stream = stream();
        let properties = authorization("NTLM", &authenticate("jane", "PARTNERX", "WS01")[..40]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let failure = Ntlm.identify(&arrival).expect_err("truncated");

        assert!(failure.message.contains("truncated"), "{failure}");
    }

    #[test]
    fn a_message_that_is_not_ntlmssp_is_an_error_naming_why() {
        let stream = stream();
        let properties = authorization("NTLM", b"not an NTLM message at all");
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let failure = Ntlm.identify(&arrival).expect_err("no signature");

        assert!(failure.message.contains("NTLMSSP signature"), "{failure}");
    }

    #[test]
    fn a_scheduled_pickup_presents_nothing_because_the_credential_was_xmips_own() {
        let stream = stream();
        let properties = authorization("NTLM", &authenticate("xmip", "", ""));
        let arrival = StreamArrival::new(
            &stream,
            Arriving::Scheduled,
            "https://share/out",
            &properties,
        );

        assert!(Ntlm.identify(&arrival).expect("read").is_none());
    }
}
