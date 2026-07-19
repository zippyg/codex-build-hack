mod generated;

use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write as _};
use std::path::{Component, Path};
use std::sync::OnceLock;

pub use generated::*;
use serde::Deserialize;
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const SCHEMA_BASE: &str = "https://promptectomy.invalid/schemas/v2/";
pub const SCHEMA_VERSION: &str = "2.0.0";
pub const MAX_SAFE_JSON_BYTES: usize = 2_000_000;

const SCHEMA_TEXT: &str = include_str!("../schema/contract.schema.json");
const ENTITY_DEFINITIONS: [(&str, &str); 15] = [
    ("repository.schema.json", "Repository"),
    ("snapshot.schema.json", "Snapshot"),
    ("authority.schema.json", "Authority"),
    ("run.schema.json", "Run"),
    ("stage.schema.json", "Stage"),
    ("event.schema.json", "Event"),
    ("callsite.schema.json", "Callsite"),
    ("observation.schema.json", "Observation"),
    ("finding.schema.json", "Finding"),
    ("candidate.schema.json", "Candidate"),
    ("evaluation.schema.json", "Evaluation"),
    ("patch.schema.json", "Patch"),
    ("artifact.schema.json", "Artifact"),
    ("receipt.schema.json", "Receipt"),
    ("error.schema.json", "Error"),
];

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("contract JSON exceeds the {0}-byte limit")]
    TooLarge(usize),
    #[error("contract JSON is not valid UTF-8")]
    Utf8,
    #[error("contract JSON must not contain a byte-order mark")]
    ByteOrderMark,
    #[error("contract JSON is invalid")]
    InvalidJson,
    #[error("contract JSON contains a duplicate member")]
    DuplicateMember,
    #[error("contract JSON contains a binary float")]
    BinaryFloat,
    #[error("contract JSON contains an integer outside the I-JSON range")]
    IntegerRange,
    #[error("contract root must be an object")]
    RootType,
    #[error("unsupported schema version")]
    SchemaVersion,
    #[error("unknown schema URI")]
    SchemaUri,
    #[error("canonical schema is invalid")]
    InvalidSchema,
    #[error("contract validation failed")]
    Validation,
    #[error("contract cannot be RFC 8785 canonicalized")]
    Canonicalization,
    #[error("digest purpose is invalid")]
    DigestPurpose,
    #[error("entity ID kind is invalid")]
    IdentifierKind,
    #[error("repository-relative path is invalid")]
    RelativePath,
}

#[derive(Debug)]
struct StrictValue(Value);

impl<'de> serde::Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict I-JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if !(-(2_i64.pow(53) - 1)..=(2_i64.pow(53) - 1)).contains(&value) {
            return Err(E::custom("integer_range"));
        }
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value > 2_u64.pow(53) - 1 {
            return Err(E::custom("integer_range"));
        }
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("binary_float"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom("duplicate_member"));
            }
            values.insert(key, map.next_value::<StrictValue>()?.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

pub fn parse_strict_json(content: &[u8], max_bytes: usize) -> Result<Value, ContractError> {
    if content.len() > max_bytes {
        return Err(ContractError::TooLarge(max_bytes));
    }
    let text = std::str::from_utf8(content).map_err(|_| ContractError::Utf8)?;
    if text.starts_with('\u{feff}') {
        return Err(ContractError::ByteOrderMark);
    }
    let mut deserializer = serde_json::Deserializer::from_str(text);
    match StrictValue::deserialize(&mut deserializer) {
        Ok(value) => {
            deserializer.end().map_err(|_| ContractError::InvalidJson)?;
            Ok(value.0)
        }
        Err(error) if error.to_string().starts_with("duplicate_member") => {
            Err(ContractError::DuplicateMember)
        }
        Err(error) if error.to_string().starts_with("binary_float") => {
            Err(ContractError::BinaryFloat)
        }
        Err(error) if error.to_string().starts_with("integer_range") => {
            Err(ContractError::IntegerRange)
        }
        Err(_) => Err(ContractError::InvalidJson),
    }
}

pub fn schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(SCHEMA_TEXT).expect("tracked Contract v2 schema must parse")
    })
}

pub fn validate_schema_document() -> Result<(), ContractError> {
    jsonschema::validator_for(schema())
        .map(|_| ())
        .map_err(|_| ContractError::InvalidSchema)
}

pub fn validate_contract(value: &Value) -> Result<(), ContractError> {
    let object = value.as_object().ok_or(ContractError::RootType)?;
    if object.get("schema_version").and_then(Value::as_str) != Some(SCHEMA_VERSION) {
        return Err(ContractError::SchemaVersion);
    }
    let uri = object
        .get("schema_uri")
        .and_then(Value::as_str)
        .ok_or(ContractError::SchemaUri)?;
    let name = uri
        .strip_prefix(SCHEMA_BASE)
        .ok_or(ContractError::SchemaUri)?;
    let definitions = entity_definitions();
    let definition = definitions.get(name).ok_or(ContractError::SchemaUri)?;
    let validation_schema = json!({
        "$schema": schema()["$schema"].clone(),
        "$ref": format!("#/$defs/{definition}"),
        "$defs": schema()["$defs"].clone(),
    });
    let validator =
        jsonschema::validator_for(&validation_schema).map_err(|_| ContractError::InvalidSchema)?;
    if validator.is_valid(value) {
        Ok(())
    } else {
        Err(ContractError::Validation)
    }
}

fn entity_definitions() -> &'static HashMap<&'static str, &'static str> {
    static DEFINITIONS: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    DEFINITIONS.get_or_init(|| ENTITY_DEFINITIONS.into_iter().collect())
}

pub fn canonical_json(value: &Value) -> Result<Vec<u8>, ContractError> {
    reject_floats_and_large_integers(value)?;
    serde_jcs::to_vec(value).map_err(|_| ContractError::Canonicalization)
}

fn reject_floats_and_large_integers(value: &Value) -> Result<(), ContractError> {
    match value {
        Value::Number(number) if number.is_f64() => Err(ContractError::BinaryFloat),
        Value::Number(number) => {
            if number
                .as_i64()
                .is_some_and(|value| value < -(2_i64.pow(53) - 1))
                || number
                    .as_u64()
                    .is_some_and(|value| value > 2_u64.pow(53) - 1)
            {
                return Err(ContractError::IntegerRange);
            }
            Ok(())
        }
        Value::Array(values) => values.iter().try_for_each(reject_floats_and_large_integers),
        Value::Object(values) => values
            .values()
            .try_for_each(reject_floats_and_large_integers),
        _ => Ok(()),
    }
}

pub fn digest_json(
    value: &Value,
    purpose: &str,
    schema_uri: &str,
) -> Result<String, ContractError> {
    if purpose.is_empty()
        || !purpose.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
        })
    {
        return Err(ContractError::DigestPurpose);
    }
    if !entity_definitions().contains_key(
        schema_uri
            .strip_prefix(SCHEMA_BASE)
            .ok_or(ContractError::SchemaUri)?,
    ) {
        return Err(ContractError::SchemaUri);
    }
    let mut hash = Sha256::new();
    hash.update(b"PROMPTECTOMY\0v2\0");
    hash.update(purpose.as_bytes());
    hash.update(b"\0");
    hash.update(schema_uri.as_bytes());
    hash.update(b"\0");
    hash.update(canonical_json(value)?);
    Ok(format!("sha256:{}", encode_hex(&hash.finalize())))
}

pub fn typed_id(kind: &str) -> Result<String, ContractError> {
    let prefix = match kind {
        "repository" => "repo",
        "authority" => "auth",
        "run" => "run",
        "stage" => "stage",
        "event" => "evt",
        "finding" => "finding",
        "candidate" => "candidate",
        "evaluation" => "eval",
        "patch" => "patch",
        "error" => "err",
        _ => return Err(ContractError::IdentifierKind),
    };
    Ok(format!("{prefix}_{}", Uuid::now_v7()))
}

pub fn artifact_id(content: &[u8]) -> String {
    format!("sha256:{}", encode_hex(&Sha256::digest(content)))
}

fn encode_hex(content: &[u8]) -> String {
    let mut encoded = String::with_capacity(content.len() * 2);
    for byte in content {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

pub fn receipt_id(receipt: &Value) -> Result<String, ContractError> {
    let mut unsigned = receipt.as_object().ok_or(ContractError::RootType)?.clone();
    unsigned.remove("receipt_id");
    let digest = digest_json(
        &Value::Object(unsigned),
        "receipt_manifest",
        &format!("{SCHEMA_BASE}receipt.schema.json"),
    )?;
    Ok(format!(
        "receipt_sha256_{}",
        digest
            .strip_prefix("sha256:")
            .expect("digest prefix is fixed")
    ))
}

pub fn validate_relative_path(value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .next()
            .is_some_and(|component| component.contains(':'))
    {
        return Err(ContractError::RelativePath);
    }
    if Path::new(value).components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(ContractError::RelativePath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_json_rejects_duplicates_floats_and_large_integers() {
        assert!(matches!(
            parse_strict_json(br#"{"a":1,"a":2}"#, 100),
            Err(ContractError::DuplicateMember)
        ));
        assert!(matches!(
            parse_strict_json(br#"{"a":1.5}"#, 100),
            Err(ContractError::BinaryFloat)
        ));
        assert!(matches!(
            parse_strict_json(br#"{"a":9007199254740992}"#, 100),
            Err(ContractError::IntegerRange)
        ));
        assert!(matches!(
            parse_strict_json(br#"{"a":-9007199254740992}"#, 100),
            Err(ContractError::IntegerRange)
        ));
    }

    #[test]
    fn tracked_schema_and_examples_validate() {
        validate_schema_document().unwrap();
        let run = parse_strict_json(
            include_bytes!("../schema/examples/run.valid.json"),
            MAX_SAFE_JSON_BYTES,
        )
        .unwrap();
        validate_contract(&run).unwrap();
        let invalid = parse_strict_json(
            include_bytes!("../schema/examples/run-extra-field.invalid.json"),
            MAX_SAFE_JSON_BYTES,
        )
        .unwrap();
        assert!(matches!(
            validate_contract(&invalid),
            Err(ContractError::Validation)
        ));
    }

    #[test]
    fn canonical_digest_matches_known_python_vector() {
        let value = json!({"z": 1, "a": "x"});
        assert_eq!(canonical_json(&value).unwrap(), br#"{"a":"x","z":1}"#);
        assert_eq!(
            digest_json(&value, "report", &format!("{SCHEMA_BASE}run.schema.json")).unwrap(),
            "sha256:ee8b27dc0863511e337b632984fa3b2c7a78db0e080fee88d90bcc512bb59483"
        );
        assert_ne!(
            digest_json(&value, "report", &format!("{SCHEMA_BASE}run.schema.json")).unwrap(),
            digest_json(&value, "snapshot", &format!("{SCHEMA_BASE}run.schema.json")).unwrap()
        );
    }

    #[test]
    fn identifiers_and_paths_are_bounded() {
        let run = typed_id("run").unwrap();
        let uuid = Uuid::parse_str(run.strip_prefix("run_").unwrap()).unwrap();
        assert_eq!(uuid.get_version_num(), 7);
        assert!(validate_relative_path("src/main.rs").is_ok());
        assert!(validate_relative_path("../secret").is_err());
        assert!(validate_relative_path("C:/secret").is_err());
    }

    #[test]
    fn deterministic_strict_json_and_path_fuzz_corpus_is_fail_closed() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        for index in 0..512 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let value = seed % 9_007_199_254_740_991;
            let json = format!(
                r#"{{"schema_version":"2.0.0","schema_uri":"{SCHEMA_BASE}run.schema.json","value":{value}}}"#
            );
            assert!(parse_strict_json(json.as_bytes(), MAX_SAFE_JSON_BYTES).is_ok());

            let duplicate = format!(r#"{{"a":{index},"a":{value}}}"#);
            assert!(matches!(
                parse_strict_json(duplicate.as_bytes(), MAX_SAFE_JSON_BYTES),
                Err(ContractError::DuplicateMember)
            ));

            let path = format!("src/module_{index}/file_{value}.py");
            assert!(validate_relative_path(&path).is_ok());
            for invalid in [
                format!("../module_{index}"),
                format!("src/../secret_{index}"),
                format!("/tmp/secret_{index}"),
                format!("C:/secret_{index}"),
                format!(r"src\secret_{index}"),
                format!("src/secret_{index}\0tail"),
            ] {
                assert!(validate_relative_path(&invalid).is_err(), "{invalid}");
            }
        }
    }
}
