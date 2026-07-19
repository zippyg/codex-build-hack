use promptectomy_contracts::{MAX_SAFE_JSON_BYTES, parse_strict_json};
use serde_json::Value;

pub const RUN_VALID: &[u8] =
    include_bytes!("../../promptectomy-contracts/schema/examples/run.valid.json");
pub const EVENT_VALID: &[u8] =
    include_bytes!("../../promptectomy-contracts/schema/examples/event.valid.json");

pub fn run() -> Value {
    parse_strict_json(RUN_VALID, MAX_SAFE_JSON_BYTES).expect("tracked valid run fixture must parse")
}

pub fn event() -> Value {
    parse_strict_json(EVENT_VALID, MAX_SAFE_JSON_BYTES)
        .expect("tracked valid event fixture must parse")
}

#[cfg(test)]
mod tests {
    use promptectomy_contracts::validate_contract;

    use super::*;

    #[test]
    fn shared_fixtures_validate() {
        validate_contract(&run()).unwrap();
        validate_contract(&event()).unwrap();
    }
}
