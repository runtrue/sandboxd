use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Gvisor,
    #[serde(rename = "marcovm")]
    MarcoVm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendDescriptor {
    pub kind: BackendKind,
    pub implementation: String,
    pub implementation_version: String,
    pub state_format_version: u32,
    pub configuration_digest: String,
}

#[cfg(test)]
mod tests {
    use super::BackendKind;

    #[test]
    fn marcovm_has_a_stable_wire_identity() {
        assert_eq!(
            serde_json::to_string(&BackendKind::MarcoVm).expect("serialize backend"),
            "\"marcovm\""
        );
        assert_eq!(
            serde_json::from_str::<BackendKind>("\"marcovm\"").expect("parse backend"),
            BackendKind::MarcoVm
        );
    }

    #[test]
    fn backend_kinds_cannot_be_confused() {
        assert_ne!(BackendKind::Gvisor, BackendKind::MarcoVm);
    }
}
