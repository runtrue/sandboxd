use crate::CoreError;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct AssignmentEpoch(u64);

impl AssignmentEpoch {
    pub fn new(value: u64) -> Result<Self, CoreError> {
        if value == 0 {
            return Err(CoreError::InvalidWorkOrder(
                "assignment epoch must be greater than zero".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for AssignmentEpoch {
    type Error = CoreError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<AssignmentEpoch> for u64 {
    fn from(value: AssignmentEpoch) -> Self {
        value.0
    }
}

impl fmt::Display for AssignmentEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_nonzero() {
        assert!(AssignmentEpoch::new(1).is_ok());
        assert!(AssignmentEpoch::new(0).is_err());
        assert!(serde_json::from_str::<AssignmentEpoch>("0").is_err());
    }
}
