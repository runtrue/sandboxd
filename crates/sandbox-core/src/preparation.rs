use crate::CoreError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PREPARED_ROOT_CATALOG_VERSION: u32 = 1;
pub const MAXIMUM_PREPARED_ROOT_COHORTS: usize = 128;
pub const MAXIMUM_ARTIFACTS_PER_COHORT: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRootArtifact {
    pub worker_artifact_digest: String,
    pub expanded_root_digest: String,
}

impl PreparedRootArtifact {
    fn validate(&self) -> Result<(), CoreError> {
        if !valid_digest(&self.worker_artifact_digest) || !valid_digest(&self.expanded_root_digest)
        {
            return Err(CoreError::InvalidSpecification(
                "prepared-root artifact identity is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRootCohort {
    pub name: String,
    pub artifacts: Vec<PreparedRootArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRootCatalog {
    pub schema_version: u32,
    pub cohorts: Vec<PreparedRootCohort>,
}

impl PreparedRootCatalog {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.schema_version != PREPARED_ROOT_CATALOG_VERSION
            || self.cohorts.is_empty()
            || self.cohorts.len() > MAXIMUM_PREPARED_ROOT_COHORTS
        {
            return Err(CoreError::InvalidSpecification(
                "prepared-root catalog version or size is invalid".to_owned(),
            ));
        }
        let mut names = BTreeSet::new();
        let mut artifact_digests = BTreeSet::new();
        for cohort in &self.cohorts {
            if !valid_name(&cohort.name)
                || !names.insert(cohort.name.as_str())
                || cohort.artifacts.is_empty()
                || cohort.artifacts.len() > MAXIMUM_ARTIFACTS_PER_COHORT
            {
                return Err(CoreError::InvalidSpecification(
                    "prepared-root cohort is invalid or duplicated".to_owned(),
                ));
            }
            let mut prior: Option<&PreparedRootArtifact> = None;
            for artifact in &cohort.artifacts {
                artifact.validate()?;
                if prior.is_some_and(|candidate| candidate >= artifact)
                    || !artifact_digests.insert(artifact.worker_artifact_digest.as_str())
                {
                    return Err(CoreError::InvalidSpecification(
                        "prepared-root artifacts are duplicated or noncanonical".to_owned(),
                    ));
                }
                prior = Some(artifact);
            }
        }
        Ok(())
    }

    pub fn cohort(&self, name: &str) -> Option<&PreparedRootCohort> {
        self.cohorts.iter().find(|cohort| cohort.name == name)
    }

    pub fn artifact(&self, digest: &str) -> Option<(&PreparedRootCohort, &PreparedRootArtifact)> {
        self.cohorts.iter().find_map(|cohort| {
            cohort
                .artifacts
                .iter()
                .find(|artifact| artifact.worker_artifact_digest == digest)
                .map(|artifact| (cohort, artifact))
        })
    }
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'-' | b'.'))
        })
        && !value.ends_with(['-', '.'])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: char) -> String {
        format!("sha256:{}", value.to_string().repeat(64))
    }

    fn catalog() -> PreparedRootCatalog {
        PreparedRootCatalog {
            schema_version: PREPARED_ROOT_CATALOG_VERSION,
            cohorts: vec![PreparedRootCohort {
                name: "rootset-20260725".to_owned(),
                artifacts: vec![
                    PreparedRootArtifact {
                        worker_artifact_digest: digest('1'),
                        expanded_root_digest: digest('a'),
                    },
                    PreparedRootArtifact {
                        worker_artifact_digest: digest('2'),
                        expanded_root_digest: digest('b'),
                    },
                ],
            }],
        }
    }

    #[test]
    fn catalog_is_bounded_canonical_and_queryable() {
        let catalog = catalog();
        catalog.validate().expect("catalog");
        assert_eq!(
            catalog.artifact(&digest('2')).expect("artifact").0.name,
            "rootset-20260725"
        );
        assert!(catalog.cohort("rootset-20260725").is_some());
    }

    #[test]
    fn catalog_rejects_cross_cohort_artifact_aliases() {
        let mut catalog = catalog();
        catalog.cohorts.push(PreparedRootCohort {
            name: "rootset-20260726".to_owned(),
            artifacts: vec![PreparedRootArtifact {
                worker_artifact_digest: digest('1'),
                expanded_root_digest: digest('c'),
            }],
        });
        assert!(catalog.validate().is_err());
    }
}
