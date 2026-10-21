//! The case registry, one module per suite.
//!
//! Every module declares its cases with [`registry!`], which generates the
//! module's `cases()` list AND one `#[test]` per case from the same entries,
//! so a case cannot exist without its positive-control test.

use serde_json::{json, Value};

use crate::keys;

pub mod canonical;
pub mod charge;
pub mod charge_policy;
pub mod session;
pub mod x402_exact;
pub mod x402_policy;

/// `registry! { name => case_expr; ... }`: one constructor fn per case, the
/// module's `cases()`, and a positive-control `#[test]` per case that also
/// asserts the fn name equals the case id (dashes as underscores).
#[macro_export]
macro_rules! registry {
    ($($name:ident => $body:expr;)*) => {
        $(
            pub fn $name() -> $crate::case::Case {
                $body
            }
        )*

        pub fn cases() -> Vec<$crate::case::Case> {
            vec![$($name()),*]
        }

        #[cfg(test)]
        mod positive_control {
            $(
                #[test]
                fn $name() {
                    let case = super::$name();
                    assert_eq!(
                        case.id.test_name(),
                        stringify!($name),
                        "registry entry name must be the case id"
                    );
                    if let Err(error) = $crate::realize::realize_blocking(&case) {
                        panic!("{error}");
                    }
                }
            )*
        }
    };
}

/// Every case, in file then registry order.
pub fn all() -> Vec<crate::case::Case> {
    let mut out = Vec::new();
    out.extend(canonical::cases());
    out.extend(charge::cases());
    out.extend(charge_policy::cases());
    out.extend(session::cases());
    out.extend(x402_exact::cases());
    out.extend(x402_policy::cases());
    out
}

/// The client key as the vectors encode it.
pub fn client_secret() -> Value {
    keys::secret_json(keys::CLIENT_SEED)
}

/// `rpcFixtures.mints` entry list.
pub fn mints(entries: &[(&str, &str, u8)]) -> Value {
    let mut mints = serde_json::Map::new();
    for (mint, owner, decimals) in entries {
        mints.insert(
            (*mint).to_string(),
            json!({ "owner": owner, "decimals": decimals }),
        );
    }
    Value::Object(mints)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn ids_are_unique_and_files_known() {
        let mut ids = BTreeSet::new();
        for case in all() {
            assert!(ids.insert(case.id.to_string()), "duplicate id {}", case.id);
            assert!(
                case.file.ends_with(".json") && !case.file.contains('/'),
                "{}",
                case.file
            );
        }
    }

    #[test]
    fn every_case_maps_a_known_requirement() {
        let root = crate::repo_root();
        let mut known = BTreeSet::new();
        for name in ["mpp", "x402"] {
            let raw =
                std::fs::read_to_string(root.join(format!("harness/requirements/{name}.toml")))
                    .unwrap();
            let file: crate::reqlint::RequirementsFile = toml::from_str(&raw).unwrap();
            known.extend(file.requirements.into_iter().map(|r| r.id));
        }
        for case in all() {
            assert!(
                !case.requirements.is_empty(),
                "{} maps no requirement",
                case.id
            );
            for req in &case.requirements {
                assert!(
                    known.contains(req.as_str()),
                    "{} cites unknown requirement {}",
                    case.id,
                    req.as_str()
                );
            }
        }
    }
}
