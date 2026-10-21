//! Interop claims: the `(protocol, intent, role)` tuples an SDK declares in
//! `capabilities.interop` of `harness/expectations/<language>.toml`.

use std::fmt;

/// A payment flow the interop tier drives end to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Intent {
    Charge,
    X402Exact,
    X402Upto,
    Session,
}

impl Intent {
    pub const ALL: [Intent; 4] = [
        Intent::Charge,
        Intent::X402Exact,
        Intent::X402Upto,
        Intent::Session,
    ];

    /// The scenario-id prefix and README name (`charge`, `x402-exact`, ...).
    pub fn id(self) -> &'static str {
        match self {
            Intent::Charge => "charge",
            Intent::X402Exact => "x402-exact",
            Intent::X402Upto => "x402-upto",
            Intent::Session => "session",
        }
    }

    pub fn protocol(self) -> &'static str {
        match self {
            Intent::Charge | Intent::Session => "mpp",
            Intent::X402Exact | Intent::X402Upto => "x402",
        }
    }

    pub fn scheme(self) -> &'static str {
        match self {
            Intent::Charge => "charge",
            Intent::X402Exact => "exact",
            Intent::X402Upto => "upto",
            Intent::Session => "session",
        }
    }

    pub fn is_x402(self) -> bool {
        self.protocol() == "x402"
    }
}

impl fmt::Display for Intent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Client => "client",
            Role::Server => "server",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `<protocol>:<scheme>:<role>`, e.g. `mpp:charge:client`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Claim {
    pub intent: Intent,
    pub role: Role,
}

impl Claim {
    pub fn new(intent: Intent, role: Role) -> Self {
        Self { intent, role }
    }

    /// Every claim an SDK may make. Anything else in a toml is a typo.
    pub fn all() -> Vec<Claim> {
        Intent::ALL
            .iter()
            .flat_map(|i| [Claim::new(*i, Role::Client), Claim::new(*i, Role::Server)])
            .collect()
    }

    pub fn parse(text: &str) -> Option<Claim> {
        Claim::all().into_iter().find(|c| c.to_string() == text)
    }
}

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.intent.protocol(),
            self.intent.scheme(),
            self.role
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_round_trip_and_reject_typos() {
        for c in Claim::all() {
            assert_eq!(Claim::parse(&c.to_string()), Some(c));
        }
        assert_eq!(
            Claim::parse("mpp:charge:client"),
            Some(Claim::new(Intent::Charge, Role::Client))
        );
        assert_eq!(
            Claim::parse("x402:upto:server"),
            Some(Claim::new(Intent::X402Upto, Role::Server))
        );
        assert_eq!(Claim::parse("x402:exact:clients"), None);
        assert_eq!(Claim::parse("mpp:exact:client"), None);
    }
}
