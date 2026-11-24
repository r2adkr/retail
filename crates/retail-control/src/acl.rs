//! What each device may send to each other device (see `retail_proto::acl`).

use retail_proto::acl::{Accept, AclPolicy, PortRule};

/// A device as the policy sees it
pub struct Member<'a> {
    pub id: i64,
    pub tags: &'a [String],
}

fn selects(selector: &str, m: &Member) -> bool {
    let s = selector.trim();
    if s == "*" {
        return true;
    }
    if let Some(tag) = s.strip_prefix("tag:") {
        return m.tags.iter().any(|t| t == tag);
    }
    s.strip_prefix("id:").and_then(|id| id.parse::<i64>().ok()) == Some(m.id)
}

/// What `receiver` takes from `sender`: `None` if nothing
pub fn accept(policy: Option<&AclPolicy>, receiver: &Member, sender: &Member) -> Option<Accept> {
    let Some(policy) = policy else { return Some(Accept::All) };
    let mut ports: Vec<PortRule> = Vec::new();
    let mut any = false;
    for rule in &policy.rules {
        if rule.from.iter().any(|s| selects(s, sender)) && rule.to.iter().any(|s| selects(s, receiver)) {
            any = true;
            if rule.ports.is_empty() {
                return Some(Accept::All);
            }
            for p in &rule.ports {
                match PortRule::parse(p) {
                    Ok(r) if r == PortRule::ANY => return Some(Accept::All),
                    Ok(r) if !ports.contains(&r) => ports.push(r),
                    _ => {}
                }
            }
        }
    }
    any.then_some(Accept::Ports { ports })
}

/// What `viewer` gets about `peer`: `None` if they may not talk at all;
/// otherwise what the viewer accepts from the peer (replies only when the
/// peer may not start anything towards it)
pub fn view(policy: Option<&AclPolicy>, viewer: &Member, peer: &Member) -> Option<Accept> {
    match accept(policy, viewer, peer) {
        Some(a) => Some(a),
        None => accept(policy, peer, viewer).map(|_| Accept::Ports { ports: Vec::new() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use retail_proto::acl::AclRule;

    fn m(id: i64, tags: &[String]) -> Member<'_> {
        Member { id, tags }
    }

    #[test]
    fn no_policy_lets_everyone_in() {
        assert_eq!(accept(None, &m(1, &[]), &m(2, &[])), Some(Accept::All));
    }

    #[test]
    fn rules_are_directional_and_by_port() {
        let servers = vec!["server".to_string()];
        let none: Vec<String> = Vec::new();
        let policy = AclPolicy {
            rules: vec![
                AclRule { from: vec!["*".into()], to: vec!["tag:server".into()], ports: vec!["tcp:443".into(), "icmp".into()] },
                AclRule { from: vec!["id:1".into()], to: vec!["id:2".into()], ports: vec![] },
            ],
        };
        let (laptop, server, phone) = (m(1, &none), m(3, &servers), m(4, &none));
        // Anyone may reach the server on 443 and ping it
        let Some(Accept::Ports { ports }) = accept(Some(&policy), &server, &phone) else { panic!() };
        assert!(ports.iter().any(|p| p.matches(6, 443)) && ports.iter().any(|p| p.matches(1, 0)));
        assert!(!ports.iter().any(|p| p.matches(6, 22)));
        // The server may only answer the phone
        assert_eq!(view(Some(&policy), &phone, &server), Some(Accept::Ports { ports: vec![] }));
        // Phones do not see each other
        assert_eq!(view(Some(&policy), &phone, &m(5, &none)), None);
        // id:1 reaches id:2 on everything
        assert_eq!(accept(Some(&policy), &m(2, &none), &laptop), Some(Accept::All));
        // A rule with `*` ports is the same as none
        let star = AclPolicy { rules: vec![AclRule { from: vec!["*".into()], to: vec!["*".into()], ports: vec!["*".into()] }] };
        assert_eq!(accept(Some(&star), &laptop, &phone), Some(Accept::All));
        // An empty policy isolates everyone
        assert_eq!(view(Some(&AclPolicy::default()), &laptop, &phone), None);
    }
}
