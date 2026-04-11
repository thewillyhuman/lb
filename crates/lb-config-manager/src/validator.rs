use lb_types::{BackendPool, Vip};
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct ValidationError {
    pub errors: Vec<String>,
}

/// Validate a complete LB configuration.
pub fn validate(
    vips: &[Vip],
    pools: &HashMap<String, BackendPool>,
) -> Result<(), ValidationError> {
    let mut errors = Vec::new();

    // Check for dangling pool references in VIP services
    for vip in vips {
        for svc in &vip.services {
            if !pools.contains_key(&svc.backend_pool) {
                errors.push(format!(
                    "VIP '{}' references pool '{}' which does not exist",
                    vip.id.0, svc.backend_pool
                ));
            }
        }
    }

    // Check for empty backend pools
    for (id, pool) in pools {
        if pool.backends.is_empty() {
            errors.push(format!("pool '{id}' has no backends"));
        }
    }

    // Check for duplicate VIP IDs
    let mut seen_vips = HashSet::new();
    for vip in vips {
        if !seen_vips.insert(&vip.id) {
            errors.push(format!("duplicate VIP ID '{}'", vip.id.0));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ValidationError { errors })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_types::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_vip(pool_name: &str) -> Vip {
        Vip {
            id: VipId("test-vip".into()),
            address: IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10)),
            services: vec![VipService {
                protocol: Protocol::Tcp,
                port: 443,
                backend_pool: pool_name.into(),
            }],
            owner: "test".into(),
            description: "".into(),
        }
    }

    fn test_pool() -> BackendPool {
        BackendPool {
            id: BackendPoolId("web".into()),
            backends: vec![Backend::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                443,
            )],
            health_check: None,
        }
    }

    #[test]
    fn valid_config() {
        let vips = vec![test_vip("web")];
        let mut pools = HashMap::new();
        pools.insert("web".into(), test_pool());
        assert!(validate(&vips, &pools).is_ok());
    }

    #[test]
    fn dangling_pool_reference() {
        let vips = vec![test_vip("nonexistent")];
        let pools = HashMap::new();
        let err = validate(&vips, &pools).unwrap_err();
        assert!(err.errors[0].contains("does not exist"));
    }

    #[test]
    fn empty_pool() {
        let vips = vec![test_vip("empty")];
        let mut pools = HashMap::new();
        pools.insert(
            "empty".into(),
            BackendPool {
                id: BackendPoolId("empty".into()),
                backends: vec![],
                health_check: None,
            },
        );
        let err = validate(&vips, &pools).unwrap_err();
        assert!(err.errors.iter().any(|e| e.contains("no backends")));
    }
}
