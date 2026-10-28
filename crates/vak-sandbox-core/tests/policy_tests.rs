#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Tests for policy construction

#[cfg(test)]
mod tests {
    use vak_sandbox_core::Policy;

    #[test]
    fn deny_all_default() {
        let p = Policy::deny_all();
        assert!(!p.network.allow);
        assert!(p.fs.allow_read.is_empty());
        assert!(p.fs.allow_write.is_empty());
        assert!(p.env.allow.is_empty());
    }

    #[test]
    fn builder_pattern() {
        let p = Policy::deny_all()
            .allow_path_read("/usr".into())
            .allow_path_write("/tmp/work".into())
            .allow_env("PATH")
            .allow_network_egress();
        assert!(
            p.fs.allow_read
                .iter()
                .any(|x| x.to_string_lossy() == "/usr")
        );
        assert!(
            p.fs.allow_write
                .iter()
                .any(|x| x.to_string_lossy() == "/tmp/work")
        );
        assert!(p.env.allow.contains("PATH"));
        assert!(p.network.allow);
        assert!(p.network.allow_outbound);
    }

    #[test]
    fn network_modes() {
        let p = Policy::deny_all().allow_network();
        assert!(p.network.allow);
        assert!(p.network.allow_localhost);

        let p2 = Policy::deny_all().allow_network_full();
        assert!(p2.network.allow_inbound);
        assert!(p2.network.allow_dns);
    }
}
