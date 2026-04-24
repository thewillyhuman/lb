//! `lb-trace` — CLI companion to `lb-node`'s `POST /v1/trace` endpoint.
//!
//! Asks a running `lb-node` where it would send a packet matching the given
//! 5-tuple, *without* injecting anything on the wire. Output is the
//! human-readable decision trail from `lb_tracer::TraceResult`; add `--json`
//! for the raw body.
//!
//! Example:
//! ```text
//! $ lb-trace \
//!     --node http://127.0.0.1:9100 \
//!     --src  10.0.0.100:12345 \
//!     --dst  188.184.100.10:443
//! node:    lb-node-01
//! hash:    0xdeadbeef...
//! pool:    web
//! backend: 10.0.0.2 (healthy)
//! steps:
//!   - parsed 5-tuple: 10.0.0.100:12345 → 188.184.100.10:443 (Tcp)
//!   - VIP matched → pool `web`
//!   - Maglev lookup → 10.0.0.2 …
//!   - health status: healthy (or unknown — treated as healthy)
//! ```

use clap::Parser;
use lb_tracer::{TraceRequest, TraceResult};
use lb_types::Protocol;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "lb-trace",
    version,
    about = "Ask a running lb-node which backend a synthetic packet would hit"
)]
struct Cli {
    /// Base URL of the lb-node ops server, e.g. `http://127.0.0.1:9100`.
    #[arg(long, default_value = "http://127.0.0.1:9100")]
    node: String,

    /// Source endpoint, in `IP:PORT` form.
    #[arg(long)]
    src: String,

    /// Destination endpoint, in `IP:PORT` form (usually the VIP).
    #[arg(long)]
    dst: String,

    /// L4 protocol (`tcp` or `udp`).
    #[arg(long, default_value = "tcp")]
    proto: String,

    /// Request timeout in seconds.
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,

    /// Emit the raw JSON response body instead of the human-readable trail.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let (src_ip, src_port) = match parse_addr(&cli.src) {
        Some(ok) => ok,
        None => {
            eprintln!("invalid --src: {}", cli.src);
            return ExitCode::from(2);
        }
    };
    let (dst_ip, dst_port) = match parse_addr(&cli.dst) {
        Some(ok) => ok,
        None => {
            eprintln!("invalid --dst: {}", cli.dst);
            return ExitCode::from(2);
        }
    };
    let protocol = match cli.proto.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        other => {
            eprintln!("unsupported --proto: {other} (expected tcp or udp)");
            return ExitCode::from(2);
        }
    };

    let req = TraceRequest {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
    };

    let url = format!("{}/v1/trace", cli.node.trim_end_matches('/'));
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(cli.timeout_secs))
        .build();

    match agent
        .post(&url)
        .send_json(serde_json::to_value(&req).unwrap())
    {
        Ok(resp) => {
            let body: TraceResult = match resp.into_json() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("invalid response body: {e}");
                    return ExitCode::from(1);
                }
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&body).unwrap());
            } else {
                print!("{body}");
            }
            ExitCode::SUCCESS
        }
        Err(ureq::Error::Status(code, resp)) => {
            eprintln!(
                "lb-node returned HTTP {code}: {}",
                resp.into_string().unwrap_or_else(|_| "(no body)".into())
            );
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("failed to reach {url}: {e}");
            ExitCode::from(1)
        }
    }
}

/// Parse `"IP:PORT"`. Accepts IPv6 literals in the standard bracketed form
/// (`[::1]:443`); the unbracketed `rsplit_once(':')` path handles IPv4.
fn parse_addr(s: &str) -> Option<(IpAddr, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (ip_str, rest) = rest.split_once(']')?;
        let port_str = rest.strip_prefix(':')?;
        Some((ip_str.parse().ok()?, port_str.parse().ok()?))
    } else {
        let (ip_str, port_str) = s.rsplit_once(':')?;
        Some((ip_str.parse().ok()?, port_str.parse().ok()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_ipv4_addr() {
        let (ip, port) = parse_addr("10.0.0.1:443").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_ipv6_bracketed_addr() {
        let (ip, port) = parse_addr("[::1]:9100").unwrap();
        assert_eq!(port, 9100);
        assert!(ip.is_loopback());
    }

    #[test]
    fn parse_addr_rejects_garbage() {
        assert!(parse_addr("not-an-address").is_none());
        assert!(parse_addr("10.0.0.1").is_none());
        assert!(parse_addr("10.0.0.1:notnum").is_none());
    }
}
