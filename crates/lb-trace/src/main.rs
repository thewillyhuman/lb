use clap::Parser;
use lb_types::Protocol;
use std::net::IpAddr;

#[derive(Parser)]
#[command(name = "lb-trace", version, about = "Packet tracer for LB debugging")]
struct Cli {
    /// Source IP:port
    #[arg(long)]
    src: String,

    /// Destination IP:port
    #[arg(long)]
    dst: String,

    /// Protocol (tcp or udp)
    #[arg(long, default_value = "tcp")]
    proto: String,
}

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt::init();

    let (src_ip, src_port) = parse_addr(&cli.src).unwrap_or_else(|| {
        eprintln!("invalid source address: {}", cli.src);
        std::process::exit(1);
    });

    let (dst_ip, dst_port) = parse_addr(&cli.dst).unwrap_or_else(|| {
        eprintln!("invalid destination address: {}", cli.dst);
        std::process::exit(1);
    });

    let protocol = match cli.proto.as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => {
            eprintln!("unsupported protocol: {}", cli.proto);
            std::process::exit(1);
        }
    };

    let request = lb_tracer::TraceRequest {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
    };

    println!(
        "Tracing flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({:?})",
        protocol
    );
    println!("Trace request: {request:?}");
    println!("(Full trace execution requires a running LB cluster)");
}

fn parse_addr(s: &str) -> Option<(IpAddr, u16)> {
    let parts: Vec<&str> = s.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }
    let port: u16 = parts[0].parse().ok()?;
    let ip: IpAddr = parts[1].parse().ok()?;
    Some((ip, port))
}
