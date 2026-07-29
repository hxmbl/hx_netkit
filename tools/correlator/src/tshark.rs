use serde_json::Value;

pub struct TSharkPacket {
    pub epoch: Option<f64>,
    pub ip_src: Option<String>,
    pub ip_dst: Option<String>,
    pub tcp_src_port: Option<u32>,
    pub tcp_dst_port: Option<u32>,
    pub udp_src_port: Option<u32>,
    pub udp_dst_port: Option<u32>,
    pub dns_query: Option<String>,
    pub frame_len: Option<u32>,
}

pub fn extract_fields(raw_line: &str) -> Option<TSharkPacket> {
    let val: Value = serde_json::from_str(raw_line).ok()?;
    let layers = val.get("_source")
        .and_then(|s| s.get("layers"))
        .or_else(|| val.get("layers"))
        .and_then(|l| l.as_object());
    let flat = if layers.is_none() { val.as_object() } else { None };

    let get_field = |name: &str| -> Option<&str> {
        let alt = name.replace('.', "_");
        let names: [&str; 2] = [name, &alt];
        if let Some(l) = &layers {
            for n in &names {
                if let Some(v) = l.get(*n) {
                    if let Some(s) = v.as_str() { return Some(s); }
                    if let Some(arr) = v.as_array() {
                        if let Some(first) = arr.first() {
                            if let Some(s) = first.as_str() { return Some(s); }
                        }
                    }
                }
            }
            None
        } else if let Some(f) = &flat {
            for n in &names {
                if let Some(v) = f.get(*n) {
                    if let Some(s) = v.as_str() { return Some(s); }
                    if let Some(arr) = v.as_array() {
                        if let Some(first) = arr.first() {
                            if let Some(s) = first.as_str() { return Some(s); }
                        }
                    }
                }
            }
            None
        } else {
            None
        }
    };

    Some(TSharkPacket {
        epoch: get_field("frame.time_epoch").and_then(|s| s.parse::<f64>().ok()),
        ip_src: get_field("ip.src").map(|s| s.to_string()),
        ip_dst: get_field("ip.dst").map(|s| s.to_string()),
        tcp_src_port: get_field("tcp.srcport").and_then(|s| s.parse::<u32>().ok()),
        tcp_dst_port: get_field("tcp.dstport").and_then(|s| s.parse::<u32>().ok()),
        udp_src_port: get_field("udp.srcport").and_then(|s| s.parse::<u32>().ok()),
        udp_dst_port: get_field("udp.dstport").and_then(|s| s.parse::<u32>().ok()),
        dns_query: get_field("dns.qry.name").map(|s| s.to_string()),
        frame_len: get_field("frame.len").and_then(|s| s.parse::<u32>().ok()),
    })
}

/// Standard TShark args for JSON field extraction.
pub fn tshark_args(interface: &str, filter: &str) -> Vec<String> {
    let args = vec![
        "-i".into(), interface.into(),
        "-n".into(), "-l".into(), "-T".into(), "ek".into(),
        "-f".into(), if filter.is_empty() { "not host 127.0.0.1".into() } else { filter.into() },
        "-e".into(), "frame.time_epoch".into(),
        "-e".into(), "frame.len".into(),
        "-e".into(), "ip.src".into(),
        "-e".into(), "ip.dst".into(),
        "-e".into(), "tcp.srcport".into(),
        "-e".into(), "tcp.dstport".into(),
        "-e".into(), "udp.srcport".into(),
        "-e".into(), "udp.dstport".into(),
        "-e".into(), "dns.qry.name".into(),
    ];
    args
}
