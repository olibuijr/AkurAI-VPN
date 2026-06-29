//! Ingress map specs and config-file parsing.
//!
//! A [`Map`] binds a public listen port to an internal overlay target
//! (`<listen_port> -> <overlay_host>:<target_port>`). Specs arrive either as
//! `--map <listen>:<overlay>:<target>` flags or, equivalently, one per line in a
//! `--config <file>`. Files accept both the colon form (`8443:100.88.0.3:80`)
//! and the keyed form (`listen=8443 overlay=100.88.0.3 target=80`).

/// A single public-ingress mapping: forward `0.0.0.0:listen_port` to
/// `target_host:target_port` over the overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Map {
    pub listen_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

impl Map {
    /// Parse a `<listen_port>:<overlay_host>:<target_port>` spec.
    ///
    /// `overlay_host` is an overlay IP (e.g. `100.88.0.3`) or a MagicDNS name
    /// (e.g. `nas.oli.akurai`); it is resolved at connect time, never here, so
    /// only the field shape and the two ports are validated up front.
    pub fn parse_spec(spec: &str) -> Result<Map, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() != 3 {
            return Err(format!(
                "'{spec}' must be <listen_port>:<overlay_ip>:<target_port>"
            ));
        }
        let listen_port = parse_port(parts[0]).map_err(|e| format!("listen {e}"))?;
        let target_host = parts[1].trim();
        if target_host.is_empty() {
            return Err(format!("'{spec}': empty overlay target host"));
        }
        let target_port = parse_port(parts[2]).map_err(|e| format!("target {e}"))?;
        Ok(Map {
            listen_port,
            target_host: target_host.to_string(),
            target_port,
        })
    }
}

impl std::fmt::Display for Map {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "0.0.0.0:{} -> {}:{}",
            self.listen_port, self.target_host, self.target_port
        )
    }
}

/// Parse the contents of a `--config` file into maps. Blank lines and `#`
/// comments are ignored. Each remaining line is either the colon form
/// (`8443:100.88.0.3:80`) or the keyed form
/// (`listen=8443 overlay=100.88.0.3 target=80`).
pub fn parse_config(text: &str) -> Result<Vec<Map>, String> {
    let mut maps = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let map = if line.contains('=') {
            parse_kv_line(line)
        } else {
            Map::parse_spec(line)
        }
        .map_err(|e| format!("line {}: {e}", n + 1))?;
        maps.push(map);
    }
    if maps.is_empty() {
        return Err("config file contained no maps".to_string());
    }
    Ok(maps)
}

/// Parse a keyed line: `listen=8443 overlay=100.88.0.3 target=80` (any order).
fn parse_kv_line(line: &str) -> Result<Map, String> {
    let (mut listen, mut overlay, mut target) = (None, None, None);
    for tok in line.split_whitespace() {
        let (k, v) = tok
            .split_once('=')
            .ok_or_else(|| format!("'{tok}' is not key=value"))?;
        match k {
            "listen" => listen = Some(v),
            "overlay" => overlay = Some(v),
            "target" => target = Some(v),
            other => return Err(format!("unknown key '{other}'")),
        }
    }
    let listen = listen.ok_or_else(|| "missing listen=".to_string())?;
    let overlay = overlay.ok_or_else(|| "missing overlay=".to_string())?;
    let target = target.ok_or_else(|| "missing target=".to_string())?;
    Map::parse_spec(&format!("{listen}:{overlay}:{target}"))
}

/// Everything from the first `#` to end-of-line is a comment.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Parse a TCP port: a decimal number in `1..=65535` (port 0 is rejected).
fn parse_port(s: &str) -> Result<u16, String> {
    let s = s.trim();
    let p: u16 = s
        .parse()
        .map_err(|_| format!("port '{s}' is not a number in 1..=65535"))?;
    if p == 0 {
        return Err("port 0 is not allowed".to_string());
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(listen: u16, host: &str, target: u16) -> Map {
        Map {
            listen_port: listen,
            target_host: host.to_string(),
            target_port: target,
        }
    }

    #[test]
    fn parses_a_valid_colon_spec() {
        assert_eq!(
            Map::parse_spec("8443:100.88.0.3:80").unwrap(),
            map(8443, "100.88.0.3", 80)
        );
    }

    #[test]
    fn parses_a_magicdns_target_host() {
        let m = Map::parse_spec("8080:nas.oli.akurai:80").unwrap();
        assert_eq!(m.target_host, "nas.oli.akurai");
        assert_eq!(m.listen_port, 8080);
        assert_eq!(m.target_port, 80);
    }

    #[test]
    fn rejects_wrong_field_count() {
        assert!(Map::parse_spec("8443:100.88.0.3").is_err());
        assert!(Map::parse_spec("8443:100.88.0.3:80:extra").is_err());
        assert!(Map::parse_spec("8443").is_err());
    }

    #[test]
    fn rejects_bad_and_zero_and_overflow_ports() {
        assert!(Map::parse_spec("notaport:100.88.0.3:80").is_err());
        assert!(Map::parse_spec("0:100.88.0.3:80").is_err());
        assert!(Map::parse_spec("8443:100.88.0.3:0").is_err());
        assert!(Map::parse_spec("99999:100.88.0.3:80").is_err());
    }

    #[test]
    fn rejects_empty_target_host() {
        assert!(Map::parse_spec("8443::80").is_err());
    }

    #[test]
    fn display_round_trips_the_shape() {
        assert_eq!(
            map(8443, "100.88.0.3", 80).to_string(),
            "0.0.0.0:8443 -> 100.88.0.3:80"
        );
    }

    #[test]
    fn parses_config_with_both_line_forms_comments_and_blanks() {
        let text = "\
# public ingress maps
8443:100.88.0.3:80

listen=8080 overlay=nas.oli.akurai target=80  # keyed form
   # indented comment
9000:100.88.0.4:22
";
        let maps = parse_config(text).unwrap();
        assert_eq!(
            maps,
            vec![
                map(8443, "100.88.0.3", 80),
                map(8080, "nas.oli.akurai", 80),
                map(9000, "100.88.0.4", 22),
            ]
        );
    }

    #[test]
    fn keyed_line_is_order_independent() {
        let maps = parse_config("target=80 overlay=100.88.0.3 listen=8443").unwrap();
        assert_eq!(maps[0], map(8443, "100.88.0.3", 80));
    }

    #[test]
    fn rejects_keyed_line_missing_a_field() {
        assert!(parse_config("listen=8443 overlay=100.88.0.3").is_err());
    }

    #[test]
    fn rejects_unknown_key() {
        assert!(parse_config("listen=8443 overlay=100.88.0.3 target=80 tls=auto").is_err());
    }

    #[test]
    fn empty_config_is_an_error() {
        assert!(parse_config("# only comments\n\n").is_err());
    }

    #[test]
    fn config_error_reports_line_number() {
        let err = parse_config("8443:100.88.0.3:80\nbogusline").unwrap_err();
        assert!(err.contains("line 2"), "got: {err}");
    }
}
