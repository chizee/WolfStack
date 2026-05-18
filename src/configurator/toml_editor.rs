// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Structured TOML editor for WolfDisk and WolfScale configuration

use crate::installer::Component;
use super::ExecTarget;

/// Parse a TOML config file into a JSON value for form rendering.
/// Returns just the data — for missing-required-key validation,
/// call `validate_config` against the same target/component.
pub fn parse_config(target: &ExecTarget, component: &str) -> Result<serde_json::Value, String> {
    let comp = component_from_name(component)?;
    let config_path = comp.config_path()
        .ok_or_else(|| format!("No config path for {}", component))?;
    let content = target.read_file(config_path)?;
    let toml_value: toml::Value = content.parse()
        .map_err(|e| format!("Failed to parse TOML: {}", e))?;
    Ok(toml_to_json(&toml_value))
}

/// Compare the on-disk config against the default template and list
/// dotted keypaths the template defines but the file doesn't. Empty
/// = file is complete. Used by the editor to show a "missing
/// required fields — Repair?" banner.
pub fn validate_config(target: &ExecTarget, component: &str) -> Result<Vec<String>, String> {
    let comp = component_from_name(component)?;
    let config_path = comp.config_path()
        .ok_or_else(|| format!("No config path for {}", component))?;
    let content = target.read_file(config_path)?;
    let toml_value: toml::Value = content.parse()
        .map_err(|e| format!("Failed to parse TOML: {}", e))?;
    let actual = toml_to_json(&toml_value);
    let template = match default_template_json(comp) {
        Some(t) => t,
        None => return Ok(Vec::new()),
    };
    Ok(missing_keys_against(&template, &actual, ""))
}

/// Save a structured JSON config as TOML. **Merge-with-existing**:
/// read what's already on disk first, deep-merge the incoming JSON
/// into it, then write. This prevents the bug where a partial form
/// post wipes out required fields the form doesn't know about (the
/// wolfproxy wizard panicked the daemon for klasSponsor because it
/// posted [server]/[firewall]/[logging] only and lost the `host`
/// field). If the existing file is missing or unparseable, we fall
/// back to writing the new data alone.
pub fn save_config(target: &ExecTarget, component: &str, data: &serde_json::Value) -> Result<String, String> {
    let comp = component_from_name(component)?;
    let config_path = comp.config_path()
        .ok_or_else(|| format!("No config path for {}", component))?;

    // Read + parse existing config; on failure, start from empty/default
    // so a corrupted file doesn't block the operator from rewriting it.
    let mut merged = match target.read_file(config_path) {
        Ok(content) => {
            content.parse::<toml::Value>()
                .map(|tv| toml_to_json(&tv))
                .unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
        }
        Err(_) => {
            // No file yet — start from the default template so required
            // fields are always present on first save.
            default_template_json(comp).unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
        }
    };
    deep_merge(&mut merged, data);

    let toml_value = json_to_toml(&merged)
        .ok_or_else(|| "Failed to convert config to TOML format".to_string())?;
    let toml_string = toml::to_string_pretty(&toml_value)
        .map_err(|e| format!("Failed to serialize TOML: {}", e))?;
    target.write_file(config_path, &toml_string)?;
    Ok(format!("Configuration saved to {}. Restart {} to apply changes.",
        config_path, comp.service_name()))
}

/// Repair a partial/broken config by filling in missing required keys
/// from the default template. User-set values are preserved; only
/// keys that don't exist in the current file are added.
pub fn repair_config(target: &ExecTarget, component: &str) -> Result<String, String> {
    let comp = component_from_name(component)?;
    let config_path = comp.config_path()
        .ok_or_else(|| format!("No config path for {}", component))?;
    let template = default_template_json(comp)
        .ok_or_else(|| format!("No default template for {}", component))?;
    // Read whatever's on disk (fall back to empty if file is missing
    // or unparseable — same approach as save_config).
    let existing_json = target.read_file(config_path)
        .ok()
        .and_then(|c| c.parse::<toml::Value>().ok())
        .map(|tv| toml_to_json(&tv))
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    // Snapshot missing keys BEFORE the merge so we can tell the user
    // exactly what was filled in.
    let missing = missing_keys_against(&template, &existing_json, "");
    if missing.is_empty() {
        return Ok(format!(
            "{} configuration is already complete — no repair needed.",
            comp.service_name()));
    }

    // Start from template, overlay existing values on top. End result:
    // every template key is present; user values win where they exist.
    let mut merged = template.clone();
    deep_merge(&mut merged, &existing_json);

    let toml_value = json_to_toml(&merged)
        .ok_or_else(|| "Failed to convert repaired config to TOML".to_string())?;
    let toml_string = toml::to_string_pretty(&toml_value)
        .map_err(|e| format!("Failed to serialize TOML: {}", e))?;
    target.write_file(config_path, &toml_string)?;
    Ok(format!(
        "Repaired {} — filled in {} missing key(s): {}. Restart {} to apply.",
        config_path, missing.len(),
        missing.join(", "), comp.service_name()))
}

fn component_from_name(component: &str) -> Result<Component, String> {
    match component.to_lowercase().as_str() {
        "wolfdisk" => Ok(Component::WolfDisk),
        "wolfscale" => Ok(Component::WolfScale),
        "wolfproxy" => Ok(Component::WolfProxy),
        "wolfserve" => Ok(Component::WolfServe),
        _ => Err(format!("Unsupported component: {}", component)),
    }
}

/// Deep-merge `src` into `dst`. Object keys merge recursively; for
/// any non-object value (scalar, array) `src` overwrites `dst`. Null
/// in `src` is treated as "no value, leave dst alone" — that way a
/// frontend that emits `{ "foo": null }` for an unset field doesn't
/// nuke an existing setting.
fn deep_merge(dst: &mut serde_json::Value, src: &serde_json::Value) {
    use serde_json::Value;
    match (dst, src) {
        (Value::Object(d), Value::Object(s)) => {
            for (k, v) in s {
                if v.is_null() { continue; }
                match d.get_mut(k) {
                    Some(existing) => deep_merge(existing, v),
                    None => { d.insert(k.clone(), v.clone()); }
                }
            }
        }
        // Non-object dst or non-object src — overwrite if src isn't null.
        (dst_ref, src_ref) => {
            if !src_ref.is_null() { *dst_ref = src_ref.clone(); }
        }
    }
}

/// List dotted keypaths present in `template` but absent from `actual`.
/// Always reports LEAF paths — if a whole subtree is missing in
/// `actual`, every leaf the template defines under that subtree is
/// reported individually (so the operator sees "logging.level" not
/// just "logging"). `prefix` builds the dotted path.
fn missing_keys_against(template: &serde_json::Value, actual: &serde_json::Value, prefix: &str) -> Vec<String> {
    use serde_json::Value;
    let mut out = Vec::new();
    match template {
        Value::Object(t_map) => {
            // Treat a missing/non-object `actual` as an empty object —
            // so every leaf of the template's subtree gets reported.
            let empty_map = serde_json::Map::new();
            let a_map = actual.as_object().unwrap_or(&empty_map);
            for (k, t_val) in t_map {
                let path = if prefix.is_empty() { k.clone() } else { format!("{}.{}", prefix, k) };
                let a_val_owned;
                let a_val: &Value = match a_map.get(k) {
                    Some(v) => v,
                    None => {
                        if t_val.is_object() {
                            // Recurse with an empty object so leaves are reported.
                            a_val_owned = Value::Object(serde_json::Map::new());
                            &a_val_owned
                        } else {
                            out.push(path);
                            continue;
                        }
                    }
                };
                if t_val.is_object() {
                    out.extend(missing_keys_against(t_val, a_val, &path));
                }
                // Non-object template leaf with actual present → not missing.
            }
        }
        _ => { /* template root isn't an object — nothing to validate */ }
    }
    out
}

/// Parse the default template embedded in `bootstrap_config` for the
/// given component and return it as JSON. None for components with no
/// known template (shouldn't happen for the four supported ones).
fn default_template_json(comp: Component) -> Option<serde_json::Value> {
    let default_str: &str = match comp {
        Component::WolfDisk => DEFAULT_WOLFDISK,
        Component::WolfScale => DEFAULT_WOLFSCALE,
        Component::WolfProxy => DEFAULT_WOLFPROXY,
        Component::WolfServe => DEFAULT_WOLFSERVE,
        _ => return None,
    };
    default_str.parse::<toml::Value>().ok().map(|tv| toml_to_json(&tv))
}

// The default templates are also used by `bootstrap_config` below.
// Extracted to module-level constants so `default_template_json` can
// parse them without duplicating the string. Keep in sync with the
// rendered text the bootstrap function writes to disk.

const DEFAULT_WOLFDISK: &str = r#"# WolfDisk Configuration
# Auto-generated default — edit as needed

[node]
id = "node-1"
role = "auto"
bind = "0.0.0.0:8550"
data_dir = "/var/lib/wolfdisk"

[cluster]
name = "default"
peers = []
discovery = "udp://0.0.0.0:8551"

[replication]
mode = "shared"
factor = 3
chunk_size = 4194304

[mount]
path = "/mnt/wolfdisk"
allow_other = true
"#;

const DEFAULT_WOLFSCALE: &str = r#"# WolfScale Configuration
# Auto-generated default — edit as needed

[node]
id = "node-1"
bind_address = "0.0.0.0:7654"
data_dir = "/var/lib/wolfscale"

[database]
host = "localhost"
port = 3306
user = "wolfscale"
password = ""
pool_size = 10
connect_timeout_secs = 30

[wal]
batch_size = 1000
flush_interval_ms = 100
compression = true
segment_size_mb = 64
retention_hours = 168
fsync = true

[cluster]
peers = []
heartbeat_interval_ms = 500
election_timeout_ms = 2000
max_batch_entries = 1000

[api]
enabled = true
bind_address = "0.0.0.0:8080"
cors_enabled = false

[logging]
level = "info"
format = "pretty"
"#;

const DEFAULT_WOLFPROXY: &str = r#"# WolfProxy Configuration
# Auto-generated default — edit as needed

[server]
host = "0.0.0.0"
bind_address = "0.0.0.0:80"
bind_address_ssl = "0.0.0.0:443"
worker_threads = 0

[firewall]
enabled = false
rate_limit_rps = 100

[logging]
level = "info"
access_log = "/var/log/wolfproxy/access.log"
error_log = "/var/log/wolfproxy/error.log"
"#;

const DEFAULT_WOLFSERVE: &str = r#"# WolfServe Configuration
# Auto-generated default — edit as needed

[server]
bind_address = "0.0.0.0:80"
bind_address_ssl = "0.0.0.0:443"
worker_threads = 0
document_root = "/var/www/html"

[logging]
level = "info"
access_log = "/var/log/wolfserve/access.log"
error_log = "/var/log/wolfserve/error.log"
"#;

/// Bootstrap a default TOML config for a component — never overwrites existing files
pub fn bootstrap_config(target: &ExecTarget, component: &str) -> Result<String, String> {
    let comp = match component.to_lowercase().as_str() {
        "wolfdisk" => Component::WolfDisk,
        "wolfscale" => Component::WolfScale,
        "wolfproxy" => Component::WolfProxy,
        "wolfserve" => Component::WolfServe,
        _ => return Err(format!("Unsupported component: {}", component)),
    };

    let config_path = comp.config_path()
        .ok_or_else(|| format!("No config path for {}", component))?;

    // Never overwrite existing config
    if target.path_exists(config_path).unwrap_or(false) {
        return Ok(format!("Configuration already exists at {}. Not overwriting.", config_path));
    }

    // Create parent directory
    if let Some(parent) = std::path::Path::new(config_path).parent() {
        let _ = target.exec(&format!("mkdir -p '{}'", parent.display()));
    }

    // Templates live as module-level constants (see DEFAULT_*) so
    // validate / repair can parse the same canonical text we write
    // here.
    let default_config = match comp {
        Component::WolfDisk => DEFAULT_WOLFDISK,
        Component::WolfScale => DEFAULT_WOLFSCALE,
        Component::WolfProxy => DEFAULT_WOLFPROXY,
        Component::WolfServe => DEFAULT_WOLFSERVE,
        _ => return Err(format!("No default config template for {}", component)),
    };

    target.write_file(config_path, default_config)?;
    Ok(format!("Default configuration created at {}. Edit the values and save.", config_path))
}

/// Validate a TOML string (parse it and check for errors)
pub fn validate_toml(content: &str) -> Result<(), String> {
    let _: toml::Value = content.parse()
        .map_err(|e| format!("Invalid TOML: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_merge_preserves_existing_and_overlays_new() {
        let mut existing = serde_json::json!({
            "server": { "host": "0.0.0.0", "bind_address": "0.0.0.0:80" },
            "firewall": { "enabled": false }
        });
        let incoming = serde_json::json!({
            "server": { "bind_address": "0.0.0.0:8080" },
            "logging": { "level": "trace" }
        });
        deep_merge(&mut existing, &incoming);
        // host preserved (existed in old, not in new)
        assert_eq!(existing["server"]["host"], "0.0.0.0");
        // bind_address overwritten by new value
        assert_eq!(existing["server"]["bind_address"], "0.0.0.0:8080");
        // logging section added wholesale
        assert_eq!(existing["logging"]["level"], "trace");
        // firewall section preserved untouched
        assert_eq!(existing["firewall"]["enabled"], false);
    }

    #[test]
    fn deep_merge_null_does_not_clobber() {
        // Frontends sometimes emit { "field": null } for unset values.
        // That must NOT delete an existing setting.
        let mut existing = serde_json::json!({ "server": { "host": "0.0.0.0" } });
        let incoming = serde_json::json!({ "server": { "host": null } });
        deep_merge(&mut existing, &incoming);
        assert_eq!(existing["server"]["host"], "0.0.0.0");
    }

    #[test]
    fn missing_keys_finds_dotted_paths() {
        let template = serde_json::json!({
            "server": { "host": "x", "bind_address": "y" },
            "logging": { "level": "info" }
        });
        let actual = serde_json::json!({
            "server": { "bind_address": "y" }
        });
        let mut missing = missing_keys_against(&template, &actual, "");
        missing.sort();
        assert_eq!(missing, vec!["logging.level".to_string(), "server.host".to_string()]);
    }

    #[test]
    fn missing_keys_empty_when_actual_has_everything() {
        let template = serde_json::json!({ "a": { "b": 1 } });
        let actual = serde_json::json!({ "a": { "b": 99, "c": 100 } });
        let missing = missing_keys_against(&template, &actual, "");
        assert!(missing.is_empty(), "got {:?}", missing);
    }

    #[test]
    fn wolfproxy_default_template_has_host_field() {
        // The exact field klasSponsor's panic complained about being
        // missing. Locking this in so a future template edit doesn't
        // silently drop it again.
        let tpl = default_template_json(Component::WolfProxy).expect("template parses");
        assert!(tpl["server"]["host"].is_string(),
            "wolfproxy default template must include server.host");
        assert!(tpl["server"]["bind_address"].is_string());
        assert!(tpl["server"]["bind_address_ssl"].is_string());
    }

    #[test]
    fn missing_keys_on_klassponsor_actual_config_reports_host() {
        // Reproduces the exact config klasSponsor reported in Discord
        // 2026-05-18: [server] with bind_address/bind_address_ssl/
        // worker_threads but no host. The validator must report
        // server.host as missing.
        let tpl = default_template_json(Component::WolfProxy).unwrap();
        let actual = r#"
            [firewall]
            enabled = false
            rate_limit_rps = 100
            [logging]
            level = "trace"
            [server]
            bind_address = "0.0.0.0:180"
            bind_address_ssl = "0.0.0.0:443"
            worker_threads = 0
        "#.parse::<toml::Value>().unwrap();
        let actual_json = toml_to_json(&actual);
        let missing = missing_keys_against(&tpl, &actual_json, "");
        assert!(missing.iter().any(|k| k == "server.host"),
            "expected server.host in missing list, got {:?}", missing);
    }
}

/// Convert a TOML value to a JSON value
fn toml_to_json(value: &toml::Value) -> serde_json::Value {
    match value {
        toml::Value::String(s) => serde_json::Value::String(s.clone()),
        toml::Value::Integer(i) => serde_json::json!(*i),
        toml::Value::Float(f) => serde_json::json!(*f),
        toml::Value::Boolean(b) => serde_json::Value::Bool(*b),
        toml::Value::Datetime(d) => serde_json::Value::String(d.to_string()),
        toml::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(toml_to_json).collect())
        }
        toml::Value::Table(table) => {
            let mut map = serde_json::Map::new();
            for (k, v) in table {
                map.insert(k.clone(), toml_to_json(v));
            }
            serde_json::Value::Object(map)
        }
    }
}

/// Convert a JSON value to a TOML value
fn json_to_toml(value: &serde_json::Value) -> Option<toml::Value> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::Bool(b) => Some(toml::Value::Boolean(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(toml::Value::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Some(toml::Value::Float(f))
            } else {
                None
            }
        }
        serde_json::Value::String(s) => Some(toml::Value::String(s.clone())),
        serde_json::Value::Array(arr) => {
            let items: Vec<toml::Value> = arr.iter()
                .filter_map(json_to_toml)
                .collect();
            Some(toml::Value::Array(items))
        }
        serde_json::Value::Object(obj) => {
            let mut table = toml::map::Map::new();
            for (k, v) in obj {
                if let Some(tv) = json_to_toml(v) {
                    table.insert(k.clone(), tv);
                }
            }
            Some(toml::Value::Table(table))
        }
    }
}
