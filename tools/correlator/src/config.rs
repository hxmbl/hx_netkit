use std::path::PathBuf;
use serde::Deserialize;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default = "default_interface")]
    pub interface: String,
    #[serde(default = "default_target")]
    pub target: String,
    #[serde(default = "default_duration")]
    pub duration: u64,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_save_path")]
    pub save_path: PathBuf,
    #[serde(default)]
    pub ai: AiConfig,
    pub ollama_url: Option<String>,
    /// Ollama context window (tokens). Default 12288 — keep ≤16384 on 8GB RAM.
    #[serde(default = "default_num_ctx")]
    pub num_ctx: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AiConfig {
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self { model: default_model(), enabled: true }
    }
}

pub fn default_interface() -> String { "en1".into() }
pub fn default_target() -> String { "192.168.1.0/24".into() }
pub fn default_duration() -> u64 { 300 }
pub fn default_model() -> String { "qwen3:4b".into() }
pub fn default_save_path() -> PathBuf { dirs().join("correlator") }
fn default_true() -> bool { true }
pub fn default_num_ctx() -> u32 { 12288 }

pub fn dirs() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".correlator"))
        .unwrap_or_else(|_| std::env::temp_dir().join("correlator"))
}

pub fn load_config() -> Config {
    let paths = [
        PathBuf::from("correlator.toml"),
        dirs().join("config.toml"),
        PathBuf::from("/etc/correlator/config.toml"),
    ];
    for p in &paths {
        if p.exists() {
            if let Ok(content) = std::fs::read_to_string(p) {
                if let Ok(cfg) = toml::from_str::<Config>(&content) {
                    return cfg;
                }
            }
        }
    }
    Config::default()
}

/// Resolve the Ollama model: CLI flag wins, else top-level `model` when customized,
/// else `[ai].model`. This matches configs that set `model = "hermes3:8b"` at top level
/// while leaving a stale `[ai].model`.
pub fn resolve_model<'a>(cli: Option<&'a str>, config: &'a Config) -> &'a str {
    if let Some(m) = cli {
        return m;
    }
    if config.model != default_model() {
        &config.model
    } else {
        &config.ai.model
    }
}
