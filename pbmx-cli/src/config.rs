//! Configuration reading/writing

use crate::{constants::CONFIG_FILE_NAME, Result};
use std::{collections::HashMap, fs};

#[derive(Debug, Default)]
pub struct Config {
    pub tokens: HashMap<u64, String>,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigRaw {
    tokens: Option<HashMap<String, String>>,
}

impl Config {
    pub fn read() -> Result<Config> {
        if fs::metadata(CONFIG_FILE_NAME).is_err() {
            return Ok(Config::default());
        }
        let s = fs::read_to_string(CONFIG_FILE_NAME)?;
        let raw: ConfigRaw = toml::from_str(&s)?;
        let raw_tokens = raw.tokens.unwrap_or_default();
        let tokens: HashMap<_, _> = raw_tokens
            .into_iter()
            .map(|(k, v)| Ok((str::parse::<u64>(&k)?, v)))
            .collect::<Result<_>>()?;
        Ok(Config { tokens })
    }
}
