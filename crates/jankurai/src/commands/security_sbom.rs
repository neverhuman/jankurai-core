//! Validate scanner output; a serialized producer name is not execution authority.
use anyhow::{bail, Context, Result};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn validate(path: &Path, started: SystemTime, finished: SystemTime) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("read SBOM metadata")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_BYTES {
        bail!("SBOM must be a nonempty regular file no larger than 64 MiB");
    }
    if metadata.modified()? < started || metadata.modified()? > finished {
        bail!("SBOM file is outside this scan's time window");
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        bail!("SBOM changed size while being read");
    }
    let value = serde_json::from_slice::<UniqueJson>(&bytes)
        .context("parse SBOM without duplicate object keys")?
        .0;
    let schema: Value =
        serde_json::from_str(include_str!("../../vendor/cyclonedx/bom-1.6.schema.json"))?;
    let registry = jsonschema::Registry::new()
        .add(
            "http://cyclonedx.org/schema/spdx.schema.json",
            serde_json::from_str::<Value>(include_str!("../../vendor/cyclonedx/spdx.schema.json"))?,
        )?
        .add(
            "http://cyclonedx.org/schema/jsf-0.82.schema.json",
            serde_json::from_str::<Value>(include_str!(
                "../../vendor/cyclonedx/jsf-0.82.schema.json"
            ))?,
        )?
        .prepare()?;
    let validator = jsonschema::options()
        .offline()
        .with_registry(&registry)
        .should_validate_formats(true)
        .should_ignore_unknown_formats(false)
        .build(&schema)?;
    validator
        .validate(&value)
        .map_err(|error| anyhow::anyhow!("invalid CycloneDX SBOM: {}", error.masked()))?;
    if value["specVersion"] != "1.6"
        || !value["serialNumber"].is_string()
        || !value["components"].is_array()
    {
        bail!("SBOM requires CycloneDX 1.6, an identity, and an explicit component inventory");
    }
    let timestamp = value["metadata"]["timestamp"]
        .as_str()
        .context("SBOM requires a producer timestamp")?;
    let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp)?.timestamp();
    let start_seconds = i64::try_from(started.duration_since(UNIX_EPOCH)?.as_secs())?;
    let finish_seconds = i64::try_from(finished.duration_since(UNIX_EPOCH)?.as_secs())?;
    if !(start_seconds..=finish_seconds).contains(&timestamp) {
        bail!("SBOM producer timestamp is outside this scan's time window");
    }
    let tools = value["metadata"]["tools"]["components"]
        .as_array()
        .context("SBOM requires its scanner identity")?;
    if !tools
        .iter()
        .any(|tool| tool["name"] == "syft" && tool["version"] == "1.40.0")
    {
        bail!("SBOM must identify the pinned Syft 1.40.0 scanner");
    }
    Ok(())
}

struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = UniqueJson;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON with unique object keys")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueJson>()? {
                    if values.insert(key, value.0).is_some() {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                }
                Ok(UniqueJson(Value::Object(values)))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueJson>()? {
                    values.push(value.0);
                }
                Ok(UniqueJson(Value::Array(values)))
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Bool(value)))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| UniqueJson(Value::Number(number)))
                    .ok_or_else(|| de::Error::custom("non-finite JSON number"))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(value.to_owned())))
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}
