//! The Claude Code CLI that vibe-kanban runs, and what we ask it about itself.
//!
//! vibe-kanban runs the `claude` binary installed on this machine (no npx
//! pin), so the model list also comes from that binary: the `initialize`
//! control request returns every model the CLI accepts for `--model`,
//! with the concrete model each alias resolves to and its effort levels.

use std::{path::Path, process::Stdio, time::Duration};

use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};
use workspace_utils::{command_ext::GroupSpawnNoWindowExt, shell::resolve_executable_path};

use super::ClaudeCode;
use crate::{
    command::{CommandBuildError, CommandBuilder, apply_overrides},
    env::{ExecutionEnv, RepoContext},
    executors::ExecutorError,
    model_selector::{ModelInfo, ReasoningOption},
};

/// Executable looked up on PATH.
pub const CLAUDE_EXECUTABLE: &str = "claude";
/// claude-code-router (opt-in via `claude_code_router`); it wraps the local CLI.
pub const ROUTER_COMMAND: &str = "npx -y @musistudio/claude-code-router@1.0.66 code";
/// Model id the CLI uses for "whatever it recommends".
pub const CLI_DEFAULT_MODEL: &str = "default";

const MODELS_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);
const MODELS_REQUEST_ID: &str = "vk_discover_models";

/// Base command line, before any Claude flags are appended.
pub fn base_command(claude_code_router: bool) -> &'static str {
    if claude_code_router {
        ROUTER_COMMAND
    } else {
        CLAUDE_EXECUTABLE
    }
}

/// Runs `claude --version` and returns e.g. `2.1.331`.
pub async fn detect_version() -> Option<String> {
    let exe = resolve_executable_path(CLAUDE_EXECUTABLE).await?;
    let output = Command::new(exe).arg("--version").output().await.ok()?;
    if !output.status.success() {
        return None;
    }
    parse_version_output(&String::from_utf8_lossy(&output.stdout))
}

/// Parses `2.1.331 (Claude Code)` into `2.1.331`.
pub fn parse_version_output(output: &str) -> Option<String> {
    output
        .split_whitespace()
        .next()
        .filter(|tok| tok.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .map(str::to_string)
}

/// One entry of `models` in the CLI's `initialize` response.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CliModel {
    /// What to pass to `--model` (`default`, `opus`, `claude-opus-4-7`, ...).
    pub value: String,
    #[serde(default)]
    pub resolved_model: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub supported_effort_levels: Option<Vec<String>>,
}

impl From<CliModel> for ModelInfo {
    fn from(m: CliModel) -> Self {
        let display = m.display_name.unwrap_or_else(|| m.value.clone());
        // Show the concrete model behind aliases, e.g. "Default (recommended) · claude-opus-5-5".
        let name = match m.resolved_model {
            Some(resolved) if resolved != m.value && !display.contains(&resolved) => {
                format!("{display} · {resolved}")
            }
            _ => display,
        };
        ModelInfo {
            id: m.value,
            name,
            provider_id: None,
            reasoning_options: ReasoningOption::from_names(
                m.supported_effort_levels.unwrap_or_default(),
            ),
        }
    }
}

/// Extracts the models from a `control_response` line answering our request.
pub fn parse_initialize_models(line: &str) -> Option<Vec<CliModel>> {
    let json: serde_json::Value = serde_json::from_str(line).ok()?;
    if json.get("type")?.as_str()? != "control_response" {
        return None;
    }
    let response = json.get("response")?;
    if response.get("request_id")?.as_str()? != MODELS_REQUEST_ID {
        return None;
    }
    serde_json::from_value(response.get("response")?.get("models")?.clone()).ok()
}

impl ClaudeCode {
    fn build_models_discovery_command_builder(&self) -> Result<CommandBuilder, CommandBuildError> {
        let builder = CommandBuilder::new(base_command(self.claude_code_router.unwrap_or(false)))
            .params([
                "-p",
                "--verbose",
                "--output-format=stream-json",
                "--input-format=stream-json",
            ]);
        apply_overrides(builder, &self.cmd)
    }

    /// Asks the CLI which models it supports. No prompt is sent, so this makes no API call.
    pub async fn discover_cli_models(
        &self,
        current_dir: &Path,
    ) -> Result<Vec<ModelInfo>, ExecutorError> {
        let command_parts = self
            .build_models_discovery_command_builder()?
            .build_initial()?;
        let (program_path, args) = command_parts.into_resolved().await?;

        let mut command = Command::new(program_path);
        command
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .current_dir(current_dir)
            .args(&args);
        ExecutionEnv::new(RepoContext::default(), false, String::new())
            .with_profile(&self.cmd)
            .apply_to_command(&mut command);
        if self.disable_api_key.unwrap_or(false) {
            command.env_remove("ANTHROPIC_API_KEY");
        }

        let mut child = command.group_spawn_no_window()?;
        let mut stdin =
            child.inner().stdin.take().ok_or_else(|| {
                ExecutorError::Io(std::io::Error::other("Claude Code missing stdin"))
            })?;
        let stdout = child.inner().stdout.take().ok_or_else(|| {
            ExecutorError::Io(std::io::Error::other("Claude Code missing stdout"))
        })?;

        let request = serde_json::json!({
            "type": "control_request",
            "request_id": MODELS_REQUEST_ID,
            "request": { "subtype": "initialize" },
        });

        let discovery = async {
            stdin
                .write_all(format!("{request}\n").as_bytes())
                .await
                .map_err(ExecutorError::Io)?;
            stdin.flush().await.map_err(ExecutorError::Io)?;

            let mut lines = BufReader::new(stdout).lines();
            while let Some(line) = lines.next_line().await.map_err(ExecutorError::Io)? {
                if let Some(models) = parse_initialize_models(&line) {
                    return Ok(models);
                }
            }
            Err(ExecutorError::Io(std::io::Error::other(
                "Claude Code exited before reporting its models",
            )))
        };

        let res = tokio::time::timeout(MODELS_DISCOVERY_TIMEOUT, discovery).await;
        let _ = child.kill().await;

        match res {
            Ok(Ok(models)) => Ok(models.into_iter().map(ModelInfo::from).collect()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ExecutorError::Io(std::io::Error::other(
                "Timed out discovering Claude Code models",
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_command_is_local_claude() {
        assert_eq!(base_command(false), "claude");
        assert_eq!(base_command(true), ROUTER_COMMAND);
    }

    #[test]
    fn parses_version_output() {
        assert_eq!(
            parse_version_output("2.1.331 (Claude Code)\n").as_deref(),
            Some("2.1.331")
        );
        assert_eq!(parse_version_output("command not found"), None);
    }

    #[test]
    fn parses_models_from_initialize_response() {
        let line = r#"{"type":"control_response","response":{"subtype":"success","request_id":"vk_discover_models","response":{"models":[
            {"value":"default","resolvedModel":"claude-opus-5-5","displayName":"Default (recommended)","supportedEffortLevels":["low","high","max"]},
            {"value":"claude-haiku-4-5-20251001","resolvedModel":"claude-haiku-4-5-20251001","displayName":"Haiku 4.5"}
        ]}}}"#;
        let models: Vec<ModelInfo> = parse_initialize_models(line)
            .unwrap()
            .into_iter()
            .map(ModelInfo::from)
            .collect();

        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id, "default");
        assert_eq!(models[0].name, "Default (recommended) · claude-opus-5-5");
        assert_eq!(models[0].reasoning_options.len(), 3);
        assert_eq!(models[1].name, "Haiku 4.5");
        assert!(models[1].reasoning_options.is_empty());
    }

    #[test]
    fn ignores_other_lines() {
        assert!(parse_initialize_models(r#"{"type":"system","subtype":"init"}"#).is_none());
        assert!(
            parse_initialize_models(
                r#"{"type":"control_response","response":{"request_id":"other","response":{"models":[]}}}"#
            )
            .is_none()
        );
        assert!(parse_initialize_models("not json").is_none());
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Needs a logged-in `claude` on PATH: `cargo test -p executors live_cli -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn live_cli_reports_models() {
        let executor: ClaudeCode = serde_json::from_str("{}").unwrap();
        let models = executor
            .discover_cli_models(&std::env::temp_dir())
            .await
            .unwrap();
        for m in &models {
            println!("{} => {}", m.id, m.name);
        }
        assert!(models.iter().any(|m| m.id == CLI_DEFAULT_MODEL));
        println!("version: {:?}", detect_version().await);
    }
}
