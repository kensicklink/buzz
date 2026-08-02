use crate::managed_agents::{resolve_command, KnownAcpRuntime};

pub(crate) fn configure_runtime_cli(
    command: &mut std::process::Command,
    runtime: Option<&KnownAcpRuntime>,
    descriptor_has_claude_code_executable: bool,
) {
    let Some(runtime) = runtime else {
        return;
    };
    if runtime.id != "claude" || descriptor_has_claude_code_executable {
        return;
    }
    if let Some(cli_path) = runtime.underlying_cli.and_then(resolve_command) {
        // Windows batch shims cannot be passed directly to CreateProcess. Let
        // the Claude adapter find the real executable through PATH instead.
        if super::path::should_skip_claude_executable(&cli_path, cfg!(windows)) {
            return;
        }
        command.env("CLAUDE_CODE_EXECUTABLE", cli_path);
    }
}

#[cfg(test)]
mod tests {
    use super::configure_runtime_cli;
    use crate::managed_agents::known_acp_runtime;

    fn fake_executable(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp
            .path()
            .join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&path, "").expect("write fake cli");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("make fake cli executable");
        }
        (temp, path)
    }

    #[test]
    fn claude_spawn_uses_the_probed_cli_executable() {
        let _guard = crate::managed_agents::lock_path_mutex();
        let (temp, cli) = fake_executable("claude");
        let original_path = std::env::var_os("PATH");
        std::env::set_var("PATH", temp.path());

        let mut command = std::process::Command::new("buzz-acp");
        configure_runtime_cli(&mut command, known_acp_runtime("claude-agent-acp"), false);

        if let Some(path) = original_path {
            std::env::set_var("PATH", path);
        } else {
            std::env::remove_var("PATH");
        }
        assert!(command.get_envs().any(|(key, value)| {
            key == "CLAUDE_CODE_EXECUTABLE" && value == Some(cli.as_os_str())
        }));
    }

    #[test]
    fn descriptor_executable_wins_over_auto_discovery() {
        let _guard = crate::managed_agents::lock_path_mutex();
        let (temp, _) = fake_executable("claude");
        let original_path = std::env::var_os("PATH");
        std::env::set_var("PATH", temp.path());

        let explicit = std::path::Path::new("/custom/claude");
        let mut command = std::process::Command::new("buzz-acp");
        command.env("CLAUDE_CODE_EXECUTABLE", explicit);
        configure_runtime_cli(&mut command, known_acp_runtime("claude-agent-acp"), true);

        if let Some(path) = original_path {
            std::env::set_var("PATH", path);
        } else {
            std::env::remove_var("PATH");
        }
        assert!(command.get_envs().any(|(key, value)| {
            key == "CLAUDE_CODE_EXECUTABLE" && value == Some(explicit.as_os_str())
        }));
    }

    #[test]
    fn codex_spawn_does_not_set_a_claude_executable() {
        let mut command = std::process::Command::new("buzz-acp");
        configure_runtime_cli(&mut command, known_acp_runtime("codex-acp"), false);
        assert!(!command
            .get_envs()
            .any(|(key, _)| key == "CLAUDE_CODE_EXECUTABLE"));
    }
}
