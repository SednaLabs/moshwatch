// SPDX-License-Identifier: GPL-3.0-or-later

//! Local build and install orchestration for `moshwatch`.
//!
//! `xtask` owns the repo's operational install story: building the vendored
//! `mosh-server`, copying runtime artifacts into a stable per-user prefix,
//! wiring the wrapper, and installing the user service.

use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result};
use moshwatch_core::{
    AppConfig, MetricCardinality, MetricKind, MetricLabelSchema, MetricPrivacy, MetricsDetailTier,
    metric_catalog,
};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use tempfile::NamedTempFile;

const PATH_BLOCK_START: &str = "# >>> moshwatch path >>>";
const PATH_BLOCK_END: &str = "# <<< moshwatch path <<<";

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_string());
    match command.as_str() {
        "build" => build_all(),
        "install" => {
            build_all()?;
            install_artifacts()?;
            install_wrapper()?;
            install_shell_integration()?;
            install_service()?;
            Ok(())
        }
        "install-artifacts" => install_artifacts(),
        "install-wrapper" => {
            install_artifacts()?;
            install_wrapper()
        }
        "install-service" => install_service(),
        "install-shell-integration" => install_shell_integration(),
        "sync-observability-docs" => sync_observability_docs(false),
        "check-observability-docs" => sync_observability_docs(true),
        "validate-observability-assets" => validate_observability_assets(),
        _ => {
            eprintln!(
                "usage: cargo run -p xtask -- <build|install|install-artifacts|install-wrapper|install-service|install-shell-integration|sync-observability-docs|check-observability-docs|validate-observability-assets>"
            );
            Ok(())
        }
    }
}

fn repo_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("determine repo root")
}

fn install_root() -> Result<PathBuf> {
    Ok(home_dir()?.join(".local/share/moshwatch"))
}

fn install_bin_dir() -> Result<PathBuf> {
    Ok(install_root()?.join("bin"))
}

fn build_all() -> Result<()> {
    // Keep `dist/bin` as the repo-local handoff point. Both local development
    // and `xtask install` consume the same built artifacts from there.
    let root = repo_root()?;
    let dist_bin = root.join("dist/bin");
    let vendor_source = root.join("vendor/mosh");
    let vendor_build = root.join("build/vendor-mosh");
    fs::create_dir_all(&dist_bin).context("create dist/bin")?;
    fs::create_dir_all(&vendor_build).context("create vendor build dir")?;

    if !vendor_source.join("configure").exists() {
        run(Command::new("bash")
            .arg("autogen.sh")
            .current_dir(&vendor_source))?;
    }

    configure_vendor_build(&vendor_source, &vendor_build)?;
    run(Command::new("make")
        .arg(format!("-j{}", available_parallelism()))
        .current_dir(&vendor_build))?;

    install_binary(
        &vendor_build.join("src/frontend/mosh-server"),
        &dist_bin.join("mosh-server-real"),
    )
    .context("copy instrumented mosh-server")?;

    run(Command::new("cargo")
        .arg("build")
        .arg("--locked")
        .arg("--release")
        .arg("-p")
        .arg("moshwatchd")
        .arg("-p")
        .arg("moshwatch-ui")
        .current_dir(&root))?;

    install_binary(
        &root.join("target/release/moshwatchd"),
        &dist_bin.join("moshwatchd"),
    )
    .context("copy moshwatchd")?;
    install_binary(
        &root.join("target/release/moshwatch-ui"),
        &dist_bin.join("moshwatch"),
    )
    .context("copy moshwatch ui")?;
    Ok(())
}

fn configure_vendor_build(vendor_source: &Path, vendor_build: &Path) -> Result<()> {
    let configure = || {
        run(Command::new(vendor_source.join("configure"))
            .arg("--enable-server")
            .arg("--disable-client")
            .arg("--disable-examples")
            .arg("--enable-compile-warnings=no")
            .current_dir(vendor_build))
    };

    match configure() {
        Ok(()) => Ok(()),
        Err(_error) => {
            eprintln!(
                "moshwatch xtask: configure failed in {}, cleaning and retrying once",
                vendor_build.display()
            );
            let _ = fs::remove_dir_all(vendor_build);
            fs::create_dir_all(vendor_build)
                .with_context(|| format!("recreate vendor build dir {}", vendor_build.display()))?;
            configure().context("retry configure after cleaning vendor build dir")?;
            Ok(())
        }
    }
}

fn install_artifacts() -> Result<()> {
    let root = repo_root()?;
    let dist_bin = root.join("dist/bin");
    let install_bin = install_bin_dir()?;
    let user_bin = home_dir()?.join(".local/bin");

    fs::create_dir_all(&install_bin)
        .with_context(|| format!("create install bin dir {}", install_bin.display()))?;
    fs::create_dir_all(&user_bin).context("create ~/.local/bin")?;

    install_binary(
        &dist_bin.join("mosh-server-real"),
        &install_bin.join("mosh-server-real"),
    )?;
    install_binary(
        &dist_bin.join("moshwatchd"),
        &install_bin.join("moshwatchd"),
    )?;
    install_binary(&dist_bin.join("moshwatch"), &install_bin.join("moshwatch"))?;
    install_binary(&dist_bin.join("moshwatch"), &user_bin.join("moshwatch"))?;
    Ok(())
}

fn install_wrapper() -> Result<()> {
    let root = repo_root()?;
    let user_bin = home_dir()?.join(".local/bin");
    fs::create_dir_all(&user_bin).context("create ~/.local/bin")?;
    let rendered = render_template(
        root.join("scripts/mosh-server-wrapper.sh"),
        &[(
            "@INSTALL_BIN_DIR@",
            install_bin_dir()?.display().to_string(),
        )],
    )?;
    install_text_file(&user_bin.join("mosh-server"), &rendered, 0o755)?;
    Ok(())
}

fn install_shell_integration() -> Result<()> {
    // Non-interactive SSH command shells often bypass interactive PATH setup,
    // so install a tiny sourced snippet and manage it from both `.bashrc` and
    // `.profile` instead of assuming one shell startup path.
    let home = home_dir()?;
    let config_dir = home.join(".config/moshwatch");
    fs::create_dir_all(&config_dir).context("create ~/.config/moshwatch")?;

    let snippet_path = config_dir.join("path.sh");
    let snippet = r#"# Added by moshwatch install. Keep ~/.local/bin ahead of system PATH so SSH-launched Mosh sessions resolve the wrapper.
if [ -d "$HOME/.local/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) PATH="$HOME/.local/bin:$PATH" ;;
    esac
fi
"#;
    install_text_file(&snippet_path, snippet, 0o644)?;

    let block = format!(
        "{PATH_BLOCK_START}\n[ -r \"$HOME/.config/moshwatch/path.sh\" ] && . \"$HOME/.config/moshwatch/path.sh\"\n{PATH_BLOCK_END}\n"
    );
    upsert_managed_block(&home.join(".bashrc"), &block, Placement::Prepend)?;
    upsert_managed_block(&home.join(".profile"), &block, Placement::Append)?;
    Ok(())
}

fn install_service() -> Result<()> {
    let root = repo_root()?;
    let target_dir = home_dir()?.join(".config/systemd/user");
    fs::create_dir_all(&target_dir).context("create systemd user dir")?;
    let rendered = render_template(
        root.join("systemd/moshwatchd.service.template"),
        &[(
            "@INSTALL_BIN_DIR@",
            install_bin_dir()?.display().to_string(),
        )],
    )?;
    let target = target_dir.join("moshwatchd.service");
    install_text_file(&target, &rendered, 0o644)?;
    run(Command::new("systemctl").arg("--user").arg("daemon-reload"))?;
    run(Command::new("systemctl")
        .arg("--user")
        .arg("enable")
        .arg("moshwatchd.service"))?;
    run(Command::new("systemctl")
        .arg("--user")
        .arg("restart")
        .arg("moshwatchd.service"))?;
    Ok(())
}

fn render_template(path: PathBuf, replacements: &[(&str, String)]) -> Result<String> {
    let mut template =
        fs::read_to_string(&path).with_context(|| format!("read template {}", path.display()))?;
    for (needle, replacement) in replacements {
        template = template.replace(needle, replacement);
    }
    Ok(template)
}

fn available_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
}

fn home_dir() -> Result<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

fn run(command: &mut Command) -> Result<()> {
    let status = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("spawn {:?}", command))?;
    if !status.success() {
        anyhow::bail!("command {:?} failed with status {status}", command);
    }
    Ok(())
}

fn install_binary(source: &Path, destination: &Path) -> Result<()> {
    install_file_with_temporary(destination, 0o600, |temporary| {
        let mut source_file =
            fs::File::open(source).with_context(|| format!("open {}", source.display()))?;
        let destination_path = temporary.path().to_path_buf();
        let destination_file = temporary.as_file_mut();
        io::copy(&mut source_file, destination_file).with_context(|| {
            format!(
                "copy {} to {}",
                source.display(),
                destination_path.display()
            )
        })?;
        destination_file
            .flush()
            .with_context(|| format!("flush {}", destination_path.display()))
    })?;
    make_executable(destination)
}

fn install_text_file(destination: &Path, contents: &str, mode: u32) -> Result<()> {
    install_file_with_temporary(destination, mode, |temporary| {
        let temporary_path = temporary.path().to_path_buf();
        let file = temporary.as_file_mut();
        file.write_all(contents.as_bytes())
            .with_context(|| format!("write {}", temporary_path.display()))?;
        file.flush()
            .with_context(|| format!("flush {}", temporary_path.display()))
    })
}

fn upsert_managed_block(path: &Path, block: &str, placement: Placement) -> Result<()> {
    // Update only the marked block so repeated installs are idempotent and do
    // not trample unrelated shell customizations.
    let existing = fs::read_to_string(path).unwrap_or_default();
    let cleaned = strip_managed_block(&existing);
    let updated = match placement {
        Placement::Prepend => {
            if cleaned.trim().is_empty() {
                block.to_string()
            } else {
                format!("{block}\n{}", cleaned.trim_start_matches('\n'))
            }
        }
        Placement::Append => {
            if cleaned.trim().is_empty() {
                block.to_string()
            } else {
                format!("{}\n\n{block}", cleaned.trim_end())
            }
        }
    };
    let mode = file_mode_or_default(path, 0o644);
    install_text_file(path, &updated, mode)
}

fn strip_managed_block(contents: &str) -> String {
    let mut cleaned = contents.to_string();
    while let Some(start) = cleaned.find(PATH_BLOCK_START) {
        let Some(end_relative) = cleaned[start..].find(PATH_BLOCK_END) else {
            break;
        };
        let end = start + end_relative + PATH_BLOCK_END.len();
        let trailing_newline = cleaned[end..]
            .strip_prefix('\n')
            .map(|rest| cleaned.len() - rest.len())
            .unwrap_or(end);
        cleaned.replace_range(start..trailing_newline, "");
    }
    cleaned
}

fn file_mode_or_default(path: &Path, default_mode: u32) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Ok(metadata) = fs::metadata(path) {
            return metadata.permissions().mode();
        }
    }
    default_mode
}

fn install_file_with_temporary<F>(destination: &Path, mode: u32, write: F) -> Result<()>
where
    F: FnOnce(&mut NamedTempFile) -> Result<()>,
{
    // Create the temporary file in the destination directory and keep it open
    // for the whole write. That preserves atomic `persist()` behavior while
    // avoiding the old predictable `*.tmp` path that could be pre-staged by a
    // same-user process.
    let mut temporary = create_temporary_file_in_same_dir(destination, mode)?;
    let temporary_path = temporary.path().to_path_buf();
    (|| {
        write(&mut temporary)?;
        set_mode_if_unix(&temporary_path, mode)?;
        temporary
            .persist(destination)
            .map(|_| ())
            .with_context(|| {
                format!(
                    "rename {} to {}",
                    temporary_path.display(),
                    destination.display()
                )
            })?;
        Ok(())
    })()
}

fn create_temporary_file_in_same_dir(path: &Path, mode: u32) -> Result<NamedTempFile> {
    let parent = path
        .parent()
        .context("determine temporary file parent directory")?;
    let file_name = path
        .file_name()
        .context("determine temporary file name")?
        .to_string_lossy();
    let prefix = format!(".{file_name}.");
    let temporary = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .tempfile_in(parent)
        .with_context(|| format!("create temporary file alongside {}", path.display()))?;
    set_mode_if_unix(temporary.path(), mode)?;
    Ok(temporary)
}

fn sync_observability_docs(check_only: bool) -> Result<()> {
    let root = repo_root()?;
    write_or_check_generated(
        &root.join("docs/observability/metric-catalog.md"),
        &render_metric_catalog_markdown(),
        check_only,
    )?;
    write_or_check_generated(
        &root.join("examples/observability/config/moshwatch.toml"),
        &render_default_config_toml()?,
        check_only,
    )?;
    Ok(())
}

fn validate_observability_assets() -> Result<()> {
    let root = repo_root()?;
    sync_observability_docs(true)?;

    let required = [
        root.join("docs/observability/operator-guide.md"),
        root.join("docs/observability/metric-catalog.md"),
        root.join("docs/observability/migration.md"),
        root.join("examples/observability/README.md"),
        root.join("examples/observability/config/moshwatch.toml"),
        root.join("examples/observability/prometheus/README.md"),
        root.join("examples/observability/prometheus/prometheus.yml"),
        root.join("examples/observability/prometheus/rules/moshwatch.rules.yml"),
        root.join("examples/observability/prometheus/tests/moshwatch.rules.test.yml"),
        root.join("examples/observability/grafana/README.md"),
        root.join("examples/observability/grafana/provisioning/datasources/moshwatch.yml"),
        root.join("examples/observability/grafana/provisioning/dashboards/moshwatch.yml"),
        root.join("examples/observability/grafana/dashboards/moshwatch-overview.json"),
        root.join("examples/observability/otel-collector/README.md"),
        root.join("examples/observability/otel-collector/otelcol.yaml"),
    ];
    for path in &required {
        anyhow::ensure!(
            path.exists(),
            "missing required observability asset {}",
            path.display()
        );
    }

    let config: AppConfig = toml::from_str(&fs::read_to_string(
        root.join("examples/observability/config/moshwatch.toml"),
    )?)
    .context("parse generated moshwatch observability config example")?;
    config.validate()?;

    parse_yaml(root.join("examples/observability/prometheus/prometheus.yml"))?;
    parse_yaml(root.join("examples/observability/prometheus/rules/moshwatch.rules.yml"))?;
    parse_yaml(root.join("examples/observability/prometheus/tests/moshwatch.rules.test.yml"))?;
    parse_yaml(root.join("examples/observability/grafana/provisioning/datasources/moshwatch.yml"))?;
    parse_yaml(root.join("examples/observability/grafana/provisioning/dashboards/moshwatch.yml"))?;
    parse_yaml(root.join("examples/observability/otel-collector/otelcol.yaml"))?;

    let dashboard =
        parse_json(root.join("examples/observability/grafana/dashboards/moshwatch-overview.json"))?;
    anyhow::ensure!(
        dashboard.get("title").and_then(JsonValue::as_str).is_some(),
        "Grafana dashboard is missing a title"
    );
    anyhow::ensure!(
        dashboard
            .get("panels")
            .and_then(JsonValue::as_array)
            .is_some(),
        "Grafana dashboard is missing panels"
    );
    anyhow::ensure!(
        dashboard.get("templating").is_some(),
        "Grafana dashboard is missing templating"
    );

    if command_exists("promtool") {
        run(Command::new("promtool")
            .arg("check")
            .arg("config")
            .arg("--syntax-only")
            .arg(root.join("examples/observability/prometheus/prometheus.yml")))?;
        run(Command::new("promtool")
            .arg("check")
            .arg("rules")
            .arg(root.join("examples/observability/prometheus/rules/moshwatch.rules.yml")))?;
        run(Command::new("promtool")
            .arg("test")
            .arg("rules")
            .arg(root.join("examples/observability/prometheus/tests/moshwatch.rules.test.yml")))?;
    } else {
        eprintln!("warning: promtool not found; skipping Prometheus semantic validation");
    }

    Ok(())
}

fn render_metric_catalog_markdown() -> String {
    let mut output = String::from(
        "<!-- Generated by `cargo run --locked -p xtask -- sync-observability-docs`; do not edit by hand. -->

# Metric Catalog

This file is generated from `crates/moshwatch-core/src/observability.rs`. It is the canonical exported metrics contract for Prometheus/OpenMetrics and OTLP.

| Metric | Type | Unit | Labels | Minimum Detail Tier | Privacy | Cardinality | Description |
| --- | --- | --- | --- | --- | --- | --- | --- |
",
    );
    for descriptor in metric_catalog() {
        let _ = std::fmt::Write::write_fmt(
            &mut output,
            format_args!(
                "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} |
",
                descriptor.name,
                metric_kind_name(descriptor.kind),
                descriptor.unit,
                label_schema_name(descriptor.labels),
                detail_tier_name(descriptor.minimum_detail_tier),
                privacy_name(descriptor.privacy),
                cardinality_name(descriptor.cardinality),
                descriptor.help.replace('|', "\\|"),
            ),
        );
    }
    output
}

fn render_default_config_toml() -> Result<String> {
    let config = AppConfig::default();
    let body = toml::to_string_pretty(&config).context("render default app config TOML")?;
    Ok(format!(
        "# Generated by `cargo run --locked -p xtask -- sync-observability-docs`; do not edit by hand.

{body}"
    ))
}

fn write_or_check_generated(path: &Path, expected: &str, check_only: bool) -> Result<()> {
    if check_only {
        let actual = fs::read_to_string(path)
            .with_context(|| format!("read generated file {}", path.display()))?;
        anyhow::ensure!(
            actual == expected,
            "generated file {} is out of date; run `cargo run --locked -p xtask -- sync-observability-docs`",
            path.display()
        );
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create generated doc parent {}", parent.display()))?;
    }
    install_text_file(path, expected, 0o644)
}

fn parse_yaml(path: PathBuf) -> Result<YamlValue> {
    let body = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_yaml::from_str(&body).with_context(|| format!("parse YAML {}", path.display()))
}

fn parse_json(path: PathBuf) -> Result<JsonValue> {
    let body = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&body).with_context(|| format!("parse JSON {}", path.display()))
}

fn command_exists(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn metric_kind_name(kind: MetricKind) -> &'static str {
    match kind {
        MetricKind::Gauge => "gauge",
        MetricKind::Counter => "counter",
        MetricKind::Info => "info",
    }
}

fn cardinality_name(cardinality: MetricCardinality) -> &'static str {
    match cardinality {
        MetricCardinality::Static => "static",
        MetricCardinality::Low => "low",
        MetricCardinality::PerSession => "per_session",
    }
}

fn privacy_name(privacy: MetricPrivacy) -> &'static str {
    match privacy {
        MetricPrivacy::FleetSafe => "fleet_safe",
        MetricPrivacy::OperatorSensitive => "operator_sensitive",
    }
}

fn label_schema_name(labels: MetricLabelSchema) -> &'static str {
    match labels {
        MetricLabelSchema::None => "none",
        MetricLabelSchema::BuildVersion => "version",
        MetricLabelSchema::Observer => "observer",
        MetricLabelSchema::Kind => "kind",
        MetricLabelSchema::KindHealth => "kind,health",
        MetricLabelSchema::Loop => "loop",
        MetricLabelSchema::Severity => "severity",
        MetricLabelSchema::Result => "result",
        MetricLabelSchema::ExporterDetailTier => "detail_tier",
        MetricLabelSchema::SessionValue => "session_id,kind",
        MetricLabelSchema::SessionInfo => {
            "session_id,display_session_id,kind,pid,started_at_unix_ms"
        }
        MetricLabelSchema::SessionWindow => "session_id,kind,window",
    }
}

fn detail_tier_name(detail_tier: MetricsDetailTier) -> &'static str {
    match detail_tier {
        MetricsDetailTier::AggregateOnly => "aggregate_only",
        MetricsDetailTier::PerSession => "per_session",
    }
}

enum Placement {
    Prepend,
    Append,
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    set_mode_if_unix(path, 0o755)
}

#[cfg(unix)]
fn set_mode_if_unix(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("chmod {:o} {}", mode, path.display()))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_mode_if_unix(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, fs::symlink},
    };

    use tempfile::tempdir;

    use super::{
        PATH_BLOCK_END, PATH_BLOCK_START, Placement, install_binary, install_text_file,
        render_template, strip_managed_block, upsert_managed_block,
    };

    #[test]
    fn strip_managed_block_removes_existing_section() {
        let input = format!("before\n{PATH_BLOCK_START}\nmanaged\n{PATH_BLOCK_END}\nafter\n");
        let cleaned = strip_managed_block(&input);
        assert_eq!(cleaned, "before\nafter\n");
    }

    #[test]
    fn upsert_managed_block_prepends_once() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join(".bashrc");
        fs::write(&path, "existing\n").expect("write");
        let block = format!("{PATH_BLOCK_START}\nmanaged\n{PATH_BLOCK_END}\n");

        upsert_managed_block(&path, &block, Placement::Prepend).expect("first upsert");
        upsert_managed_block(&path, &block, Placement::Prepend).expect("second upsert");

        let contents = fs::read_to_string(&path).expect("read");
        assert_eq!(contents.matches(PATH_BLOCK_START).count(), 1);
        assert!(contents.starts_with(PATH_BLOCK_START));
    }

    #[test]
    fn render_template_replaces_install_prefix_placeholder() {
        let tempdir = tempdir().expect("tempdir");
        let template_path = tempdir.path().join("template.service");
        fs::write(&template_path, "ExecStart=@INSTALL_BIN_DIR@/moshwatchd\n")
            .expect("write template");

        let rendered = render_template(
            template_path,
            &[("@INSTALL_BIN_DIR@", "/tmp/moshwatch/bin".to_string())],
        )
        .expect("render template");

        assert_eq!(rendered, "ExecStart=/tmp/moshwatch/bin/moshwatchd\n");
    }

    #[test]
    fn install_text_file_ignores_staged_legacy_tmp_symlink() {
        let tempdir = tempdir().expect("tempdir");
        let destination = tempdir.path().join("config.toml");
        let victim = tempdir.path().join("victim.txt");
        fs::write(&victim, "keep").expect("write victim");
        symlink(&victim, destination.with_extension("tmp")).expect("create staged tmp symlink");

        install_text_file(&destination, "safe", 0o644).expect("install text file");

        assert_eq!(
            fs::read_to_string(&destination).expect("read destination"),
            "safe"
        );
        assert_eq!(fs::read_to_string(&victim).expect("read victim"), "keep");
    }

    #[test]
    fn install_binary_ignores_staged_legacy_tmp_symlink() {
        let tempdir = tempdir().expect("tempdir");
        let source = tempdir.path().join("source-bin");
        let destination = tempdir.path().join("moshwatch");
        let victim = tempdir.path().join("victim.bin");
        fs::write(&source, b"binary").expect("write source");
        fs::write(&victim, b"keep").expect("write victim");
        symlink(&victim, destination.with_extension("tmp")).expect("create staged tmp symlink");

        install_binary(&source, &destination).expect("install binary");

        assert_eq!(fs::read(&destination).expect("read destination"), b"binary");
        assert_eq!(fs::read(&victim).expect("read victim"), b"keep");
        let mode = fs::metadata(&destination)
            .expect("stat destination")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }
}
