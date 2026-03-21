// SPDX-License-Identifier: GPL-3.0-or-later

//! Local build and install orchestration for `moshwatch`.
//!
//! `xtask` owns the repo's operational install story: building the vendored
//! `mosh-server`, copying runtime artifacts into a stable per-user prefix,
//! wiring the wrapper, and installing the user service.

use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use flate2::{Compression, GzBuilder, write::GzEncoder};
use moshwatch_core::{
    AppConfig, MetricCardinality, MetricKind, MetricLabelSchema, MetricPrivacy, MetricsDetailTier,
    metric_catalog,
};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use sha2::{Digest, Sha256};
use tar::{Builder as TarBuilder, EntryType, Header};
use tempfile::NamedTempFile;

const PATH_BLOCK_START: &str = "# >>> moshwatch path >>>";
const PATH_BLOCK_END: &str = "# <<< moshwatch path <<<";
const VENDOR_CONFIGURE_ARGS: &[&str] = &[
    "--enable-server",
    "--disable-client",
    "--disable-examples",
    "--enable-compile-warnings=no",
];
const VENDOR_BUILD_PINNED_ENV: &[(&str, &str)] = &[
    ("LANG", "C"),
    ("LC_ALL", "C"),
    ("TZ", "UTC"),
    ("ZERO_AR_DATE", "1"),
];
const VENDOR_BUILD_DEFAULT_TOOLS: &[(&str, &str)] = &[
    ("CC", "cc"),
    ("CXX", "c++"),
    ("AR", "ar"),
    ("RANLIB", "ranlib"),
    ("PKG_CONFIG", "pkg-config"),
    ("PROTOC", "protoc"),
];

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_string());
    match command.as_str() {
        "build" => {
            let root = repo_root()?;
            let source_date_epoch = local_build_source_date_epoch(&root)?;
            build_all(&root, source_date_epoch)
        }
        "install" => {
            let root = repo_root()?;
            let source_date_epoch = local_build_source_date_epoch(&root)?;
            build_all(&root, source_date_epoch)?;
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
        "package-release" => package_release(parse_package_release_tag(args)?),
        "sync-observability-docs" => sync_observability_docs(false),
        "check-observability-docs" => sync_observability_docs(true),
        "validate-observability-assets" => validate_observability_assets(),
        _ => {
            eprintln!(
                "usage: cargo run -p xtask -- <build|install|install-artifacts|install-wrapper|install-service|install-shell-integration|package-release [--tag <tag>]|sync-observability-docs|check-observability-docs|validate-observability-assets>"
            );
            Ok(())
        }
    }
}

fn parse_package_release_tag(mut args: impl Iterator<Item = String>) -> Result<String> {
    let mut tag = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--tag" => {
                let value = args.next().context("--tag requires a release tag value")?;
                tag = Some(value);
            }
            value if value.starts_with("--tag=") => {
                tag = Some(value.trim_start_matches("--tag=").to_string());
            }
            "-h" | "--help" => {
                anyhow::bail!("usage: cargo run -p xtask -- package-release [--tag <tag>]");
            }
            unexpected => anyhow::bail!("unexpected argument {unexpected}"),
        }
    }
    Ok(tag.unwrap_or_else(expected_release_tag))
}

fn expected_release_tag() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Clone)]
struct SourceMetadata {
    source_ref: String,
    source_commit: String,
    source_commit_unix_ts: u64,
    source_date_epoch: u64,
}

#[derive(Debug, Clone)]
struct MoshServerBuildInfo {
    release_tag: String,
    source_ref: String,
    source_commit: String,
    source_commit_unix_ts: u64,
    source_date_epoch: u64,
    configure_args: Vec<String>,
    packaged_binary_sha256: String,
    build_environment: BTreeMap<String, String>,
    tool_versions: BTreeMap<String, String>,
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

fn build_all(root: &Path, source_date_epoch: u64) -> Result<()> {
    // Keep `dist/bin` as the repo-local handoff point. Both local development
    // and `xtask install` consume the same built artifacts from there.
    let dist_bin = root.join("dist/bin");
    let vendor_source = root.join("vendor/mosh");
    let vendor_build = root.join("build/vendor-mosh");
    let vendor_build_env = vendored_build_environment(source_date_epoch);
    fs::create_dir_all(&dist_bin).context("create dist/bin")?;
    fs::create_dir_all(&vendor_build).context("create vendor build dir")?;

    if !vendor_source.join("configure").exists() {
        run_vendored_command(
            Command::new("bash")
                .arg("autogen.sh")
                .current_dir(&vendor_source),
            &vendor_build_env,
            source_date_epoch,
        )?;
    }

    configure_vendor_build(
        &vendor_source,
        &vendor_build,
        &vendor_build_env,
        source_date_epoch,
    )?;
    run_vendored_command(
        Command::new("make")
            .arg(format!("-j{}", available_parallelism()))
            .current_dir(&vendor_build),
        &vendor_build_env,
        source_date_epoch,
    )?;

    install_binary(
        &vendor_build.join("src/frontend/mosh-server"),
        &dist_bin.join("mosh-server-real"),
    )
    .context("copy instrumented mosh-server")?;

    run_vendored_command(
        Command::new("cargo")
            .arg("build")
            .arg("--locked")
            .arg("--release")
            .arg("-p")
            .arg("moshwatchd")
            .arg("-p")
            .arg("moshwatch-ui")
            .current_dir(root),
        &vendor_build_env,
        source_date_epoch,
    )?;

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

fn package_release(tag: String) -> Result<()> {
    ensure_release_platform()?;
    let expected_tag = expected_release_tag();
    anyhow::ensure!(
        tag == expected_tag,
        "release tag {tag} does not match workspace version tag {expected_tag}"
    );

    let root = repo_root()?;
    let source_ref = resolve_release_source_ref(&root, &tag)?;
    let source_metadata = resolve_source_metadata(&root, &source_ref)?;
    let vendor_build_env = vendored_build_environment(source_metadata.source_date_epoch);
    let artifact_paths = release_artifact_paths(&root, &tag);

    build_all(&root, source_metadata.source_date_epoch)?;
    stage_release_tree(&root, &artifact_paths.stage_dir)?;
    validate_release_tree(&artifact_paths.stage_dir)?;
    write_mosh_server_build_info(
        &artifact_paths.build_info_json,
        &MoshServerBuildInfo {
            release_tag: tag.clone(),
            source_ref: source_metadata.source_ref.clone(),
            source_commit: source_metadata.source_commit.clone(),
            source_commit_unix_ts: source_metadata.source_commit_unix_ts,
            source_date_epoch: source_metadata.source_date_epoch,
            configure_args: VENDOR_CONFIGURE_ARGS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            packaged_binary_sha256: sha256_hex(
                &artifact_paths.stage_dir.join("bin/mosh-server-real"),
            )?,
            build_environment: vendor_build_env.clone(),
            tool_versions: collect_tool_versions(&vendor_build_env)?,
        },
    )?;
    write_binary_archive(
        &artifact_paths.stage_dir,
        &artifact_paths.binary_tarball,
        source_metadata.source_date_epoch,
    )?;
    write_source_archive(&root, &tag, &source_ref, &artifact_paths.source_tarball)?;
    write_sha256_sums(
        &artifact_paths.sha256_sums,
        &[
            &artifact_paths.binary_tarball,
            &artifact_paths.source_tarball,
            &artifact_paths.build_info_json,
        ],
    )?;

    eprintln!(
        "staged {} and wrote {}",
        artifact_paths.stage_dir.display(),
        artifact_paths.release_dir.display()
    );
    Ok(())
}

fn ensure_release_platform() -> Result<()> {
    anyhow::ensure!(
        cfg!(target_os = "linux") && cfg!(target_arch = "x86_64"),
        "package-release is only supported on Linux x86_64"
    );
    Ok(())
}

fn resolve_source_metadata(root: &Path, source_ref: &str) -> Result<SourceMetadata> {
    let source_commit = capture_stdout(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .arg("rev-parse")
            .arg("--verify")
            .arg(format!("{source_ref}^{{commit}}")),
    )?;
    let source_commit_unix_ts = capture_stdout(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .arg("show")
            .arg("-s")
            .arg("--format=%ct")
            .arg(source_commit.trim()),
    )?
    .trim()
    .parse::<u64>()
    .with_context(|| format!("parse commit timestamp for {source_ref}"))?;

    Ok(SourceMetadata {
        source_ref: source_ref.to_string(),
        source_commit: source_commit.trim().to_string(),
        source_commit_unix_ts,
        source_date_epoch: source_commit_unix_ts,
    })
}

fn local_build_source_date_epoch(root: &Path) -> Result<u64> {
    local_build_source_date_epoch_from(root, |key| env::var_os(key), current_unix_time_secs)
}

fn local_build_source_date_epoch_from<F, G>(
    root: &Path,
    mut lookup: F,
    now_unix_time_secs: G,
) -> Result<u64>
where
    F: FnMut(&str) -> Option<OsString>,
    G: FnOnce() -> Result<u64>,
{
    if let Some(value) = lookup("SOURCE_DATE_EPOCH") {
        return parse_source_date_epoch(value);
    }
    if root.join(".git").exists() {
        return Ok(resolve_source_metadata(root, "HEAD")?.source_date_epoch);
    }
    now_unix_time_secs()
}

fn parse_source_date_epoch(value: OsString) -> Result<u64> {
    value
        .to_string_lossy()
        .parse::<u64>()
        .with_context(|| format!("parse SOURCE_DATE_EPOCH value {:?}", value))
}

fn current_unix_time_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_secs())
}

fn resolve_release_source_ref(root: &Path, tag: &str) -> Result<String> {
    let tracked_changes = capture_stdout(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .arg("status")
            .arg("--porcelain")
            .arg("--untracked-files=no"),
    )?;
    anyhow::ensure!(
        tracked_changes.trim().is_empty(),
        "refusing to package a release with tracked worktree changes"
    );

    let head = capture_stdout(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .arg("rev-parse")
            .arg("HEAD"),
    )?;
    let Some(tag_commit) = resolve_git_commit(root, &format!("{tag}^{{commit}}"))? else {
        return Ok("HEAD".to_string());
    };
    anyhow::ensure!(
        head.trim() == tag_commit.trim(),
        "release tag {tag} must point at HEAD before packaging"
    );
    Ok(tag.to_string())
}

struct ReleaseArtifactPaths {
    release_dir: PathBuf,
    stage_dir: PathBuf,
    binary_tarball: PathBuf,
    source_tarball: PathBuf,
    sha256_sums: PathBuf,
    build_info_json: PathBuf,
}

fn release_artifact_paths(root: &Path, tag: &str) -> ReleaseArtifactPaths {
    let release_dir = root.join("dist/release");
    let stage_dir = release_dir.join(format!("moshwatch-{tag}-linux-x86_64"));
    ReleaseArtifactPaths {
        release_dir: release_dir.clone(),
        stage_dir: stage_dir.clone(),
        binary_tarball: release_dir.join(format!("moshwatch-{tag}-linux-x86_64.tar.gz")),
        source_tarball: release_dir.join(format!("moshwatch-{tag}-source.tar.gz")),
        sha256_sums: release_dir.join("SHA256SUMS"),
        build_info_json: release_dir
            .join(format!("moshwatch-{tag}-mosh-server-real-build-info.json")),
    }
}

fn stage_release_tree(root: &Path, stage_dir: &Path) -> Result<()> {
    if stage_dir.exists() {
        fs::remove_dir_all(stage_dir)
            .with_context(|| format!("clear release stage {}", stage_dir.display()))?;
    }
    fs::create_dir_all(stage_dir)
        .with_context(|| format!("create release stage {}", stage_dir.display()))?;

    let dist_bin = root.join("dist/bin");
    let stage_bin = stage_dir.join("bin");
    let stage_templates = stage_dir.join("templates");
    let stage_licenses = stage_dir.join("licenses");
    let stage_vendor_licenses = stage_licenses.join("vendor-mosh");
    fs::create_dir_all(&stage_bin).with_context(|| format!("create {}", stage_bin.display()))?;
    fs::create_dir_all(&stage_templates)
        .with_context(|| format!("create {}", stage_templates.display()))?;
    fs::create_dir_all(&stage_vendor_licenses)
        .with_context(|| format!("create {}", stage_vendor_licenses.display()))?;

    for binary in ["mosh-server-real", "moshwatchd", "moshwatch"] {
        install_binary(&dist_bin.join(binary), &stage_bin.join(binary))
            .with_context(|| format!("stage binary {binary}"))?;
    }

    install_text_file(
        &stage_dir.join("install.sh"),
        &render_release_install_script(),
        0o755,
    )
    .context("stage release installer")?;

    for (source, destination) in [
        (
            root.join("scripts/mosh-server-wrapper.sh"),
            stage_templates.join("mosh-server-wrapper.sh"),
        ),
        (
            root.join("systemd/moshwatchd.service.template"),
            stage_templates.join("moshwatchd.service"),
        ),
        (root.join("README.md"), stage_dir.join("README.md")),
        (root.join("LICENSE"), stage_dir.join("LICENSE")),
        (root.join("NOTICE"), stage_dir.join("NOTICE")),
        (root.join("LICENSES.md"), stage_dir.join("LICENSES.md")),
        (
            root.join("vendor/mosh/AUTHORS"),
            stage_vendor_licenses.join("AUTHORS"),
        ),
        (
            root.join("vendor/mosh/COPYING"),
            stage_vendor_licenses.join("COPYING"),
        ),
        (
            root.join("vendor/mosh/COPYING.iOS"),
            stage_vendor_licenses.join("COPYING.iOS"),
        ),
        (
            root.join("vendor/mosh/README.md"),
            stage_vendor_licenses.join("README.md"),
        ),
    ] {
        install_text_file(
            &destination,
            &fs::read_to_string(&source).with_context(|| format!("read {}", source.display()))?,
            0o644,
        )
        .with_context(|| format!("stage {}", destination.display()))?;
    }

    Ok(())
}

fn validate_release_tree(stage_dir: &Path) -> Result<()> {
    for relative in [
        "bin/mosh-server-real",
        "bin/moshwatchd",
        "bin/moshwatch",
        "install.sh",
        "README.md",
        "LICENSE",
        "NOTICE",
        "LICENSES.md",
        "templates/mosh-server-wrapper.sh",
        "templates/moshwatchd.service",
        "licenses/vendor-mosh/AUTHORS",
        "licenses/vendor-mosh/COPYING",
        "licenses/vendor-mosh/COPYING.iOS",
        "licenses/vendor-mosh/README.md",
    ] {
        let path = stage_dir.join(relative);
        anyhow::ensure!(path.exists(), "missing release file {}", path.display());
    }

    let install_mode = file_mode_or_default(&stage_dir.join("install.sh"), 0);
    anyhow::ensure!(
        install_mode & 0o111 != 0,
        "release installer is not executable"
    );

    Ok(())
}

fn write_mosh_server_build_info(destination: &Path, info: &MoshServerBuildInfo) -> Result<()> {
    let body = serde_json::to_string_pretty(&serde_json::json!({
        "release_tag": &info.release_tag,
        "source": {
            "ref": &info.source_ref,
            "commit": &info.source_commit,
            "commit_unix_ts": info.source_commit_unix_ts,
            "source_date_epoch": info.source_date_epoch,
        },
        "configure": {
            "args": &info.configure_args,
            "environment": &info.build_environment,
        },
        "packaged_binary_sha256": &info.packaged_binary_sha256,
        "tool_versions": &info.tool_versions,
    }))
    .context("serialize mosh-server-real build info")?;
    install_text_file(destination, &(body + "\n"), 0o644)
}

fn render_release_install_script() -> String {
    format!(
        r#"#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

PATH_BLOCK_START='{path_block_start}'
PATH_BLOCK_END='{path_block_end}'

RELEASE_ROOT="$(CDPATH= cd -- "$(dirname -- "${{BASH_SOURCE[0]}}")" && pwd)"
INSTALL_BIN_DIR="$HOME/.local/share/moshwatch/bin"
USER_BIN_DIR="$HOME/.local/bin"
CONFIG_DIR="$HOME/.config/moshwatch"
SYSTEMD_DIR="$HOME/.config/systemd/user"

mkdir -p "$INSTALL_BIN_DIR" "$USER_BIN_DIR" "$CONFIG_DIR" "$SYSTEMD_DIR"

install -m 0755 "$RELEASE_ROOT/bin/mosh-server-real" "$INSTALL_BIN_DIR/mosh-server-real"
install -m 0755 "$RELEASE_ROOT/bin/moshwatchd" "$INSTALL_BIN_DIR/moshwatchd"
install -m 0755 "$RELEASE_ROOT/bin/moshwatch" "$INSTALL_BIN_DIR/moshwatch"
install -m 0755 "$RELEASE_ROOT/bin/moshwatch" "$USER_BIN_DIR/moshwatch"

render_template() {{
    local source_file="$1"
    local destination_file="$2"
    local rendered_file
    rendered_file="$(mktemp "$(dirname -- "$destination_file")/.${{destination_file##*/}}.XXXXXX")"
    sed "s#@INSTALL_BIN_DIR@#${{INSTALL_BIN_DIR}}#g" "$source_file" > "$rendered_file"
    mv "$rendered_file" "$destination_file"
}}

render_template "$RELEASE_ROOT/templates/mosh-server-wrapper.sh" "$USER_BIN_DIR/mosh-server"
chmod 0755 "$USER_BIN_DIR/mosh-server"

render_template "$RELEASE_ROOT/templates/moshwatchd.service" "$SYSTEMD_DIR/moshwatchd.service"
chmod 0644 "$SYSTEMD_DIR/moshwatchd.service"

cat > "$CONFIG_DIR/path.sh" <<'EOF'
# Added by moshwatch install. Keep ~/.local/bin ahead of system PATH so SSH-launched Mosh sessions resolve the wrapper.
if [ -d "$HOME/.local/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) PATH="$HOME/.local/bin:$PATH" ;;
    esac
fi
EOF

upsert_managed_block() {{
    local file_path="$1"
    local placement="$2"
    local tmp_file
    local next_file
    tmp_file="$(mktemp "$(dirname -- "$file_path")/.${{file_path##*/}}.XXXXXX")"
    next_file="$(mktemp "$(dirname -- "$file_path")/.${{file_path##*/}}.next.XXXXXX")"

    if [[ -f "$file_path" ]]; then
        awk -v start="$PATH_BLOCK_START" -v end="$PATH_BLOCK_END" '
            BEGIN {{ skipping = 0; buffered_lines = 0 }}
            !skipping && $0 == start {{
                skipping = 1
                buffered_lines = 0
                buffered[buffered_lines++] = $0
                next
            }}
            skipping {{
                buffered[buffered_lines++] = $0
                if ($0 == end) {{
                    skipping = 0
                    buffered_lines = 0
                }}
                next
            }}
            {{ print }}
            END {{
                if (skipping) {{
                    for (idx = 0; idx < buffered_lines; idx++) {{
                        print buffered[idx]
                    }}
                }}
            }}
        ' "$file_path" > "$tmp_file"
    else
        : > "$tmp_file"
    fi

    if [[ "$placement" == "prepend" ]]; then
        if [[ -s "$tmp_file" ]]; then
            {{
                printf '%s\n' "$PATH_BLOCK_START"
                printf '[ -r "$HOME/.config/moshwatch/path.sh" ] && . "$HOME/.config/moshwatch/path.sh"\n'
                printf '%s\n' "$PATH_BLOCK_END"
                printf '\n'
                cat "$tmp_file"
            }} > "$next_file"
        else
            {{
                printf '%s\n' "$PATH_BLOCK_START"
                printf '[ -r "$HOME/.config/moshwatch/path.sh" ] && . "$HOME/.config/moshwatch/path.sh"\n'
                printf '%s\n' "$PATH_BLOCK_END"
            }} > "$next_file"
        fi
    else
        if [[ -s "$tmp_file" ]]; then
            {{
                cat "$tmp_file"
                printf '\n'
                printf '%s\n' "$PATH_BLOCK_START"
                printf '[ -r "$HOME/.config/moshwatch/path.sh" ] && . "$HOME/.config/moshwatch/path.sh"\n'
                printf '%s\n' "$PATH_BLOCK_END"
            }} > "$next_file"
        else
            {{
                printf '%s\n' "$PATH_BLOCK_START"
                printf '[ -r "$HOME/.config/moshwatch/path.sh" ] && . "$HOME/.config/moshwatch/path.sh"\n'
                printf '%s\n' "$PATH_BLOCK_END"
            }} > "$next_file"
        fi
    fi

    if [[ -L "$file_path" ]]; then
        # Write through the managed path so symlinked rc files keep the link itself.
        cat "$next_file" > "$file_path"
    else
        mv "$next_file" "$file_path"
    fi
    rm -f "$tmp_file" "$next_file"
}}

upsert_managed_block "$HOME/.bashrc" prepend
upsert_managed_block "$HOME/.profile" append

systemctl --user daemon-reload
systemctl --user enable moshwatchd.service
systemctl --user restart moshwatchd.service
"#,
        path_block_start = PATH_BLOCK_START,
        path_block_end = PATH_BLOCK_END
    )
}

fn write_binary_archive(
    stage_dir: &Path,
    destination: &Path,
    source_date_epoch: u64,
) -> Result<()> {
    let stage_name = stage_dir
        .file_name()
        .context("determine release stage directory name")?
        .to_string_lossy()
        .to_string();
    write_tar_gz(destination, |tar| {
        append_normalized_release_tree(tar, stage_dir, Path::new(&stage_name), source_date_epoch)
    })
}

fn write_source_archive(
    root: &Path,
    tag: &str,
    source_ref: &str,
    destination: &Path,
) -> Result<()> {
    let archive = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("archive")
        .arg("--format=tar.gz")
        .arg(format!("--prefix=moshwatch-{tag}-source/"))
        .arg(source_ref)
        .output()
        .with_context(|| format!("archive release source {source_ref} in {}", root.display()))?;
    anyhow::ensure!(
        archive.status.success(),
        "git archive failed with status {}",
        archive.status
    );
    install_bytes(destination, &archive.stdout, 0o644)
}

fn write_tar_gz<F>(destination: &Path, mut write_archive: F) -> Result<()>
where
    F: FnMut(&mut TarBuilder<GzEncoder<&mut fs::File>>) -> Result<()>,
{
    install_file_with_temporary(destination, 0o644, |temporary| {
        let temporary_path = temporary.path().to_path_buf();
        let file = temporary.as_file_mut();
        let encoder = GzBuilder::new()
            .mtime(0)
            .write(file, Compression::default());
        let mut tar = TarBuilder::new(encoder);
        write_archive(&mut tar)?;
        let encoder = tar
            .into_inner()
            .with_context(|| format!("finalize tar archive {}", temporary_path.display()))?;
        let file = encoder
            .finish()
            .with_context(|| format!("finish gzip archive {}", temporary_path.display()))?;
        file.flush()
            .with_context(|| format!("flush {}", temporary_path.display()))
    })
}

fn append_normalized_release_tree<W: Write>(
    tar: &mut TarBuilder<W>,
    stage_dir: &Path,
    stage_name: &Path,
    source_date_epoch: u64,
) -> Result<()> {
    append_normalized_directory(tar, stage_name, source_date_epoch)?;
    let mut entries = Vec::new();
    collect_release_tree_entries(stage_dir, stage_dir, &mut entries)?;
    entries.sort();
    for relative_path in entries {
        let path = stage_dir.join(&relative_path);
        let archive_path = stage_name.join(&relative_path);
        let metadata =
            fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        if metadata.is_dir() {
            append_normalized_directory(tar, &archive_path, source_date_epoch)?;
        } else if metadata.is_file() {
            append_normalized_file(tar, &path, &archive_path, &metadata, source_date_epoch)?;
        } else {
            anyhow::bail!("unsupported release tree entry {}", path.display());
        }
    }
    Ok(())
}

fn collect_release_tree_entries(
    root: &Path,
    current: &Path,
    entries: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut children = fs::read_dir(current)
        .with_context(|| format!("read release tree directory {}", current.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("list release tree directory {}", current.display()))?;
    children.sort();
    for path in children {
        let relative_path = path
            .strip_prefix(root)
            .with_context(|| format!("strip release tree prefix {}", path.display()))?
            .to_path_buf();
        entries.push(relative_path);
        if path.is_dir() {
            collect_release_tree_entries(root, &path, entries)?;
        }
    }
    Ok(())
}

fn append_normalized_directory<W: Write>(
    tar: &mut TarBuilder<W>,
    path_in_archive: &Path,
    source_date_epoch: u64,
) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    header.set_mtime(source_date_epoch);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    tar.append_data(&mut header, path_in_archive, io::empty())
        .with_context(|| format!("append release directory {}", path_in_archive.display()))
}

fn append_normalized_file<W: Write>(
    tar: &mut TarBuilder<W>,
    path_on_disk: &Path,
    path_in_archive: &Path,
    metadata: &fs::Metadata,
    source_date_epoch: u64,
) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_size(metadata.len());
    header.set_mode(file_mode_or_default(path_on_disk, 0o644));
    header.set_mtime(source_date_epoch);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    let mut file =
        fs::File::open(path_on_disk).with_context(|| format!("open {}", path_on_disk.display()))?;
    tar.append_data(&mut header, path_in_archive, &mut file)
        .with_context(|| format!("append release file {}", path_on_disk.display()))
}

fn write_sha256_sums(destination: &Path, files: &[&Path]) -> Result<()> {
    let mut body = String::new();
    for file in files {
        let digest = sha256_hex(file)?;
        let name = file
            .file_name()
            .context("determine checksum file name")?
            .to_string_lossy();
        body.push_str(&format!("{digest}  {name}\n"));
    }
    install_text_file(destination, &body, 0o644)
}

fn sha256_hex(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("hash {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn resolve_git_commit(root: &Path, revision: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("rev-parse")
        .arg("--verify")
        .arg("-q")
        .arg(revision)
        .output()
        .with_context(|| format!("resolve git revision {revision} in {}", root.display()))?;
    if output.status.success() {
        return String::from_utf8(output.stdout)
            .map(Some)
            .context("decode git revision stdout as UTF-8");
    }
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    anyhow::bail!(
        "git rev-parse {revision} failed with status {}",
        output.status
    );
}

fn configure_vendor_build(
    vendor_source: &Path,
    vendor_build: &Path,
    build_environment: &BTreeMap<String, String>,
    source_date_epoch: u64,
) -> Result<()> {
    let configure = || {
        run_vendored_command(
            Command::new(vendor_source.join("configure"))
                .arg("--enable-server")
                .arg("--disable-client")
                .arg("--disable-examples")
                .arg("--enable-compile-warnings=no")
                .current_dir(vendor_build),
            build_environment,
            source_date_epoch,
        )
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

fn vendored_build_environment(source_date_epoch: u64) -> BTreeMap<String, String> {
    vendored_build_environment_from(source_date_epoch, |key| env::var_os(key))
}

fn vendored_build_environment_from<F>(
    source_date_epoch: u64,
    mut lookup: F,
) -> BTreeMap<String, String>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let mut environment = BTreeMap::new();
    for (key, value) in VENDOR_BUILD_PINNED_ENV {
        environment.insert(key.to_string(), (*value).to_string());
    }
    for (key, default) in VENDOR_BUILD_DEFAULT_TOOLS {
        let value = lookup(key).unwrap_or_else(|| OsString::from(default));
        environment.insert(key.to_string(), value.to_string_lossy().to_string());
    }
    for key in ["CFLAGS", "CXXFLAGS", "LDFLAGS"] {
        if let Some(value) = lookup(key) {
            environment.insert(key.to_string(), value.to_string_lossy().to_string());
        }
    }
    if let Some(value) = lookup("ARFLAGS") {
        environment.insert("ARFLAGS".to_string(), value.to_string_lossy().to_string());
    }
    environment.insert(
        "SOURCE_DATE_EPOCH".to_string(),
        source_date_epoch.to_string(),
    );
    environment
}

fn collect_tool_versions(
    build_environment: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut tool_versions = BTreeMap::new();
    for tool in ["autoconf", "automake", "make", "rustc", "cargo"] {
        tool_versions.insert(
            tool.to_string(),
            capture_tool_version(tool, &["--version"])?,
        );
    }

    for (logical_key, env_key, default) in [
        ("cc", "CC", "cc"),
        ("cxx", "CXX", "c++"),
        ("ar", "AR", "ar"),
        ("ranlib", "RANLIB", "ranlib"),
        ("pkg-config", "PKG_CONFIG", "pkg-config"),
        ("protoc", "PROTOC", "protoc"),
    ] {
        let tool = tool_command_from_environment(build_environment, env_key, default);
        tool_versions.insert(
            logical_key.to_string(),
            capture_tool_version(&tool, &["--version"])?,
        );
    }

    Ok(tool_versions)
}

fn capture_tool_version(command: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .with_context(|| format!("spawn {command}"))?;
    anyhow::ensure!(
        output.status.success(),
        "command {command:?} failed with status {}",
        output.status
    );
    let stdout = String::from_utf8(output.stdout).context("decode tool version stdout as UTF-8")?;
    Ok(stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim()
        .to_string())
}

fn tool_command_from_environment(
    build_environment: &BTreeMap<String, String>,
    key: &str,
    default: &str,
) -> String {
    build_environment
        .get(key)
        .and_then(|value| value.split_whitespace().next())
        .filter(|value| !value.is_empty())
        .unwrap_or(default)
        .to_string()
}

fn run_vendored_command(
    command: &mut Command,
    build_environment: &BTreeMap<String, String>,
    source_date_epoch: u64,
) -> Result<()> {
    for (key, value) in build_environment {
        command.env(key, value);
    }
    command.env("SOURCE_DATE_EPOCH", source_date_epoch.to_string());
    run(command)
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

fn install_bytes(destination: &Path, contents: &[u8], mode: u32) -> Result<()> {
    install_file_with_temporary(destination, mode, |temporary| {
        let temporary_path = temporary.path().to_path_buf();
        let file = temporary.as_file_mut();
        file.write_all(contents)
            .with_context(|| format!("write {}", temporary_path.display()))?;
        file.flush()
            .with_context(|| format!("flush {}", temporary_path.display()))
    })
}

fn capture_stdout(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("spawn {:?}", command))?;
    if !output.status.success() {
        anyhow::bail!("command {:?} failed with status {}", command, output.status);
    }
    String::from_utf8(output.stdout).context("decode command stdout as UTF-8")
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
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        install_text_file_through_symlink(path, &updated, mode)
    } else {
        install_text_file(path, &updated, mode)
    }
}

fn install_text_file_through_symlink(destination: &Path, contents: &str, mode: u32) -> Result<()> {
    // Follow the symlink target instead of renaming over the symlink so dotfile
    // managers such as Stow or chezmoi keep control of the link itself.
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(destination)
        .with_context(|| format!("open {}", destination.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("write {}", destination.display()))?;
    file.flush()
        .with_context(|| format!("flush {}", destination.display()))?;
    set_mode_if_unix(destination, mode)
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
        cell::Cell,
        fs,
        os::unix::{fs::PermissionsExt, fs::symlink},
        path::Path,
        thread,
        time::Duration,
    };

    use tempfile::tempdir;

    use super::{
        MoshServerBuildInfo, PATH_BLOCK_END, PATH_BLOCK_START, Placement, install_binary,
        install_text_file, local_build_source_date_epoch_from, release_artifact_paths,
        render_release_install_script, render_template, sha256_hex, stage_release_tree,
        strip_managed_block, tool_command_from_environment, upsert_managed_block,
        validate_release_tree, vendored_build_environment_from, write_binary_archive,
        write_mosh_server_build_info, write_sha256_sums,
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
    fn upsert_managed_block_preserves_symlinked_rc_file() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join(".bashrc");
        let target = tempdir.path().join("dotfiles/.bashrc");
        fs::create_dir_all(target.parent().expect("target parent")).expect("create target dir");
        fs::write(&target, "existing\n").expect("write target");
        symlink(&target, &path).expect("create symlink");
        let block = format!("{PATH_BLOCK_START}\nmanaged\n{PATH_BLOCK_END}\n");
        let expected = format!("{block}\nexisting\n");

        upsert_managed_block(&path, &block, Placement::Prepend).expect("upsert symlinked rc");

        assert!(
            fs::symlink_metadata(&path)
                .expect("stat symlink")
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&target).expect("read target"), expected);
        assert_eq!(fs::read_to_string(&path).expect("read symlink"), expected);
        let stale_next = tempdir
            .path()
            .read_dir()
            .expect("dir entries")
            .filter_map(|entry| entry.ok())
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".bashrc.next")
            });
        assert!(
            stale_next.is_none(),
            "symlink update must not leave a .next artifact"
        );
    }

    #[test]
    fn render_release_install_script_preserves_symlinked_rc_files() {
        let script = render_release_install_script();

        assert!(script.contains("local next_file"));
        assert!(script.contains(
            r#"next_file="$(mktemp "$(dirname -- "$file_path")/.${file_path##*/}.next.XXXXXX")""#
        ));
        assert!(script.contains("if [[ -L \"$file_path\" ]]; then"));
        assert!(script.contains("cat \"$next_file\" > \"$file_path\""));
        assert!(script.contains("mv \"$next_file\" \"$file_path\""));
        assert!(script.contains("rm -f \"$tmp_file\" \"$next_file\""));
        assert!(script.contains("buffered[buffered_lines++] = $0"));
        assert!(script.contains("if (skipping) {"));
        assert!(script.contains("print buffered[idx]"));
    }

    #[test]
    fn render_release_install_script_does_not_render_templates_through_symlinks() {
        let script = render_release_install_script();

        assert!(script.contains("local rendered_file"));
        assert!(script.contains(
            r#"rendered_file="$(mktemp "$(dirname -- "$destination_file")/.${destination_file##*/}.XXXXXX")""#
        ));
        assert!(script.contains(
            r#"sed "s#@INSTALL_BIN_DIR@#${INSTALL_BIN_DIR}#g" "$source_file" > "$rendered_file""#
        ));
        assert!(script.contains(r#"mv "$rendered_file" "$destination_file""#));
        assert!(!script.contains(
            r#"sed "s#@INSTALL_BIN_DIR@#${INSTALL_BIN_DIR}#g" "$source_file" > "$destination_file""#
        ));
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

    #[test]
    fn release_artifact_paths_follow_expected_layout() {
        let root = Path::new("/tmp/moshwatch");
        let paths = release_artifact_paths(root, "v1.2.3");

        assert_eq!(paths.release_dir, root.join("dist/release"));
        assert_eq!(
            paths.stage_dir,
            root.join("dist/release/moshwatch-v1.2.3-linux-x86_64")
        );
        assert_eq!(
            paths.binary_tarball,
            root.join("dist/release/moshwatch-v1.2.3-linux-x86_64.tar.gz")
        );
        assert_eq!(
            paths.source_tarball,
            root.join("dist/release/moshwatch-v1.2.3-source.tar.gz")
        );
        assert_eq!(paths.sha256_sums, root.join("dist/release/SHA256SUMS"));
        assert_eq!(
            paths.build_info_json,
            root.join("dist/release/moshwatch-v1.2.3-mosh-server-real-build-info.json")
        );
    }

    #[test]
    fn write_binary_archive_normalizes_metadata_and_is_reproducible() {
        let tempdir = tempdir().expect("tempdir");
        let source_date_epoch = 1_701_234_567;
        let first_stage = tempdir.path().join("first/moshwatch-v1.2.3-linux-x86_64");
        let second_stage = tempdir.path().join("second/moshwatch-v1.2.3-linux-x86_64");
        let first_archive = tempdir.path().join("first.tar.gz");
        let second_archive = tempdir.path().join("second.tar.gz");

        populate_release_tree(&first_stage);
        write_binary_archive(&first_stage, &first_archive, source_date_epoch)
            .expect("write first archive");

        thread::sleep(Duration::from_secs(1));
        populate_release_tree(&second_stage);
        write_binary_archive(&second_stage, &second_archive, source_date_epoch)
            .expect("write second archive");

        assert_eq!(
            sha256_hex(&first_archive).expect("hash first archive"),
            sha256_hex(&second_archive).expect("hash second archive")
        );

        let mtimes = archive_entry_mtimes(&first_archive);
        assert!(!mtimes.is_empty(), "archive should contain entries");
        assert!(mtimes.iter().all(|(_, mtime)| *mtime == source_date_epoch));
    }

    #[test]
    fn vendored_build_environment_pins_reproducibility_and_preserves_tool_overrides() {
        let environment = vendored_build_environment_from(1_701_234_567, |key| match key {
            "CXX" => Some("clang++".into()),
            "CFLAGS" => Some("-O2".into()),
            "ARFLAGS" => Some("crs".into()),
            "TZ" => Some("Australia/Melbourne".into()),
            _ => None,
        });

        assert_eq!(environment["LANG"], "C");
        assert_eq!(environment["LC_ALL"], "C");
        assert_eq!(environment["TZ"], "UTC");
        assert_eq!(environment["ZERO_AR_DATE"], "1");
        assert_eq!(environment["CC"], "cc");
        assert_eq!(environment["CXX"], "clang++");
        assert_eq!(environment["AR"], "ar");
        assert_eq!(environment["RANLIB"], "ranlib");
        assert_eq!(environment["PKG_CONFIG"], "pkg-config");
        assert_eq!(environment["PROTOC"], "protoc");
        assert_eq!(environment["CFLAGS"], "-O2");
        assert_eq!(environment["ARFLAGS"], "crs");
        assert_eq!(environment["SOURCE_DATE_EPOCH"], "1701234567");
    }

    fn populate_release_tree(stage_dir: &Path) {
        fs::create_dir_all(stage_dir.join("bin")).expect("create bin dir");
        fs::create_dir_all(stage_dir.join("templates")).expect("create templates dir");
        fs::create_dir_all(stage_dir.join("licenses/vendor-mosh"))
            .expect("create vendor license dir");

        for (path, contents) in [
            ("bin/mosh-server-real", b"server-real".as_slice()),
            ("bin/moshwatchd", b"daemon".as_slice()),
            ("bin/moshwatch", b"ui".as_slice()),
            ("README.md", b"readme".as_slice()),
            ("LICENSE", b"license".as_slice()),
            ("NOTICE", b"notice".as_slice()),
            ("LICENSES.md", b"licenses".as_slice()),
            ("install.sh", b"#!/usr/bin/env bash\n".as_slice()),
            (
                "templates/mosh-server-wrapper.sh",
                b"ExecStart=moshwatchd\n".as_slice(),
            ),
            (
                "templates/moshwatchd.service",
                b"[Service]\nExecStart=moshwatchd\n".as_slice(),
            ),
            ("licenses/vendor-mosh/AUTHORS", b"authors".as_slice()),
            ("licenses/vendor-mosh/COPYING", b"copying".as_slice()),
            (
                "licenses/vendor-mosh/COPYING.iOS",
                b"copying-ios".as_slice(),
            ),
            (
                "licenses/vendor-mosh/README.md",
                b"vendor readme".as_slice(),
            ),
        ] {
            fs::write(stage_dir.join(path), contents).expect("write release tree file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(
                stage_dir.join("install.sh"),
                fs::Permissions::from_mode(0o755),
            )
            .expect("chmod install.sh");
            for binary in ["bin/mosh-server-real", "bin/moshwatchd", "bin/moshwatch"] {
                fs::set_permissions(stage_dir.join(binary), fs::Permissions::from_mode(0o755))
                    .expect("chmod binary");
            }
        }
    }

    fn archive_entry_mtimes(path: &Path) -> Vec<(String, u64)> {
        let file = fs::File::open(path).expect("open archive");
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        let mut mtimes = Vec::new();
        for entry in archive.entries().expect("list archive entries") {
            let entry = entry.expect("read archive entry");
            let path = entry
                .path()
                .expect("read archive entry path")
                .to_string_lossy()
                .into_owned();
            let mtime = entry.header().mtime().expect("read archive entry mtime");
            mtimes.push((path, mtime));
        }
        mtimes
    }

    #[test]
    fn local_build_source_date_epoch_uses_gitless_fallback_when_no_repo_metadata_exists() {
        let tempdir = tempdir().expect("tempdir");
        let now_called = Cell::new(false);
        let epoch = local_build_source_date_epoch_from(
            tempdir.path(),
            |_| None,
            || {
                now_called.set(true);
                Ok(1_701_234_567)
            },
        )
        .expect("resolve local build source date epoch");

        assert!(now_called.get());
        assert_eq!(epoch, 1_701_234_567);
    }

    #[test]
    fn local_build_source_date_epoch_prefers_explicit_override() {
        let tempdir = tempdir().expect("tempdir");
        let now_called = Cell::new(false);
        let epoch = local_build_source_date_epoch_from(
            tempdir.path(),
            |key| {
                if key == "SOURCE_DATE_EPOCH" {
                    Some("1701234567".into())
                } else {
                    None
                }
            },
            || {
                now_called.set(true);
                Ok(42)
            },
        )
        .expect("resolve local build source date epoch");

        assert!(!now_called.get());
        assert_eq!(epoch, 1_701_234_567);
    }

    #[test]
    fn tool_command_from_environment_uses_effective_command_name() {
        let mut environment = std::collections::BTreeMap::new();
        environment.insert("CC".to_string(), "/usr/bin/clang".to_string());
        environment.insert("CXX".to_string(), "clang++".to_string());

        assert_eq!(
            tool_command_from_environment(&environment, "CC", "cc"),
            "/usr/bin/clang"
        );
        assert_eq!(
            tool_command_from_environment(&environment, "CXX", "c++"),
            "clang++"
        );
        assert_eq!(
            tool_command_from_environment(&environment, "AR", "ar"),
            "ar"
        );
    }

    #[test]
    fn write_mosh_server_build_info_records_reproducibility_metadata() {
        let tempdir = tempdir().expect("tempdir");
        let destination = tempdir.path().join("build-info.json");
        let mut build_environment = std::collections::BTreeMap::new();
        build_environment.insert("LANG".to_string(), "C".to_string());
        build_environment.insert("LC_ALL".to_string(), "C".to_string());
        build_environment.insert("TZ".to_string(), "UTC".to_string());
        build_environment.insert("ZERO_AR_DATE".to_string(), "1".to_string());
        build_environment.insert("ARFLAGS".to_string(), "cru".to_string());
        build_environment.insert("AR".to_string(), "ar".to_string());
        build_environment.insert("RANLIB".to_string(), "ranlib".to_string());
        build_environment.insert("PKG_CONFIG".to_string(), "pkg-config".to_string());
        build_environment.insert("PROTOC".to_string(), "protoc".to_string());
        build_environment.insert("CC".to_string(), "clang".to_string());
        build_environment.insert("CXX".to_string(), "clang++".to_string());
        build_environment.insert("CFLAGS".to_string(), "-O2".to_string());
        let mut tool_versions = std::collections::BTreeMap::new();
        tool_versions.insert(
            "autoconf".to_string(),
            "autoconf (GNU Autoconf) 2.71".to_string(),
        );
        tool_versions.insert("ar".to_string(), "GNU ar (GNU Binutils) 2.42".to_string());
        tool_versions.insert("cxx".to_string(), "clang version 17.0.6".to_string());
        tool_versions.insert(
            "ranlib".to_string(),
            "GNU ranlib (GNU Binutils) 2.42".to_string(),
        );
        tool_versions.insert("pkg-config".to_string(), "1.8.1".to_string());
        tool_versions.insert("protoc".to_string(), "libprotoc 27.0".to_string());
        tool_versions.insert("cc".to_string(), "cc (Ubuntu 13.2.0) 13.2.0".to_string());

        write_mosh_server_build_info(
            &destination,
            &MoshServerBuildInfo {
                release_tag: "v1.2.3".to_string(),
                source_ref: "v1.2.3".to_string(),
                source_commit: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                source_commit_unix_ts: 1_701_234_567,
                source_date_epoch: 1_701_234_567,
                configure_args: vec![
                    "--enable-server".to_string(),
                    "--disable-client".to_string(),
                ],
                packaged_binary_sha256:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                build_environment,
                tool_versions,
            },
        )
        .expect("write build info");

        let body = fs::read_to_string(&destination).expect("read build info");
        let json: serde_json::Value = serde_json::from_str(&body).expect("parse build info");
        assert_eq!(json["release_tag"], "v1.2.3");
        assert_eq!(json["source"]["ref"], "v1.2.3");
        assert_eq!(
            json["source"]["commit"],
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
        assert_eq!(json["source"]["commit_unix_ts"], 1_701_234_567);
        assert_eq!(json["source"]["source_date_epoch"], 1_701_234_567);
        assert_eq!(json["configure"]["args"][0], "--enable-server");
        assert_eq!(json["configure"]["environment"]["LANG"], "C");
        assert_eq!(json["configure"]["environment"]["LC_ALL"], "C");
        assert_eq!(json["configure"]["environment"]["TZ"], "UTC");
        assert_eq!(json["configure"]["environment"]["ZERO_AR_DATE"], "1");
        assert_eq!(json["configure"]["environment"]["ARFLAGS"], "cru");
        assert_eq!(json["configure"]["environment"]["AR"], "ar");
        assert_eq!(json["configure"]["environment"]["RANLIB"], "ranlib");
        assert_eq!(json["configure"]["environment"]["PKG_CONFIG"], "pkg-config");
        assert_eq!(json["configure"]["environment"]["PROTOC"], "protoc");
        assert_eq!(json["configure"]["environment"]["CC"], "clang");
        assert_eq!(
            json["packaged_binary_sha256"],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            json["tool_versions"]["autoconf"],
            "autoconf (GNU Autoconf) 2.71"
        );
        assert_eq!(json["tool_versions"]["cc"], "cc (Ubuntu 13.2.0) 13.2.0");
        assert_eq!(json["tool_versions"]["cxx"], "clang version 17.0.6");
        assert_eq!(json["tool_versions"]["ar"], "GNU ar (GNU Binutils) 2.42");
        assert_eq!(
            json["tool_versions"]["ranlib"],
            "GNU ranlib (GNU Binutils) 2.42"
        );
        assert_eq!(json["tool_versions"]["pkg-config"], "1.8.1");
        assert_eq!(json["tool_versions"]["protoc"], "libprotoc 27.0");
    }

    #[test]
    fn stage_release_tree_populates_expected_release_layout() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path();
        let dist_bin = root.join("dist/bin");
        fs::create_dir_all(&dist_bin).expect("create dist/bin");
        for (name, contents) in [
            ("mosh-server-real", b"server-real".as_slice()),
            ("moshwatchd", b"daemon".as_slice()),
            ("moshwatch", b"ui".as_slice()),
        ] {
            fs::write(dist_bin.join(name), contents).expect("write release binary");
        }

        fs::create_dir_all(root.join("scripts")).expect("create scripts dir");
        fs::write(
            root.join("scripts/mosh-server-wrapper.sh"),
            "ExecStart=@INSTALL_BIN_DIR@/moshwatchd\n",
        )
        .expect("write wrapper template");
        fs::create_dir_all(root.join("systemd")).expect("create systemd dir");
        fs::write(
            root.join("systemd/moshwatchd.service.template"),
            "ExecStart=@INSTALL_BIN_DIR@/moshwatchd\n",
        )
        .expect("write service template");

        fs::write(root.join("README.md"), "readme").expect("write README.md");
        fs::write(root.join("LICENSE"), "license").expect("write LICENSE");
        fs::write(root.join("NOTICE"), "notice").expect("write NOTICE");
        fs::write(root.join("LICENSES.md"), "licenses").expect("write LICENSES.md");
        fs::create_dir_all(root.join("vendor/mosh")).expect("create vendor/mosh");
        fs::write(root.join("vendor/mosh/AUTHORS"), "authors").expect("write AUTHORS");
        fs::write(root.join("vendor/mosh/COPYING"), "copying").expect("write COPYING");
        fs::write(root.join("vendor/mosh/COPYING.iOS"), "copying-ios").expect("write COPYING.iOS");
        fs::write(root.join("vendor/mosh/README.md"), "vendor readme")
            .expect("write vendor README.md");

        let stage_dir = root.join("dist/release/moshwatch-v1.2.3-linux-x86_64");
        stage_release_tree(root, &stage_dir).expect("stage release tree");
        validate_release_tree(&stage_dir).expect("validate release tree");

        assert_eq!(
            fs::read(stage_dir.join("bin/moshwatchd")).expect("read staged daemon"),
            b"daemon"
        );
        assert_eq!(
            fs::read_to_string(stage_dir.join("templates/mosh-server-wrapper.sh"))
                .expect("read staged wrapper template"),
            "ExecStart=@INSTALL_BIN_DIR@/moshwatchd\n"
        );
        assert_eq!(
            fs::read_to_string(stage_dir.join("licenses/vendor-mosh/COPYING"))
                .expect("read staged COPYING"),
            "copying"
        );
        assert_eq!(
            fs::read_to_string(stage_dir.join("README.md")).expect("read staged README"),
            "readme"
        );
        assert_eq!(
            fs::read_to_string(stage_dir.join("install.sh")).expect("read staged installer"),
            render_release_install_script()
        );
        let install_mode = fs::metadata(stage_dir.join("install.sh"))
            .expect("stat installer")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(install_mode, 0o755);
    }

    #[test]
    fn validate_release_tree_rejects_incomplete_layout() {
        let tempdir = tempdir().expect("tempdir");
        let stage_dir = tempdir
            .path()
            .join("dist/release/moshwatch-v1.2.3-linux-x86_64");
        fs::create_dir_all(&stage_dir).expect("create stage dir");
        fs::write(stage_dir.join("install.sh"), "#!/usr/bin/env bash\n").expect("write installer");

        let err = validate_release_tree(&stage_dir).expect_err("validation should fail");
        assert!(err.to_string().contains("missing release file"));
    }

    #[test]
    fn write_sha256_sums_records_basenames_and_digests() {
        let tempdir = tempdir().expect("tempdir");
        let first = tempdir.path().join("first.tar.gz");
        let second = tempdir.path().join("second.tar.gz");
        let build_info = tempdir.path().join("build-info.json");
        fs::write(&first, b"alpha").expect("write first");
        fs::write(&second, b"beta").expect("write second");
        fs::write(&build_info, b"gamma").expect("write build info");
        let destination = tempdir.path().join("SHA256SUMS");

        write_sha256_sums(&destination, &[&first, &second, &build_info]).expect("write checksums");

        let body = fs::read_to_string(&destination).expect("read checksums");
        let expected_first = format!("{}  first.tar.gz\n", sha256_hex(&first).expect("hash"));
        let expected_second = format!("{}  second.tar.gz\n", sha256_hex(&second).expect("hash"));
        let expected_build_info = format!(
            "{}  build-info.json\n",
            sha256_hex(&build_info).expect("hash")
        );
        assert_eq!(
            body,
            format!("{expected_first}{expected_second}{expected_build_info}")
        );
    }
}
