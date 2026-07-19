use std::fs;
use std::path::Path;
#[cfg(all(test, unix))]
use std::{collections::BTreeSet, ffi::OsString, path::PathBuf, time::Duration};
#[cfg(all(unix, test))]
use std::{
    io::Read,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Instant,
};

#[cfg(all(test, unix))]
use crate::AcquisitionLimits;
#[cfg(all(test, unix))]
use crate::path_policy::{insert_collision_key, normalize_path, selected};
#[cfg(all(test, unix))]
use crate::snapshot::{CollectedMaterial, MaterializedFile, add_quota, unique_work_directory};
use crate::{AcquisitionError, AcquisitionSource};

#[cfg(all(test, unix))]
const GIT_PROGRAM: &str = "/usr/bin/git";
#[cfg(all(test, unix))]
const MAX_SAFE_VERSION_BYTES: usize = 128;
const ALLOWED_REMOTE_HOSTS: [&str; 5] = [
    "bitbucket.org",
    "codeberg.org",
    "git.sr.ht",
    "github.com",
    "gitlab.com",
];

#[cfg(all(test, unix))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GitCommandPlan {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    pub current_directory: PathBuf,
    pub max_output_bytes: usize,
    pub timeout: Duration,
}

#[cfg(all(test, unix))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GitOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
}

#[cfg(all(test, unix))]
pub(crate) trait GitRunner: Send + Sync {
    fn run(&self, plan: &GitCommandPlan) -> Result<GitOutput, AcquisitionError>;
}

#[cfg(all(test, unix))]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemGitRunner;

#[cfg(all(test, unix))]
impl GitRunner for SystemGitRunner {
    fn run(&self, plan: &GitCommandPlan) -> Result<GitOutput, AcquisitionError> {
        run_system_git(plan)
    }
}

#[cfg(all(test, unix))]
pub(crate) fn plan_git_clone(
    source: &AcquisitionSource,
    neutral_root: &Path,
    destination: &Path,
    limits: &AcquisitionLimits,
) -> Result<GitCommandPlan, AcquisitionError> {
    let (locator, protocol) = match source {
        AcquisitionSource::Https { url, revision } => {
            validate_revision(revision)?;
            (validate_https(url)?.0, "https")
        }
        AcquisitionSource::SshBrokered {
            display_host,
            opaque_handle,
            revision,
            broker_executable,
            broker_request,
        } => {
            validate_revision(revision)?;
            validate_ssh_broker(
                display_host,
                opaque_handle,
                broker_executable,
                broker_request,
            )?;
            (
                format!("ssh://promptectomy-broker.invalid/{opaque_handle}"),
                "ssh",
            )
        }
        _ => return Err(AcquisitionError::LocatorDenied),
    };
    let hooks = neutral_root
        .join("empty-hooks")
        .to_str()
        .ok_or(AcquisitionError::UnsafeStorageRoot)?
        .to_owned();
    let attributes = neutral_root
        .join("empty-attributes")
        .to_str()
        .ok_or(AcquisitionError::UnsafeStorageRoot)?
        .to_owned();
    let excludes = neutral_root
        .join("empty-excludes")
        .to_str()
        .ok_or(AcquisitionError::UnsafeStorageRoot)?
        .to_owned();
    let mut arguments = neutral_arguments(protocol, &hooks, &attributes, &excludes);
    arguments.extend([
        OsString::from("clone"),
        OsString::from("--no-checkout"),
        OsString::from("--no-tags"),
        OsString::from("--no-recurse-submodules"),
        OsString::from("--config"),
        OsString::from(format!("core.hooksPath={hooks}")),
        OsString::from("--config"),
        OsString::from("credential.helper="),
        OsString::from("--"),
        OsString::from(locator),
        destination.as_os_str().to_owned(),
    ]);
    Ok(GitCommandPlan {
        program: PathBuf::from(GIT_PROGRAM),
        arguments,
        environment: neutral_environment(source, neutral_root),
        current_directory: neutral_root.to_path_buf(),
        max_output_bytes: limits.max_git_output_bytes,
        timeout: Duration::from_secs(limits.max_git_seconds),
    })
}

#[cfg(all(test, unix))]
pub(crate) fn collect_remote(
    storage_root: &Path,
    source: &AcquisitionSource,
    selected_roots: &[String],
    limits: &AcquisitionLimits,
    runner: &dyn GitRunner,
) -> Result<CollectedMaterial, AcquisitionError> {
    let work = unique_work_directory(&storage_root.join("work"), "git")?;
    let neutral = work.path.join("neutral");
    fs::create_dir(&neutral).map_err(|_| AcquisitionError::SnapshotPublishFailed)?;
    fs::create_dir(neutral.join("empty-hooks"))
        .map_err(|_| AcquisitionError::SnapshotPublishFailed)?;
    for name in ["empty-config", "empty-attributes", "empty-excludes"] {
        fs::write(neutral.join(name), []).map_err(|_| AcquisitionError::SnapshotPublishFailed)?;
    }
    let repository = work.path.join("repository.git");
    let clone = plan_git_clone(source, &neutral, &repository, limits)?;
    require_success(runner.run(&clone)?)?;

    let (revision, redacted_locator) = match source {
        AcquisitionSource::Https { url, revision } => {
            let (_, redacted) = validate_https(url)?;
            (revision.as_str(), redacted)
        }
        AcquisitionSource::SshBrokered {
            display_host,
            revision,
            ..
        } => (
            revision.as_str(),
            format!("ssh://{display_host}/<redacted>"),
        ),
        _ => return Err(AcquisitionError::LocatorDenied),
    };
    let command = repository_command(
        source,
        &neutral,
        &repository,
        limits,
        ["rev-parse", "--verify", &format!("{revision}^{{commit}}")],
        256,
    )?;
    let commit_output = require_success(runner.run(&command)?)?;
    let commit = parse_commit(&commit_output.stdout)?;

    let command = repository_command(
        source,
        &neutral,
        &repository,
        limits,
        ["ls-tree", "-rlz", "--full-tree", &commit],
        limits.max_git_output_bytes,
    )?;
    let inventory = require_success(runner.run(&command)?)?;
    let entries = parse_inventory(&inventory.stdout, selected_roots, limits)?;
    let (files, submodule_count, lfs_pointer_count, exclusions) =
        materialize_inventory(source, &neutral, &repository, limits, runner, entries)?;
    if files.is_empty() {
        return Err(AcquisitionError::EmptySelection);
    }

    let version_command = GitCommandPlan {
        program: PathBuf::from(GIT_PROGRAM),
        arguments: vec![OsString::from("--version")],
        environment: neutral_environment(source, &neutral),
        current_directory: neutral.clone(),
        max_output_bytes: MAX_SAFE_VERSION_BYTES,
        timeout: Duration::from_secs(10),
    };
    let version_output = require_success(runner.run(&version_command)?)?;
    let git_version = safe_git_version(&version_output.stdout)?;
    let mut material =
        CollectedMaterial::new(files, redacted_locator, format!("git:{commit}"), commit);
    material.git_version = Some(git_version);
    material.submodule_count = submodule_count;
    material.lfs_pointer_count = lfs_pointer_count;
    material.path_exclusions = exclusions;
    Ok(material)
}

#[cfg(all(test, unix))]
fn materialize_inventory(
    source: &AcquisitionSource,
    neutral: &Path,
    repository: &Path,
    limits: &AcquisitionLimits,
    runner: &dyn GitRunner,
    entries: Vec<GitTreeEntry>,
) -> Result<(Vec<MaterializedFile>, usize, usize, Vec<String>), AcquisitionError> {
    let mut files = Vec::new();
    let mut total = 0_u64;
    let mut submodule_count = 0_usize;
    let mut lfs_pointer_count = 0_usize;
    let mut exclusions = Vec::new();
    for entry in entries {
        if entry.kind == "commit" {
            submodule_count += 1;
            exclusions.push(format!("submodule:{}", entry.path));
            continue;
        }
        add_quota(&mut files, &mut total, entry.size, limits)?;
        let command = repository_command(
            source,
            neutral,
            repository,
            limits,
            ["cat-file", "blob", &entry.object],
            usize::try_from(entry.size)
                .ok()
                .and_then(|size| size.checked_add(1))
                .ok_or(AcquisitionError::FileBytesExceeded)?,
        )?;
        let output = require_success(runner.run(&command)?)?;
        if u64::try_from(output.stdout.len()).map_err(|_| AcquisitionError::InvalidGitOutput)?
            != entry.size
        {
            return Err(AcquisitionError::InvalidGitOutput);
        }
        if output
            .stdout
            .starts_with(b"version https://git-lfs.github.com/spec/v1\n")
        {
            lfs_pointer_count += 1;
        }
        files.push(MaterializedFile {
            path: entry.path,
            bytes: output.stdout,
            executable: entry.executable,
        });
    }
    Ok((files, submodule_count, lfs_pointer_count, exclusions))
}

#[cfg(all(test, unix))]
fn repository_command<const N: usize>(
    source: &AcquisitionSource,
    neutral_root: &Path,
    repository: &Path,
    limits: &AcquisitionLimits,
    command: [&str; N],
    max_output_bytes: usize,
) -> Result<GitCommandPlan, AcquisitionError> {
    let hooks = neutral_root
        .join("empty-hooks")
        .to_str()
        .ok_or(AcquisitionError::UnsafeStorageRoot)?
        .to_owned();
    let attributes = neutral_root
        .join("empty-attributes")
        .to_str()
        .ok_or(AcquisitionError::UnsafeStorageRoot)?
        .to_owned();
    let excludes = neutral_root
        .join("empty-excludes")
        .to_str()
        .ok_or(AcquisitionError::UnsafeStorageRoot)?
        .to_owned();
    let protocol = match source {
        AcquisitionSource::Https { .. } => "https",
        AcquisitionSource::SshBrokered { .. } => "ssh",
        _ => return Err(AcquisitionError::LocatorDenied),
    };
    let mut arguments = neutral_arguments(protocol, &hooks, &attributes, &excludes);
    arguments.extend(command.into_iter().map(OsString::from));
    Ok(GitCommandPlan {
        program: PathBuf::from(GIT_PROGRAM),
        arguments,
        environment: neutral_environment(source, neutral_root),
        current_directory: repository.to_path_buf(),
        max_output_bytes,
        timeout: Duration::from_secs(limits.max_git_seconds),
    })
}

#[cfg(all(test, unix))]
fn neutral_arguments(
    allowed_protocol: &str,
    hooks: &str,
    attributes: &str,
    excludes: &str,
) -> Vec<OsString> {
    let mut settings = vec![
        "protocol.allow=never".to_owned(),
        "protocol.file.allow=never".to_owned(),
        "protocol.ext.allow=never".to_owned(),
        "protocol.git.allow=never".to_owned(),
        "protocol.http.allow=never".to_owned(),
        "protocol.https.allow=never".to_owned(),
        "protocol.ssh.allow=never".to_owned(),
        format!("protocol.{allowed_protocol}.allow=always"),
        format!("core.hooksPath={hooks}"),
        format!("core.attributesFile={attributes}"),
        format!("core.excludesFile={excludes}"),
        "core.fsmonitor=false".to_owned(),
        "credential.helper=".to_owned(),
        "credential.useHttpPath=true".to_owned(),
        "submodule.recurse=false".to_owned(),
        "fetch.recurseSubmodules=false".to_owned(),
        "filter.lfs.smudge=".to_owned(),
        "filter.lfs.clean=".to_owned(),
        "filter.lfs.process=".to_owned(),
        "filter.lfs.required=false".to_owned(),
        "http.followRedirects=false".to_owned(),
    ];
    let mut arguments = Vec::with_capacity(settings.len() * 2);
    for setting in settings.drain(..) {
        arguments.push(OsString::from("-c"));
        arguments.push(OsString::from(setting));
    }
    arguments
}

#[cfg(all(test, unix))]
fn neutral_environment(
    source: &AcquisitionSource,
    neutral_root: &Path,
) -> Vec<(OsString, OsString)> {
    let mut environment = vec![
        (OsString::from("HOME"), neutral_root.as_os_str().to_owned()),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("LANG"), OsString::from("C")),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            neutral_root.join("empty-config").into_os_string(),
        ),
        (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
        (
            OsString::from("GIT_ASKPASS"),
            OsString::from("/usr/bin/false"),
        ),
        (OsString::from("GIT_LFS_SKIP_SMUDGE"), OsString::from("1")),
        (OsString::from("GIT_OPTIONAL_LOCKS"), OsString::from("0")),
    ];
    if let AcquisitionSource::SshBrokered {
        broker_executable,
        broker_request,
        ..
    } = source
    {
        environment.push((
            OsString::from("GIT_SSH"),
            broker_executable.as_os_str().to_owned(),
        ));
        environment.push((OsString::from("GIT_SSH_VARIANT"), OsString::from("ssh")));
        environment.push((
            OsString::from("PROMPTECTOMY_SSH_BROKER_REQUEST"),
            broker_request.as_os_str().to_owned(),
        ));
    }
    environment
}

pub(crate) fn validate_https(url: &str) -> Result<(String, String), AcquisitionError> {
    if !url.is_ascii()
        || !url.starts_with("https://")
        || url.len() > 2048
        || url.contains(['?', '#', '\\', '%'])
    {
        return Err(AcquisitionError::LocatorDenied);
    }
    let remainder = &url[8..];
    let (authority, path) = remainder
        .split_once('/')
        .ok_or(AcquisitionError::LocatorDenied)?;
    if authority.contains('@')
        || authority.is_empty()
        || path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(AcquisitionError::LocatorDenied);
    }
    let host = validate_allowed_remote_host(authority)?;
    Ok((url.to_owned(), format!("https://{host}/<redacted>")))
}

pub(crate) fn canonical_https_host(url: &str) -> Result<String, AcquisitionError> {
    validate_https(url)?;
    let authority = url[8..]
        .split_once('/')
        .ok_or(AcquisitionError::LocatorDenied)?
        .0;
    Ok(authority
        .strip_suffix(":443")
        .unwrap_or(authority)
        .to_owned())
}

pub(crate) fn validate_remote_source(source: &AcquisitionSource) -> Result<(), AcquisitionError> {
    match source {
        AcquisitionSource::Https { url, revision } => {
            validate_revision(revision)?;
            validate_https(url)?;
        }
        AcquisitionSource::SshBrokered {
            display_host,
            opaque_handle,
            revision,
            broker_executable,
            broker_request,
        } => {
            validate_revision(revision)?;
            validate_ssh_broker(
                display_host,
                opaque_handle,
                broker_executable,
                broker_request,
            )?;
        }
        _ => return Err(AcquisitionError::LocatorDenied),
    }
    Ok(())
}

pub(crate) fn validate_public_host(authority: &str) -> Result<String, AcquisitionError> {
    let host = if let Some((host, port)) = authority.rsplit_once(':') {
        if port != "443" {
            return Err(AcquisitionError::LocatorDenied);
        }
        host
    } else {
        authority
    };
    let host = host.to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.rsplit('.').next() == Some("local")
        || host.parse::<std::net::IpAddr>().is_ok()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(AcquisitionError::LocatorDenied);
    }
    Ok(host)
}

pub(crate) fn validate_allowed_remote_host(authority: &str) -> Result<String, AcquisitionError> {
    let host = validate_public_host(authority)?;
    if !ALLOWED_REMOTE_HOSTS.contains(&host.as_str()) {
        return Err(AcquisitionError::LocatorDenied);
    }
    Ok(host)
}

pub(crate) fn validate_revision(revision: &str) -> Result<(), AcquisitionError> {
    if revision.is_empty()
        || revision.len() > 200
        || revision.starts_with('-')
        || revision.contains("..")
        || revision.contains("@{")
        || revision.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
        })
    {
        return Err(AcquisitionError::InvalidRevision);
    }
    Ok(())
}

fn validate_ssh_broker(
    display_host: &str,
    opaque_handle: &str,
    broker_executable: &Path,
    broker_request: &Path,
) -> Result<(), AcquisitionError> {
    validate_allowed_remote_host(display_host).map_err(|_| AcquisitionError::InvalidSshBroker)?;
    if opaque_handle.is_empty()
        || opaque_handle.len() > 128
        || !opaque_handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !broker_executable.is_absolute()
        || !broker_request.is_absolute()
        || !safe_regular_file(broker_executable, true)
        || !safe_regular_file(broker_request, false)
    {
        return Err(AcquisitionError::InvalidSshBroker);
    }
    Ok(())
}

fn safe_regular_file(path: &Path, executable: bool) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 || (executable && mode & 0o111 == 0) {
            return false;
        }
    }
    #[cfg(not(unix))]
    let _ = executable;
    true
}

#[derive(Debug)]
#[cfg(all(test, unix))]
struct GitTreeEntry {
    path: String,
    kind: &'static str,
    object: String,
    size: u64,
    executable: bool,
}

#[cfg(all(test, unix))]
fn parse_inventory(
    output: &[u8],
    selected_roots: &[String],
    limits: &AcquisitionLimits,
) -> Result<Vec<GitTreeEntry>, AcquisitionError> {
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(AcquisitionError::InvalidGitOutput)?;
        let metadata =
            std::str::from_utf8(&record[..tab]).map_err(|_| AcquisitionError::InvalidGitOutput)?;
        let fields = metadata.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(AcquisitionError::InvalidGitOutput);
        }
        let path = normalize_path(&record[tab + 1..], limits.max_path_bytes)?;
        if !selected(&path, selected_roots) {
            continue;
        }
        if entries.len() >= limits.max_files {
            return Err(AcquisitionError::FileCountExceeded);
        }
        insert_collision_key(&path, &mut seen)?;
        let (kind, executable, size) = match (fields[0], fields[1]) {
            ("100644", "blob") => ("blob", false, parse_object_size(fields[3])?),
            ("100755", "blob") => ("blob", true, parse_object_size(fields[3])?),
            ("160000", "commit") => ("commit", false, 0),
            _ => return Err(AcquisitionError::UnsupportedFileType),
        };
        if !valid_object_id(fields[2]) {
            return Err(AcquisitionError::InvalidGitOutput);
        }
        entries.push(GitTreeEntry {
            path,
            kind,
            object: fields[2].to_owned(),
            size,
            executable,
        });
    }
    Ok(entries)
}

#[cfg(all(test, unix))]
fn parse_object_size(value: &str) -> Result<u64, AcquisitionError> {
    value
        .parse()
        .map_err(|_| AcquisitionError::InvalidGitOutput)
}

#[cfg(all(test, unix))]
fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(all(test, unix))]
fn parse_commit(output: &[u8]) -> Result<String, AcquisitionError> {
    let value = std::str::from_utf8(output)
        .map_err(|_| AcquisitionError::InvalidGitOutput)?
        .trim();
    if !valid_object_id(value) {
        return Err(AcquisitionError::InvalidGitOutput);
    }
    Ok(value.to_owned())
}

#[cfg(all(test, unix))]
fn safe_git_version(output: &[u8]) -> Result<String, AcquisitionError> {
    let value = std::str::from_utf8(output)
        .map_err(|_| AcquisitionError::InvalidGitOutput)?
        .trim();
    if value.is_empty()
        || value.len() > MAX_SAFE_VERSION_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b' ' | b'-'))
    {
        return Err(AcquisitionError::InvalidGitOutput);
    }
    Ok(value.to_owned())
}

#[cfg(all(test, unix))]
fn require_success(output: GitOutput) -> Result<GitOutput, AcquisitionError> {
    if !output.success {
        return Err(AcquisitionError::GitFailed);
    }
    Ok(output)
}

#[cfg(all(unix, test))]
fn run_system_git(plan: &GitCommandPlan) -> Result<GitOutput, AcquisitionError> {
    use std::os::unix::process::CommandExt;

    if !plan.program.is_absolute()
        || plan.program != Path::new(GIT_PROGRAM)
        || !plan.current_directory.is_absolute()
        || plan.timeout.is_zero()
        || plan.max_output_bytes == 0
    {
        return Err(AcquisitionError::GitStartFailed);
    }
    let mut command = Command::new(&plan.program);
    command
        .args(&plan.arguments)
        .env_clear()
        .envs(plan.environment.iter().cloned())
        .current_dir(&plan.current_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| AcquisitionError::GitStartFailed)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(AcquisitionError::GitStartFailed)?;
    let stderr = child
        .stderr
        .take()
        .ok_or(AcquisitionError::GitStartFailed)?;
    let observed = Arc::new(AtomicUsize::new(0));
    let stdout_thread = capture_bounded(stdout, plan.max_output_bytes, Arc::clone(&observed), true);
    let stderr_thread =
        capture_bounded(stderr, plan.max_output_bytes, Arc::clone(&observed), false);
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| AcquisitionError::GitFailed)? {
            break status;
        }
        if started.elapsed() >= plan.timeout {
            kill_process_group(child.id());
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(AcquisitionError::GitTimedOut);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| AcquisitionError::GitFailed)??;
    stderr_thread
        .join()
        .map_err(|_| AcquisitionError::GitFailed)??;
    if observed.load(Ordering::Relaxed) > plan.max_output_bytes {
        return Err(AcquisitionError::GitOutputExceeded);
    }
    Ok(GitOutput {
        success: status.success(),
        stdout,
    })
}

#[cfg(all(unix, test))]
fn capture_bounded<R: Read + Send + 'static>(
    mut reader: R,
    max_output_bytes: usize,
    observed: Arc<AtomicUsize>,
    retain: bool,
) -> thread::JoinHandle<Result<Vec<u8>, AcquisitionError>> {
    thread::spawn(move || {
        let mut output = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|_| AcquisitionError::GitFailed)?;
            if count == 0 {
                break;
            }
            let before = observed.fetch_add(count, Ordering::Relaxed);
            if retain && before < max_output_bytes {
                let kept = count.min(max_output_bytes - before);
                output.extend_from_slice(&buffer[..kept]);
            }
        }
        Ok(output)
    })
}

#[cfg(all(unix, test))]
fn kill_process_group(process_id: u32) {
    let kill = if Path::new("/bin/kill").exists() {
        "/bin/kill"
    } else {
        "/usr/bin/kill"
    };
    let _ = Command::new(kill)
        .env_clear()
        .args(["-KILL", &format!("-{process_id}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
