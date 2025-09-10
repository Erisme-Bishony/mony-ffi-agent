use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, process::Command, str};
use tracing_subscriber::{fmt, EnvFilter};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "mony-ffi-agent")]
#[command(about = "Runner Agent for Mony FFI Cloud (replay executor)")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server: String,
    #[arg(long, default_value = "local-dev")]
    runner_id: String,
    #[arg(long, env = "MONY_TOKEN", default_value = "dev-token")]
    token: String,
}

#[derive(Serialize)]
struct LeaseRequest { runner_id: String, token: Option<String> }

#[derive(Deserialize, Debug, Clone)]
struct RepoRef { provider: String, owner: String, name: String }

#[derive(Deserialize, Debug, Clone)]
struct LeaseResponse {
    job_id: Uuid,
    repo: RepoRef,
    target_key: String,
    commit_sha: String,
}

#[derive(Serialize)]
#[serde(tag = "type", content = "reason")]
enum JobStatus { Queued, Running, Succeeded, Failed(String) }

#[derive(Serialize)]
struct ReportRequest { job_id: Uuid, status: JobStatus, note: Option<String> }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt().with_env_filter(EnvFilter::from_default_env()).init();
    let args = Cli::parse();

    // 禁用系统代理，避免本地 127.0.0.1 走公司代理导致 502
    let client = reqwest::Client::builder().no_proxy().build()?;

    tracing::info!("agent starting, server={}, runner_id={}", args.server, args.runner_id);

    loop {
        // 1) 租约
        let lease_url = format!("{}/lease", args.server);
        let resp = client.post(&lease_url)
            .json(&LeaseRequest { runner_id: args.runner_id.clone(), token: Some(args.token.clone()) })
            .send().await?;

        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            continue;
        }
        if !resp.status().is_success() {
            tracing::warn!("lease failed: {}", resp.status());
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }

        let lease: LeaseResponse = resp.json().await?;
        tracing::info!(
            "leased job {} repo={}/{}, target={}, sha={}",
            lease.job_id, lease.repo.owner, lease.repo.name, lease.target_key, lease.commit_sha
        );

        // 2) 生成 & 执行重放脚本
        let script_path = write_replay_script(&lease)?;
        let run = run_replay_script(&script_path)?;

        // 3) 解析脚本打印的“产物路径”，做校验
        let (status, note) = match run {
            ExecResult { code: 0, stdout, stderr } => {
                let artifact = parse_artifact_from_stdout(&stdout);
                if let Some(p) = artifact {
                    if p.exists() {
                        let (sha, size) = sha256_and_size(&p)?;
                        let msg = format!(
                            "artifact_ok path={} sha256={} size={}B",
                            p.display(), sha, size
                        );
                        (JobStatus::Succeeded, Some(msg))
                    } else {
                        let msg = format!("artifact_missing stdout={} stderr={}", trim(&stdout), trim(&stderr));
                        (JobStatus::Failed("artifact missing".into()), Some(msg))
                    }
                } else {
                    let msg = format!("no_artifact_hint stdout={} stderr={}", trim(&stdout), trim(&stderr));
                    (JobStatus::Failed("no artifact in stdout".into()), Some(msg))
                }
            }
            ExecResult { code, stdout, stderr } => {
                let reason = format!("replay exit {}", code);
                let msg = format!("stdout={} stderr={}", trim(&stdout), trim(&stderr));
                (JobStatus::Failed(reason), Some(msg))
            }
        };

        // 4) 回报
        let report_url = format!("{}/report", args.server);
        let ok = client.post(&report_url)
            .json(&ReportRequest { job_id: lease.job_id, status, note })
            .send().await?.status().is_success();
        tracing::info!("report result: {}", ok);
    }
}

fn write_replay_script(lease: &LeaseResponse) -> anyhow::Result<PathBuf> {
    let mut work = std::env::temp_dir();
    work.push(format!("ffi_work_{}", lease.job_id));
    fs::create_dir_all(&work)?;

    // 失败测试：设置 MONY_FAIL=1 会让脚本返回非零
    let induce_fail = std::env::var("MONY_FAIL").ok().as_deref() == Some("1");

    #[cfg(windows)]
    {
        use std::fmt::Write as _;
        let mut p = work.clone();
        p.push("replay.ps1");
        let mut content = String::new();
        writeln!(content, r#"$ErrorActionPreference = 'Stop'"#)?;
        writeln!(content, r#"$ProgressPreference = 'SilentlyContinue'"#)?;
        writeln!(content, r#"$env:TARGET_KEY = "{}""#, lease.target_key)?;
        writeln!(content, r#"$env:COMMIT_SHA = "{}""#, lease.commit_sha)?;
        writeln!(content, r#"$work = "{}""#, work.display())?;
        writeln!(content, r#"New-Item -ItemType Directory -Force $work | Out-Null"#)?;
        // TODO: 真正接入 git clone / maturin build / audit / sbom
        if induce_fail {
            writeln!(content, r#"Write-Error "forced failure via MONY_FAIL"; exit 1"#)?;
        } else {
            writeln!(content, r#""build ok: $env:TARGET_KEY $env:COMMIT_SHA" | Out-File -Encoding utf8 "$work\artifact.txt""#)?;
            // 将产物绝对路径打印到 stdout 的最后一行（Agent 用于解析）
            writeln!(content, r#"Write-Host "$work\artifact.txt""#)?;
        }
        fs::write(&p, content)?;
        Ok(p)
    }

    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        use std::fmt::Write as _;
        let mut p = work.clone();
        p.push("replay.sh");
        let mut content = String::new();
        writeln!(content, "#!/usr/bin/env bash")?;
        writeln!(content, "set -euo pipefail")?;
        writeln!(content, r#"export TARGET_KEY="{}""#, lease.target_key)?;
        writeln!(content, r#"export COMMIT_SHA="{}""#, lease.commit_sha)?;
        writeln!(content, r#"work="{}""#, work.display())?;
        writeln!(content, r#"mkdir -p "$work""#)?;
        if induce_fail {
            writeln!(content, r#"echo "forced failure via MONY_FAIL" >&2; exit 1"#)?;
        } else {
            writeln!(content, r#"echo "build ok: $TARGET_KEY $COMMIT_SHA" > "$work/artifact.txt""#)?;
            writeln!(content, r#"echo "$work/artifact.txt""#)?;
        }
        fs::write(&p, content)?;
        let mut perm = fs::metadata(&p)?.permissions();
        perm.set_mode(0o755);
        fs::set_permissions(&p, perm)?;
        Ok(p)
    }
}

struct ExecResult { code: i32, stdout: String, stderr: String }

fn run_replay_script(path: &PathBuf) -> anyhow::Result<ExecResult> {
    #[cfg(windows)]
    let output = Command::new("powershell")
        .args(["-NoProfile","-ExecutionPolicy","Bypass","-File", &path.to_string_lossy()])
        .output()?;

    #[cfg(not(windows))]
    let output = Command::new("bash")
        .arg(&path)
        .output()?;

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Ok(ExecResult { code, stdout, stderr })
}

fn parse_artifact_from_stdout(stdout: &str) -> Option<PathBuf> {
    let last = stdout.lines().rev().find(|l| !l.trim().is_empty())?.trim().to_string();
    let p = PathBuf::from(last);
    Some(p)
}

fn sha256_and_size(p: &PathBuf) -> anyhow::Result<(String, u64)> {
    use sha2::{Digest, Sha256};
    let bytes = fs::read(p)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha = format!("{:x}", hasher.finalize());
    Ok((sha, bytes.len() as u64))
}

fn trim(s: &str) -> String {
    let s = s.trim();
    if s.len() > 500 { format!("{}...[trunc]", &s[..500]) } else { s.to_string() }
}
