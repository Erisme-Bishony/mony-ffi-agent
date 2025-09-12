/* SPDX-License-Identifier: MIT OR Apache-2.0 */
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, process::Command};
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

    // 禁用系统代理，避免 127.0.0.1 走公司代理导致 502
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

        // 3) 解析脚本打印的“产物路径”，做校验（sha256/size）
        let (status, note) = match run {
            ExecResult { code: 0, stdout, stderr } => {
                if let Some(p) = parse_artifact_from_stdout(&stdout) {
                    if p.exists() {
                        let (sha, size) = sha256_and_size(&p)?;
                        let msg = format!("artifact_ok path={} sha256={} size={}B", p.display(), sha, size);
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
        writeln!(content, r#"$work = "{}""#, work.display())?;
        writeln!(content, r#"$src = Join-Path $work 'src'"#)?;
        writeln!(content, r#"New-Item -ItemType Directory -Force $work | Out-Null"#)?;

        // 1) 准备源码：优先 REPLAY_SRC，否则 git clone
        writeln!(content, r#"if ($env:REPLAY_SRC -and (Test-Path $env:REPLAY_SRC)) {{ "#)?;
        writeln!(content, r#"  Copy-Item -Recurse -Force $env:REPLAY_SRC $src"#)?;
        writeln!(content, r#"}} else {{ "#)?;
        writeln!(content, r#"  $repoUrl = "https://github.com/{}/{}.git""#, lease.repo.owner, lease.repo.name)?;
        writeln!(content, r#"  git clone --depth 1 $repoUrl $src"#)?;
        writeln!(content, r#"  if ("{}" -ne "") {{ Push-Location $src; git fetch --depth 1 origin "{}" 2>$null; git checkout "{}"; Pop-Location }}"#, lease.commit_sha, lease.commit_sha, lease.commit_sha)?;
        writeln!(content, r#"}}"#)?;

        // 2) 安装 maturin（幂等）
        writeln!(content, r#"py -3.11 -m pip install -U pip maturin | Out-Null"#)?;

        // 3) 失败注入
        writeln!(content, r#"if ($env:MONY_FAIL -eq "1") {{ Write-Error "forced failure via MONY_FAIL"; exit 1 }}"#)?;

        // 4) 构建（针对当前平台）
        writeln!(content, r#"Push-Location $src"#)?;
        writeln!(content, r#"py -3.11 -m maturin build --release"#)?;
        writeln!(content, r#"Pop-Location"#)?;

        // 5) 找到 wheel 并输出绝对路径（Agent 解析）
        writeln!(content, r#"$wheelDir = Join-Path $src 'target\wheels'"#)?;
        writeln!(content, r#"$wheel = Get-ChildItem -Recurse -Filter *.whl $wheelDir | Sort-Object LastWriteTime -Descending | Select-Object -First 1"#)?;
        writeln!(content, r#"if (-not $wheel) {{ Write-Error "no wheel produced"; exit 1 }}"#)?;
        writeln!(content, r#"Write-Host $($wheel.FullName)"#)?;

        fs::write(&p, content)?;
        return Ok(p);
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
        writeln!(content, r#"work="{}""#, work.display())?;
        writeln!(content, r#"src="$work/src""#)?;
        writeln!(content, r#"mkdir -p "$work""#)?;
        writeln!(content, r#"if [[ -n "${REPLAY_SRC:-}" && -d "$REPLAY_SRC" ]]; then cp -r "$REPLAY_SRC" "$src"; else "#)?;
        writeln!(content, r#"  repo_url="https://github.com/{}/{}.git""#, lease.repo.owner, lease.repo.name)?;
        writeln!(content, r#"  git clone --depth 1 "$repo_url" "$src""#)?;
        writeln!(content, r#"  if [[ -n "{}" ]]; then (cd "$src" && git fetch --depth 1 origin "{}" >/dev/null 2>&1 && git checkout "{}"); fi"#, lease.commit_sha, lease.commit_sha, lease.commit_sha)?;
        writeln!(content, r#"fi"#)?;
        writeln!(content, r#"python -m pip install -U pip maturin >/dev/null"#)?;
        writeln!(content, r#"if [[ "${MONY_FAIL:-}" == "1" ]]; then echo "forced failure via MONY_FAIL" >&2; exit 1; fi"#)?;
        writeln!(content, r#"(cd "$src" && maturin build --release)"#)?;
        writeln!(content, r#"wheel_dir="$src/target/wheels""#)?;
        writeln!(content, r#"wheel=$(ls -1t "$wheel_dir"/*.whl | head -n1 || true)"#)?;
        writeln!(content, r#"[[ -n "$wheel" ]] || {{ echo "no wheel produced" >&2; exit 1 }}"#)?;
        writeln!(content, r#"echo "$wheel""#)?;
        fs::write(&p, content)?;
        let mut perm = fs::metadata(&p)?.permissions();
        perm.set_mode(0o755);
        fs::set_permissions(&p, perm)?;
        return Ok(p);
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
    Some(PathBuf::from(last))
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
    const MAX: usize = 500;
    if s.chars().count() > MAX {
        let mut out = String::with_capacity(MAX + 12);
        for (i, ch) in s.chars().enumerate() {
            if i >= MAX { break; }
            out.push(ch);
        }
        out.push_str("...[trunc]");
        out
    } else {
        s.to_string()
    }
}
