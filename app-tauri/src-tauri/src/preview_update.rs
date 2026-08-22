//! Bounded discovery for OsaGuard's signed GitHub preview channel.
//!
//! GitHub's `releases/latest` endpoint excludes prereleases. Preview builds
//! therefore discover a newer immutable prerelease tag through the GitHub API,
//! then hand that tag's exact `latest.json` to Tauri for signature verification.

use reqwest::{redirect::Policy, Client, StatusCode};
use semver::Version;
use serde::Deserialize;
use std::time::Duration;
use tokio::time::Instant;

pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
pub const UPDATE_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
const DISCOVERY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RELEASES_API: &str = "https://api.github.com/repos/aiwaki/osaguard/releases?per_page=100";
const RELEASES_PER_PAGE: usize = 100;
const MAX_RELEASE_PAGES: usize = 3;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_TOTAL_BYTES: usize = MAX_RESPONSE_BYTES * MAX_RELEASE_PAGES;
const REPOSITORY: &str = "aiwaki/osaguard";
const APPCAST_ASSET: &str = "latest.json";
const ARCHIVE_ASSET: &str = "OsaGuard.app.tar.gz";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewRelease {
    pub version: Version,
    pub appcast_url: String,
    pub archive_url: String,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

pub fn is_preview_version(version: &Version) -> bool {
    preview_sequence(version).is_some()
}

fn preview_sequence(version: &Version) -> Option<u64> {
    if !version.build.is_empty() {
        return None;
    }
    let mut parts = version.pre.as_str().split('.');
    if parts.next()? != "preview" {
        return None;
    }
    let sequence_text = parts.next()?;
    if parts.next().is_some()
        || sequence_text.is_empty()
        || (sequence_text.len() > 1 && sequence_text.starts_with('0'))
    {
        return None;
    }
    let sequence = sequence_text.parse::<u64>().ok()?;
    (sequence > 0).then_some(sequence)
}

fn parse_preview_tag(tag: &str) -> Option<Version> {
    let raw = tag.strip_prefix('v')?;
    let version = Version::parse(raw).ok()?;
    if !is_preview_version(&version) || format!("v{version}") != tag {
        return None;
    }
    Some(version)
}

fn release_asset_url(tag: &str, asset: &str) -> String {
    format!("https://github.com/{REPOSITORY}/releases/download/{tag}/{asset}")
}

pub fn select_preview_release(
    current: &Version,
    response: &[u8],
) -> Result<Option<PreviewRelease>, String> {
    if response.len() > MAX_RESPONSE_BYTES {
        return Err("preview release response exceeds the byte limit".into());
    }
    if !is_preview_version(current) {
        return Err("preview discovery requires a preview package version".into());
    }
    let releases: Vec<GithubRelease> = serde_json::from_slice(response)
        .map_err(|error| format!("invalid preview release response: {error}"))?;
    if releases.len() > RELEASES_PER_PAGE {
        return Err("preview release response exceeds the item limit".into());
    }

    let mut selected: Option<PreviewRelease> = None;
    for release in releases {
        if release.draft || !release.prerelease {
            continue;
        }
        let Some(version) = parse_preview_tag(&release.tag_name) else {
            continue;
        };
        if version <= *current {
            continue;
        }
        let expected_appcast = release_asset_url(&release.tag_name, APPCAST_ASSET);
        let expected_archive = release_asset_url(&release.tag_name, ARCHIVE_ASSET);
        let mut appcasts = release
            .assets
            .iter()
            .filter(|asset| asset.name == APPCAST_ASSET);
        let Some(appcast) = appcasts.next() else {
            continue;
        };
        if appcasts.next().is_some() || appcast.browser_download_url != expected_appcast {
            continue;
        }
        let mut archives = release
            .assets
            .iter()
            .filter(|asset| asset.name == ARCHIVE_ASSET);
        let Some(archive) = archives.next() else {
            continue;
        };
        if archives.next().is_some() || archive.browser_download_url != expected_archive {
            continue;
        }
        let candidate = PreviewRelease {
            version,
            appcast_url: expected_appcast,
            archive_url: expected_archive,
        };
        if selected
            .as_ref()
            .is_none_or(|existing| candidate.version > existing.version)
        {
            selected = Some(candidate);
        }
    }
    Ok(selected)
}

pub async fn discover_preview_release(current: &Version) -> Result<Option<PreviewRelease>, String> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let client = Client::builder()
        .connect_timeout(DISCOVERY_CONNECT_TIMEOUT)
        .timeout(DISCOVERY_TIMEOUT)
        .redirect(Policy::none())
        .user_agent("OsaGuard-Updater/1")
        .build()
        .map_err(|error| format!("preview discovery client unavailable: {error}"))?;
    let deadline = Instant::now() + DISCOVERY_TIMEOUT;
    let mut selected: Option<PreviewRelease> = None;
    let mut total_bytes = 0_usize;
    for page in 1..=MAX_RELEASE_PAGES {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| "preview discovery exceeded its deadline".to_string())?;
        let mut response = client
            .get(format!("{RELEASES_API}&page={page}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .timeout(remaining)
            .send()
            .await
            .map_err(|error| format!("preview discovery failed: {error}"))?;
        if response.status() != StatusCode::OK {
            return Err(format!(
                "preview discovery returned HTTP {}",
                response.status()
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err("preview release response exceeds the byte limit".into());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("preview discovery body failed: {error}"))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES
                || total_bytes
                    .saturating_add(body.len())
                    .saturating_add(chunk.len())
                    > MAX_TOTAL_BYTES
            {
                return Err("preview release response exceeds the byte limit".into());
            }
            body.extend_from_slice(&chunk);
        }
        total_bytes = total_bytes.saturating_add(body.len());
        let item_count = serde_json::from_slice::<Vec<serde_json::Value>>(&body)
            .map_err(|error| format!("invalid preview release response: {error}"))?
            .len();
        if let Some(candidate) = select_preview_release(current, &body)? {
            if selected
                .as_ref()
                .is_none_or(|existing| candidate.version > existing.version)
            {
                selected = Some(candidate);
            }
        }
        if item_count < RELEASES_PER_PAGE {
            return Ok(selected);
        }
    }
    Err("preview release history exceeds the bounded page limit".into())
}

#[cfg(test)]
mod tests {
    use super::{is_preview_version, select_preview_release};
    use semver::Version;
    use serde_json::json;

    fn asset(tag: &str, name: &str) -> serde_json::Value {
        json!({
            "name": name,
            "browser_download_url": format!(
                "https://github.com/aiwaki/osaguard/releases/download/{tag}/{name}"
            )
        })
    }

    fn release(tag: &str) -> serde_json::Value {
        json!({
            "tag_name": tag,
            "draft": false,
            "prerelease": true,
            "assets": [asset(tag, "latest.json"), asset(tag, "OsaGuard.app.tar.gz")]
        })
    }

    #[test]
    fn preview_version_shape_is_exact() {
        assert!(is_preview_version(
            &Version::parse("0.1.3-preview.1").unwrap()
        ));
        assert!(!is_preview_version(&Version::parse("0.1.3").unwrap()));
        assert!(!is_preview_version(
            &Version::parse("0.1.3-preview.0").unwrap()
        ));
        assert!(Version::parse("0.1.3-preview.01").is_err());
        assert!(!is_preview_version(
            &Version::parse("0.1.3-preview.1+local").unwrap()
        ));
    }

    #[test]
    fn newest_newer_immutable_preview_wins() {
        let response = serde_json::to_vec(&json!([
            release("v0.1.3-preview.2"),
            release("v0.1.3-preview.4"),
            release("v0.1.3-preview.3")
        ]))
        .unwrap();
        let selected =
            select_preview_release(&Version::parse("0.1.3-preview.1").unwrap(), &response)
                .unwrap()
                .unwrap();
        assert_eq!(selected.version, Version::parse("0.1.3-preview.4").unwrap());
        assert_eq!(
            selected.appcast_url,
            "https://github.com/aiwaki/osaguard/releases/download/v0.1.3-preview.4/latest.json"
        );
    }

    #[test]
    fn mutable_cross_tag_or_incomplete_assets_are_rejected() {
        let mut cross_tag = release("v0.1.3-preview.2");
        cross_tag["assets"][0]["browser_download_url"] = json!(
            "https://github.com/aiwaki/osaguard/releases/download/v0.1.3-preview.3/latest.json"
        );
        let response = serde_json::to_vec(&json!([
            cross_tag,
            {
                "tag_name": "v0.1.3-preview.3",
                "draft": false,
                "prerelease": true,
                "assets": [asset("v0.1.3-preview.3", "latest.json")]
            },
            {
                "tag_name": "v0.1.3-preview.4",
                "draft": true,
                "prerelease": true,
                "assets": [
                    asset("v0.1.3-preview.4", "latest.json"),
                    asset("v0.1.3-preview.4", "OsaGuard.app.tar.gz")
                ]
            }
        ]))
        .unwrap();
        assert_eq!(
            select_preview_release(&Version::parse("0.1.3-preview.1").unwrap(), &response).unwrap(),
            None
        );
    }
}
