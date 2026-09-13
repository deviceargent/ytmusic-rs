//! OAuth 2.0 device authorization flow for YouTube Music (RFC 8628).
//!
//! Sign-in without pasting cookies: the user gets a code and a URL, enters the code
//! on any signed-in device, and the client receives a refresh token that survives
//! restarts. [`crate::YtMusic::with_oauth`] consumes the grazing access token and
//! refreshes it when it expires.

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

/// The Google client registered for the YouTube TV device flow. This id/secret pair is
/// the public one embedded in every TV client (and in ytmusicapi); Google issues no
/// private secret for devices that cannot keep one.
pub const CLIENT_ID: &str =
    "861556708454-d6dlm3lh05idd8npek18k06be7ba3oc8.apps.googleusercontent.com";
pub const CLIENT_SECRET: &str = "SboVhoG9s0rNafixCSGGKXAT";

const SCOPE: &str = "https://www.googleapis.com/auth/youtube";
const CODE_URL: &str = "https://oauth2.googleapis.com/device/code";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// What the user has to do to authorize, returned by [`begin`].
pub struct Instructions {
    /// The code to type at [`Self::url`], e.g. `ABCD-EFGH`.
    pub user_code: String,
    /// The page to open, usually `https://www.google.com/device`.
    pub url: String,
    device_code: String,
    interval: u64,
}

/// An access token minted from a refresh token.
pub struct AccessToken {
    pub token: String,
    pub expires_at: std::time::Instant,
}

/// Starts the device flow. Show the instructions to the user, then call [`wait`].
pub async fn begin() -> Result<Instructions> {
    let http = reqwest::Client::new();
    let body = ["client_id", CLIENT_ID, "scope", SCOPE];
    let response = http
        .post(CODE_URL)
        .form(&pairs(body))
        .send()
        .await
        .context("cannot reach the google device endpoint")?;
    #[derive(Deserialize)]
    struct Code {
        device_code: String,
        user_code: String,
        verification_url: String,
        #[serde(default = "default_interval")]
        interval: u64,
    }
    let code: Code = response.json().await.context("cannot read the device code")?;
    Ok(Instructions {
        user_code: code.user_code,
        url: code.verification_url,
        device_code: code.device_code,
        interval: code.interval,
    })
}

/// Waits until the user completes the authorization, polling at Google's pace. Returns
/// the persistable refresh token; only errors on refusal or expiry.
pub async fn wait(instructions: &Instructions) -> Result<String> {
    let http = reqwest::Client::new();
    loop {
        let body = [
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("device_code", instructions.device_code.as_str()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ];
        let response = http
            .post(TOKEN_URL)
            .form(&body)
            .send()
            .await
            .context("cannot reach the token endpoint")?;
        #[derive(Deserialize)]
        struct Attempt {
            refresh_token: Option<String>,
            error: Option<String>,
        }
        let attempt: Attempt = response
            .json()
            .await
            .context("cannot read the token response")?;
        if let Some(refresh) = attempt.refresh_token {
            return Ok(refresh);
        }
        match attempt.error.as_deref() {
            Some("authorization_pending") => {
                tokio::time::sleep(std::time::Duration::from_secs(instructions.interval)).await;
            }
            Some("slow_down") => {
                tokio::time::sleep(std::time::Duration::from_secs(instructions.interval + 5)).await;
            }
            Some("access_denied") => bail!("google login was declined"),
            Some("expired_token") => bail!("the google login code expired"),
            other => bail!("google login failed: {}", other.unwrap_or("unknown error")),
        }
    }
}

/// Mints a fresh access token from a persisted refresh token.
pub async fn refresh(http: &reqwest::Client, refresh_token: &str) -> Result<AccessToken> {
    let body = [
        ("client_id", CLIENT_ID),
        ("client_secret", CLIENT_SECRET),
        ("refresh_token", refresh_token),
        ("grant_type", "refresh_token"),
    ];
    let response = http
        .post(TOKEN_URL)
        .form(&body)
        .send()
        .await
        .context("cannot reach the token endpoint")?;
    #[derive(Deserialize)]
    struct Minted {
        access_token: Option<String>,
        expires_in: Option<u64>,
        error: Option<String>,
        error_description: Option<String>,
    }
    let minted: Minted = response.json().await.context("cannot read the token")?;
    if let Some(error) = minted.error {
        let detail = minted.error_description.unwrap_or(error);
        bail!("cannot refresh the google token: {detail}");
    }
    let expires_in = minted.expires_in.unwrap_or(3600);
    Ok(AccessToken {
        token: minted.access_token.context("token carries no access_token")?,
        // Renew a minute early; the server clock may lag ours slightly.
        expires_at: std::time::Instant::now()
            + std::time::Duration::from_secs(expires_in.saturating_sub(60)),
    })
}

fn default_interval() -> u64 {
    5
}

fn pairs<const N: usize>(flat: [&str; N]) -> Vec<(&str, &str)> {
    flat.chunks_exact(2).map(|pair| (pair[0], pair[1])).collect()
}
