//! Role-aware JSON API. Presentation and legacy routes remain separate.
use crate::{
    auth,
    roles::{self, Action, Envelope},
    runtime,
    web::App,
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

static WORKERS: Semaphore = Semaphore::const_new(2);
const COOKIE: &str = "kn_daemon_roles";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    request_id: String,
    confirmation: Option<String>,
    payload: Action,
}
fn cookie<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|p| {
            p.trim()
                .split_once('=')
                .filter(|(n, _)| *n == name)
                .map(|(_, v)| v)
        })
}
fn failure(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error":message}))).into_response()
}
fn set_cookie(r: &mut Response, app: &App, name: &str, value: &str, age: u32) {
    r.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "{name}={value}; HttpOnly; SameSite=Strict; Path=/api/v1/roles; Max-Age={age}{}",
            if app.origin.starts_with("https:") {
                "; Secure"
            } else {
                ""
            }
        )
        .parse()
        .expect("fixed cookie and generated hex"),
    );
}
pub fn routes() -> Router<App> {
    Router::new()
        .route("/api/v1/roles/auth", get(challenge))
        .route("/api/v1/roles/login", post(login))
        .route("/api/v1/roles/products/{product}", get(product))
        .route("/api/v1/roles/{action}", get(read).post(write))
        .layer(DefaultBodyLimit::max(16384))
}
async fn challenge(State(app): State<App>) -> Response {
    match auth::random() {
        Ok(nonce) => {
            let mut r = Json(json!({"csrf":nonce})).into_response();
            set_cookie(&mut r, &app, "kn_roles_login", &nonce, 600);
            r
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Sign-in unavailable"),
    }
}
async fn login(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    h: HeaderMap,
    Json(body): Json<Request>,
) -> Response {
    if h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(app.origin.as_str())
        || h.get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.len() == 64)
            != cookie(&h, "kn_roles_login").filter(|v| v.len() == 64)
        || cookie(&h, "kn_roles_login").is_none()
    {
        return failure(StatusCode::FORBIDDEN, "Refresh the sign-in challenge");
    }
    if !matches!(body.payload, Action::Login { .. }) || body.confirmation.is_some() {
        return failure(StatusCode::BAD_REQUEST, "Expected login");
    }
    let e = Envelope {
        version: 1,
        request_id: body.request_id,
        session: None,
        confirmation: None,
        payload: body.payload,
    };
    match execute(&app, e, Some(peer.ip())).await {
        Ok(mut value) => {
            let token = value
                .as_object_mut()
                .and_then(|v| v.remove("token"))
                .and_then(|v| v.as_str().map(str::to_owned))
                .expect("login returns token");
            let mut r = Json(value).into_response();
            set_cookie(&mut r, &app, COOKIE, &token, 28800);
            r
        }
        Err(e)
            if e.to_string() == "Authentication workers busy"
                || e.to_string() == "Password workers busy; retry later" =>
        {
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Authentication busy; retry later",
            )
        }
        Err(_) => failure(
            StatusCode::UNAUTHORIZED,
            "Sign-in failed or is temporarily limited",
        ),
    }
}
async fn execute(app: &App, e: Envelope, peer: Option<std::net::IpAddr>) -> anyhow::Result<Value> {
    let permit = WORKERS
        .try_acquire()
        .map_err(|_| anyhow::anyhow!("Authentication workers busy"))?;
    let store = app.store.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        roles::handle_web(
            &store,
            &e,
            peer.ok_or_else(|| anyhow::anyhow!("Browser peer unavailable"))?,
        )
        .and_then(|v| runtime::complete_analytics(&store, &e.payload, v))
    })
    .await
    .map_err(|_| anyhow::anyhow!("Request unavailable"))?
}
async fn dispatch(
    app: App,
    h: HeaderMap,
    request: Request,
    mutate: bool,
    peer: std::net::IpAddr,
) -> Response {
    let token = cookie(&h, COOKIE).unwrap_or("");
    let csrf = match roles::web_session(&app.store, token) {
        Ok(v) => v,
        Err(_) => return failure(StatusCode::UNAUTHORIZED, "Sign in again"),
    };
    if mutate
        && (h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(app.origin.as_str())
            || h.get("x-csrf-token").and_then(|v| v.to_str().ok()) != Some(csrf.as_str()))
    {
        return failure(
            StatusCode::FORBIDDEN,
            "Reload before submitting this change",
        );
    }
    let logout = matches!(request.payload, Action::Logout);
    let e = Envelope {
        version: 1,
        request_id: request.request_id,
        session: Some(token.into()),
        confirmation: request.confirmation,
        payload: request.payload,
    };
    match execute(&app, e, Some(peer)).await {
        Ok(value) => {
            let mut r = Json(value).into_response();
            if logout {
                set_cookie(&mut r, &app, COOKIE, "", 0);
            }
            r
        }
        Err(e) => public_error(&e.to_string()),
    }
}
fn public_error(message: &str) -> Response {
    let status = match message {
        "Sign in again" => StatusCode::UNAUTHORIZED,
        "Authentication workers busy" | "Password workers busy; retry later" => {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Authentication busy; retry later",
            );
        }
        "User changed; reload"
        | "Security settings changed; reload"
        | "Retention changed; reload" => StatusCode::CONFLICT,
        "Action not permitted"
        | "Web administration is disabled"
        | "Fresh confirmation required"
        | "Confirmation refused"
        | "Unexpected confirmation"
        | "Authentication refused"
        | "Authentication refused; retry later"
        | "Unknown product"
        | "Viewer cannot have product grants"
        | "Only Managers have product grants"
        | "User limit reached"
        | "Cannot remove the last enabled Operator"
        | "Use a password between 12 and 1024 bytes"
        | "Enter a valid administrator email"
        | "Authorization changed; retry after signing in" => StatusCode::FORBIDDEN,
        _ => return failure(StatusCode::INTERNAL_SERVER_ERROR, "Request unavailable"),
    };
    failure(status, message)
}
async fn read(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Path(action): Path<String>,
    h: HeaderMap,
) -> Response {
    let payload = match action.as_str() {
        "whoami" => Action::Whoami,
        "capabilities" => Action::Capabilities,
        "users" => Action::UserList,
        "security" => Action::SecurityGet,
        "audit" => Action::Audit,
        "overview" => Action::Overview,
        "retention" => Action::Retention,
        "backup-agent-status" => Action::BackupAgentStatus,
        _ => return failure(StatusCode::NOT_FOUND, "Unknown read action"),
    };
    dispatch(
        app,
        h,
        Request {
            request_id: auth::random().unwrap_or_default(),
            confirmation: None,
            payload,
        },
        false,
        peer.ip(),
    )
    .await
}
async fn product(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Path(product): Path<String>,
    h: HeaderMap,
) -> Response {
    dispatch(
        app,
        h,
        Request {
            request_id: auth::random().unwrap_or_default(),
            confirmation: None,
            payload: Action::ProductStatus { product },
        },
        false,
        peer.ip(),
    )
    .await
}
async fn write(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Path(action): Path<String>,
    h: HeaderMap,
    Json(body): Json<Request>,
) -> Response {
    let valid = matches!(
        (action.as_str(), &body.payload),
        ("confirm", Action::Reauthenticate { .. })
            | ("users-create", Action::UserCreate { .. })
            | ("users-update", Action::UserUpdate { .. })
            | ("users-reset-password", Action::UserResetPassword { .. })
            | ("security", Action::SecuritySet { .. })
            | ("password", Action::ChangePassword { .. })
            | ("logout", Action::Logout)
            | ("retention", Action::SetRetention { .. })
            | ("metrics", Action::Metrics { .. })
            | ("receipt", Action::ReceiptGet { .. })
    );
    if !valid {
        return failure(StatusCode::NOT_FOUND, "Unknown or mismatched action");
    }
    dispatch(app, h, body, true, peer.ip()).await
}
