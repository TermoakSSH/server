//! `termoak-server`: the Termoak server.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use termoak_server::config::{EXAMPLE, ServerConfig};
use termoak_server::{build_state, routes};

#[derive(Parser)]
#[command(name = "termoak-server", version, about = "Termoak server")]
struct Cli {
    /// TOML configuration file.
    #[arg(short, long, env = "TERMOAK_CONFIG", global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Starts the server (default).
    Serve,
    /// Prints an example configuration.
    ExampleConfig,
    /// Prints the OpenAPI contract.
    Openapi,
    /// User management.
    User {
        #[command(subcommand)]
        action: UserCmd,
    },
    /// Status of the AI providers.
    AiProviders,
    /// Session holder: keeps the SSH connections of the server sessions so
    /// restarting the server does not cut them (separate service).
    SessionsHolder {
        /// Socket (default: `[sessions] holder_socket`).
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Holder protocol version (for deployment).
    #[command(hide = true)]
    HolderProtocol,
}

#[derive(Subcommand)]
enum UserCmd {
    /// Creates a user.
    Add {
        email: String,
        #[arg(long, default_value = "")]
        name: String,
        #[arg(long)]
        admin: bool,
        /// Password (otherwise read from TERMOAK_PASSWORD).
        #[arg(long, env = "TERMOAK_PASSWORD")]
        password: String,
    },
    /// Lists the users.
    List,
    /// Changes a user's password.
    Passwd {
        email: String,
        #[arg(long, env = "TERMOAK_PASSWORD")]
        password: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,russh=warn,tower_http=info".into()),
        )
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let config = ServerConfig::load(cli.config.as_deref())?;
    match cli.command.unwrap_or(Command::Serve) {
        Command::ExampleConfig => {
            print!("{EXAMPLE}");
            Ok(())
        }
        Command::Openapi => {
            println!(
                "{}",
                serde_json::to_string_pretty(&termoak_server::openapi::document())?
            );
            Ok(())
        }
        Command::User { action } => {
            let state = build_state(config).await?;
            match action {
                UserCmd::Add {
                    email,
                    name,
                    admin,
                    password,
                } => {
                    let u = state
                        .store
                        .create_user(&email, &name, &password, admin)
                        .await?;
                    println!(
                        "User created: {} ({}){}",
                        u.email,
                        u.id,
                        if u.is_admin { " [admin]" } else { "" }
                    );
                }
                UserCmd::List => {
                    for u in state.store.list_users().await? {
                        println!(
                            "{}  {:30} {:20} {}{}",
                            u.id,
                            u.email,
                            u.name,
                            if u.is_admin { "admin " } else { "" },
                            if u.disabled { "disabled" } else { "" }
                        );
                    }
                }
                UserCmd::Passwd { email, password } => {
                    let u = state
                        .store
                        .user_by_email(&email)
                        .await?
                        .context("no such user")?;
                    state.store.set_password(u.id, &password).await?;
                    println!("Password changed for {}", u.email);
                }
            }
            Ok(())
        }
        Command::AiProviders => {
            let state = build_state(config).await?;
            for p in state.ai.providers().await {
                println!(
                    "{:14} {:32} {}",
                    p.key,
                    p.label,
                    if p.available {
                        format!(
                            "available (model: {})",
                            p.default_model.unwrap_or_else(|| "default".into())
                        )
                    } else {
                        format!("unavailable: {}", p.reason.unwrap_or_default())
                    }
                );
            }
            println!("\nChain: {}", state.ai.registry().chain(None).join(" → "));
            Ok(())
        }
        Command::SessionsHolder { socket } => {
            let socket = socket
                .or(config.sessions.holder_socket)
                .context("missing socket: --socket or [sessions] holder_socket")?;
            let stop = tokio_util::sync::CancellationToken::new();
            let on_signal = stop.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                on_signal.cancel();
            });
            termoak_server::holder::daemon::run(&socket, stop).await
        }
        Command::HolderProtocol => {
            println!("{}", termoak_server::holder::proto::PROTOCOL);
            Ok(())
        }
        Command::Serve => serve(config).await,
    }
}

async fn serve(config: ServerConfig) -> anyhow::Result<()> {
    let listen = config.server.listen;
    let tls = match (&config.server.tls_cert, &config.server.tls_key) {
        (Some(c), Some(k)) => Some((c.clone(), k.clone())),
        (None, None) => None,
        _ => anyhow::bail!("tls_cert and tls_key must be set together"),
    };
    let state = build_state(config).await?;
    termoak_server::start_sessions(&state).await?;
    let chain = state.ai.registry().chain(None);
    tracing::info!(
        %listen,
        tls = tls.is_some(),
        ai = %if chain.is_empty() { "no providers".to_string() } else { chain.join(" → ") },
        "Termoak {} listening",
        env!("CARGO_PKG_VERSION")
    );
    let app = routes::router(state);
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down…");
        shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
    });
    match tls {
        Some((cert, key)) => {
            let rustls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .context("could not load the TLS certificate")?;
            // No Nagle: terminals send many small chunks and each one would
            // wait for the previous one to be acknowledged (up to 40 ms).
            let acceptor = axum_server::tls_rustls::RustlsAcceptor::new(rustls)
                .acceptor(axum_server::accept::NoDelayAcceptor::new());
            axum_server::bind(listen)
                .acceptor(acceptor)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
        None => {
            axum_server::bind(listen)
                .acceptor(axum_server::accept::NoDelayAcceptor::new())
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
    }
    Ok(())
}
