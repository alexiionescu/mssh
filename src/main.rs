use std::borrow::Cow;
///
/// Run this example with:
/// cargo run --example client_exec_simple -- -k <private key path> <host> <command>
///
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use log::{error, info};
use russh::keys::*;
use russh::*;
use tokio::io::AsyncWriteExt;
use tokio::net::ToSocketAddrs;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .init();

    // CLI options are defined later in this file
    let cli = Cli::parse();

    if cli.private_key_password.is_some() {
        info!("Key path: {}. Encrypted", cli.private_key.display());
    } else {
        info!("Key path: {}", cli.private_key.display());
    }
    if let Some(ossh_cert) = &cli.openssh_certificate {
        info!("OpenSSH Certificate path: {}", ossh_cert.display());
    }

    let commands = Vec::from_iter(cli.command.split(|c| c == ";").map(|command| {
        command
            .iter()
            .map(|x| shell_escape::escape(x.into())) // arguments are escaped manually since the SSH protocol doesn't support quoting
            .collect::<Vec<_>>()
            .join(" ")
    }));

    let hosts = if let Some(hosts_csv) = &cli.hosts_csv {
        let mut rdr = csv::ReaderBuilder::new()
            .delimiter(cli.delimiter)
            .from_path(hosts_csv)?;
        let host_idx = rdr
            .headers()?
            .iter()
            .position(|h| h.eq_ignore_ascii_case("host") || h.eq_ignore_ascii_case("ip"))
            .unwrap_or_default();
        rdr.records()
            .filter_map(Result::ok)
            .map(|record| record.get(host_idx).unwrap_or("").to_string())
            .collect::<Vec<_>>()
    } else {
        cli.hosts
            .iter()
            .map(|h| {
                cli.hosts_prefix
                    .as_ref()
                    .map_or(h.clone(), |prefix| format!("{prefix}{h}"))
            })
            .collect::<Vec<_>>()
    };
    for host in hosts {
        // Session is a wrapper around a russh client, defined down below
        match Session::connect(
            &cli.private_key,
            cli.private_key_password.as_deref(),
            cli.username.clone(),
            cli.openssh_certificate.as_ref(),
            &(host.clone(), cli.port),
        )
        .await
        {
            Ok(mut ssh) => {
                info!("Connected to {host}");
                print!("{host}\t");
                for command in &commands {
                    let code = ssh.call(command).await?;
                    if code > 0 {
                        error!("Command exited with code {code}");
                    } else {
                        info!("Command executed successfully");
                    }
                }
                println!();

                if let Err(e) = ssh.close().await {
                    error!("Failed to close session: {e}");
                }
            }
            Err(e) => {
                error!("Failed to connect to {host}: {e}");
                continue; // Skip to the next host if connection fails
            }
        }
    }
    Ok(())
}

struct Client {}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// This struct is a convenience wrapper
/// around a russh client
pub struct Session {
    session: client::Handle<Client>,
}

impl Session {
    async fn connect<P: AsRef<Path>, A: ToSocketAddrs>(
        key_path: &P,
        key_password: Option<&str>,
        user: impl Into<String>,
        openssh_cert_path: Option<&P>,
        addrs: &A,
    ) -> Result<Self> {
        let key_pair = load_secret_key(key_path, key_password)?;

        // load ssh certificate
        let mut openssh_cert = None;
        if openssh_cert_path.is_some() {
            openssh_cert = Some(load_openssh_certificate(openssh_cert_path.unwrap())?);
        }

        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            preferred: Preferred {
                kex: Cow::Owned(vec![
                    russh::kex::CURVE25519_PRE_RFC_8731,
                    russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
                ]),
                ..Default::default()
            },
            ..<_>::default()
        };

        let config = Arc::new(config);
        let sh = Client {};

        let connect_future = client::connect(config, addrs, sh);
        let mut session = match tokio::time::timeout(Duration::from_secs(5), connect_future).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => anyhow::bail!("Connection timed out after 5 seconds"),
        };
        // use publickey authentication, with or without certificate
        if openssh_cert.is_none() {
            let auth_res = session
                .authenticate_publickey(
                    user,
                    PrivateKeyWithHashAlg::new(
                        Arc::new(key_pair),
                        session.best_supported_rsa_hash().await?.flatten(),
                    ),
                )
                .await?;

            if !auth_res.success() {
                anyhow::bail!("Authentication (with publickey) failed");
            }
        } else {
            let auth_res = session
                .authenticate_openssh_cert(user, Arc::new(key_pair), openssh_cert.unwrap())
                .await?;

            if !auth_res.success() {
                anyhow::bail!("Authentication (with publickey+cert) failed");
            }
        }

        Ok(Self { session })
    }

    async fn call(&mut self, command: &str) -> Result<u32> {
        info!("Executing command: {command}");
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut code = None;
        let mut stdout = tokio::io::stdout();

        loop {
            // There's an event available on the session channel
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                // Write data to the terminal
                ChannelMsg::Data { ref data } => {
                    let out = str::from_utf8(data)
                        .unwrap_or("<non-utf8 data>")
                        .to_string()
                        .replace('\n', "\t");
                    stdout.write_all(out.as_bytes()).await?;
                    stdout.flush().await?;
                }
                // The command has returned an exit code
                ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                    // cannot leave the loop immediately, there might still be more data to receive
                }
                _ => {}
            }
        }
        Ok(code.expect("program did not exit cleanly"))
    }

    async fn close(&mut self) -> Result<()> {
        if let Err(e) = self
            .session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await
        {
            error!("Failed to disconnect: {e}");
        }
        Ok(())
    }
}

#[derive(clap::Parser)]
#[clap(trailing_var_arg = true)]
pub struct Cli {
    #[clap(
        long,
        help = "CSV where the first 'Host' column contains hosts to connect to"
    )]
    hosts_csv: Option<PathBuf>,
    #[clap(long, help = "Prefix for hosts, e.g. '192.168.168.'")]
    hosts_prefix: Option<String>,
    #[clap(
        long,
        help = "Hosts to connect to, can be specified multiple times, e.g. '21,22,23'"
    )]
    #[clap(short = 'H', long, num_args(1..))]
    hosts: Vec<String>,

    #[clap(long, short, default_value_t = 22)]
    port: u16,

    #[clap(long, short)]
    username: String,

    #[clap(long, short = 'i')]
    private_key: PathBuf,
    #[clap(
        long,
        short = 'P',
        help = "Password for the private key, if it is encrypted"
    )]
    private_key_password: Option<String>,

    #[clap(long, short = 'o')]
    openssh_certificate: Option<PathBuf>,

    #[clap(
        num_args(1..), required = true,
        help = "Command to execute on the remote host(s). Multiple commands can be specified as a semicolon-separated list, e.g. 'ls -la \\; pwd'")]
    command: Vec<String>,

    #[clap(long, default_value_t = b'\t')]
    delimiter: u8,
}
