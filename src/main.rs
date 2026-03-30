use futures::StreamExt;
use openvpn_mgmt_codec::{
    ClientDeny, ClientEvent, Crv1Challenge, ManagementEvent, Notification, OvpnCodec,
    split::{ManagementSink, management_split},
};
use tokio::net::UnixStream;
use tokio_util::codec::Framed;
use tracing::{debug, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "openvpn_mfa=debug,openvpn_mgmt_codec=info".parse().unwrap()),
        )
        .init();

    let stream = UnixStream::connect("/home/felix/prog/openvpn-lab-felix/run/mgmt.socket").await?;
    let framed = Framed::new(stream, OvpnCodec::new());
    let (mut sink, mut events) = management_split(framed);

    while let Some(event) = events.next().await {
        match event? {
            ManagementEvent::Notification(notification) => {
                info!(?notification, "notification");

                // Auto-approve all client connections (demo only!).
                if let Notification::Client {
                    event: ClientEvent::Connect,
                    cid,
                    kid: Some(kid),
                    env,
                    ..
                } = &notification
                {
                    env.values_mut().for_each(|v| *v = v.to_lowercase());

                    if let Some(password) = env.get("password")
                        && let Some(username) = env.get("username")
                    {
                        info!(%cid, %password, "evaluating client credentials");

                        let credentials_match = (password.as_str() == "pass123"
                            && username.as_str() == "user")
                            || (password.as_str() == "123pass"
                                && username.as_str() == "client-with-certs");

                        if credentials_match {
                            if let Some(common_name) = env.get("common_name")
                                && common_name == username
                            {
                                sink.client_auth_nt(*cid, *kid).await?;
                                continue;
                            }

                            let challenge = Crv1Challenge::builder()
                                .flags("R,E")
                                .state_id("O0w1u7Fh4LrGBS7uh0SWtzwabUiGiW6l")
                                .username(username.as_str())
                                .challenge_text("Enter Your OTP Code")
                                .build();

                            // TODO Build proper state_id and username https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt#L1296
                            sink.client_deny(
                                ClientDeny::builder()
                                    .cid(*cid)
                                    .kid(*kid)
                                    .reason("pending MFA")
                                    .client_reason(challenge.to_string())
                                    .build(),
                            )
                            .await?;
                        } else {
                            sink.client_deny(
                                ClientDeny::builder()
                                    .cid(*cid)
                                    .kid(*kid)
                                    .reason("Invalid user/password")
                                    .build(),
                            )
                            .await?;
                        }
                    }
                }
            }
            ManagementEvent::Response(response) => {
                debug!(?response, "response");
            }
        }
    }

    Ok(())
}
