use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::{
    OvpnCodec, OvpnCommand,
    stream::{ManagementEvent, classify},
};
use std::collections::BTreeMap;
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio_util::codec::Framed;
use tracing::{debug, error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let stream = UnixStream::connect("/home/felix/prog/openvpn-lab-felix/run/mgmt.socket").await?;
    let mut framed = Framed::new(stream, OvpnCodec::new());
    let (mut sink, raw_stream) = framed.split();
    let mut mgmt = raw_stream.map(classify);

    while let Some(event) = mgmt.next().await {
        match event? {
            ManagementEvent::Notification(notification) => {
                info!(?notification, "notification");

                // Auto-approve all client connections (demo only!).
                if let openvpn_mgmt_codec::Notification::Client {
                    event: openvpn_mgmt_codec::ClientEvent::Connect,
                    cid,
                    kid: Some(kid),
                    env,
                    ..
                } = &notification
                {
                    let env =
                        BTreeMap::from_iter(env.into_iter().map(|(k, v)| (k.to_lowercase(), v)));
                    if let Some(password) = env.get("password")
                        && let Some(username) = env.get("username")
                    {
                        info!(%cid, %password, "auto-approving client");

                        if (password.as_str() == "pass123" && username.as_str() == "user")
                            || password.as_str() == "123pass"
                                && username.as_str() == "client-with-certs"
                        {
                            if let Some(commonName) = env.get("common_name")
                                && commonName == username
                            {
                                sink.send(OvpnCommand::ClientAuthNt {
                                    cid: *cid,
                                    kid: *kid,
                                })
                                .await?;
                                continue;
                            }
                            sink.send(OvpnCommand::ClientDeny {
                                cid: *cid,
                                kid: *kid,
                                reason: String::from("Invalid user/password"),
                                // TODO Build proper state_id and username https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt#L1296
                                client_reason: Some(String::from("CRV1:R,E:T20wMXU3Rmg0THJHQlM3dWgwU1dtendhYlVpR2lXNmw=:dXNlcg==:Enter Your OTP Code")),
                            })
                                .await?;
                        } else {
                            sink.send(OvpnCommand::ClientDeny {
                                cid: *cid,
                                kid: *kid,
                                reason: String::from("Invalid user/password"),
                                client_reason: None,
                            })
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
