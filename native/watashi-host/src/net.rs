//! Network layer — wraps kami-knp for Watashi input transport.
//!
//! Channel assignment:
//! - `Unreliable` (0): Mouse movement (loss-tolerant, latency-critical)
//! - `ReliableOrdered` (1): Key input, mouse clicks (order matters)
//! - `ReliableUnordered` (2): Clipboard sync, screen geometry exchange
//! - `Voice` (3): Reserved for future audio passthrough

use anyhow::Result;
use kami_bridge::BridgeEvent;
use kami_knp::client::Client;
use kami_knp::packet::Channel;
use kami_knp::server::Server;
use log::info;
use std::net::SocketAddr;

/// Network event from KNP.
pub enum NetEvent {
    PeerConnected { addr: SocketAddr },
    PeerDisconnected { addr: SocketAddr },
    InputEvent { event: BridgeEvent, from: SocketAddr },
}

/// Determine the KNP channel for a bridge event.
fn channel_for(event: &BridgeEvent) -> Channel {
    match event {
        BridgeEvent::MouseMove { .. } | BridgeEvent::Scroll { .. } => Channel::Unreliable,
        _ => Channel::ReliableOrdered,
    }
}

/// Server-side network wrapper.
pub struct NetServer {
    server: Server,
}

impl NetServer {
    /// Poll for network events.
    pub fn poll(&mut self) -> Vec<NetEvent> {
        let mut events = Vec::new();
        for server_event in self.server.poll() {
            match server_event {
                kami_knp::server::ServerEvent::ClientConnected { client_id: _, addr } => {
                    events.push(NetEvent::PeerConnected { addr });
                }
                kami_knp::server::ServerEvent::ClientData {
                    client_id: _,
                    channel: _,
                    payload,
                } => {
                    if let Some(bridge_event) = BridgeEvent::from_bytes(&payload) {
                        events.push(NetEvent::InputEvent {
                            event: bridge_event,
                            from: "0.0.0.0:0".parse().unwrap(),
                        });
                    }
                }
            }
        }
        events
    }

    /// Broadcast a bridge event to all connected peers.
    pub fn broadcast_event(&mut self, event: &BridgeEvent) {
        let channel = channel_for(event);
        let bytes = event.to_bytes();
        self.server.broadcast(channel, bytes);
    }

    /// Send a bridge event to a specific peer.
    pub fn send_to(&mut self, addr: SocketAddr, event: &BridgeEvent) {
        let channel = channel_for(event);
        let bytes = event.to_bytes();
        self.server.send_to_addr(addr, channel, bytes);
    }
}

/// Start KNP server.
pub fn start_server(addr: SocketAddr) -> Result<NetServer> {
    let server = Server::bind(addr)?;
    info!("KNP server bound to {addr}");
    Ok(NetServer { server })
}

/// Client-side network wrapper.
pub struct NetClient {
    client: Client,
}

impl NetClient {
    /// Poll for network events.
    pub fn poll(&mut self) -> Vec<NetEvent> {
        let mut events = Vec::new();
        for client_event in self.client.poll() {
            match client_event {
                kami_knp::client::ClientEvent::Connected {
                    session_id: _,
                    client_id: _,
                } => {
                    events.push(NetEvent::PeerConnected {
                        addr: "0.0.0.0:0".parse().unwrap(),
                    });
                }
                kami_knp::client::ClientEvent::Data {
                    channel: _,
                    payload,
                } => {
                    if let Some(bridge_event) = BridgeEvent::from_bytes(&payload) {
                        events.push(NetEvent::InputEvent {
                            event: bridge_event,
                            from: "0.0.0.0:0".parse().unwrap(),
                        });
                    }
                }
            }
        }
        events
    }

    /// Send a bridge event to the server.
    pub fn send_event(&mut self, event: &BridgeEvent) {
        let channel = channel_for(event);
        let bytes = event.to_bytes();
        self.client.send(channel, bytes);
    }
}

/// Start KNP client.
pub fn start_client(server_addr: SocketAddr) -> Result<NetClient> {
    let client = Client::connect(server_addr)?;
    info!("KNP client connecting to {server_addr}");
    Ok(NetClient { client })
}
