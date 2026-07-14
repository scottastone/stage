// UPnP IGD port forwarding. Compiled in behind the default `upnp` feature;
// when the feature is off these become no-ops, mirroring the optional
// miniupnpc dependency in the Python version.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct UpnpInfo {
    pub external_ip: String,
    pub external_port: u16,
    pub internal_ip: String,
    pub internal_port: u16,
}

/// True if UPnP support was compiled in.
pub fn available() -> bool {
    cfg!(feature = "upnp")
}

#[cfg(feature = "upnp")]
pub fn try_forward(port: u16) -> Option<UpnpInfo> {
    use igd::PortMappingProtocol;
    use std::net::{Ipv4Addr, SocketAddrV4};

    let gateway = igd::search_gateway(Default::default()).ok()?;
    let external_ip = gateway.get_external_ip().ok()?;
    let internal: Ipv4Addr = crate::platform::local_ips()
        .first()
        .and_then(|s| s.parse().ok())?;
    let local_addr = SocketAddrV4::new(internal, port);
    // lease duration 0 == indefinite.
    gateway
        .add_port(PortMappingProtocol::TCP, port, local_addr, 0, "stage")
        .ok()?;
    Some(UpnpInfo {
        external_ip: external_ip.to_string(),
        external_port: port,
        internal_ip: internal.to_string(),
        internal_port: port,
    })
}

#[cfg(not(feature = "upnp"))]
pub fn try_forward(_port: u16) -> Option<UpnpInfo> {
    None
}

#[cfg(feature = "upnp")]
pub fn remove_forward(info: &UpnpInfo) {
    use igd::PortMappingProtocol;
    if let Ok(gateway) = igd::search_gateway(Default::default()) {
        let _ = gateway.remove_port(PortMappingProtocol::TCP, info.external_port);
    }
}

#[cfg(not(feature = "upnp"))]
pub fn remove_forward(_info: &UpnpInfo) {}
