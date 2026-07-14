#![allow(
    unsafe_code,
    reason = "localized reviewed Linux sockaddr and socket-option ABI adapters"
)]

use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd};

use nix::libc;
use nix::sys::socket::{
    ControlMessageOwned, LinkAddr, MsgFlags, SockaddrIn, SockaddrIn6, SockaddrStorage, recvmsg,
    sendto,
};
use rustix::net::{AddressFamily, Protocol, SocketFlags, SocketType, socket_with};

use crate::error::ScannerError;

const ETH_P_ALL: u16 = 0x0003;
const PACKET_BUFFER_BYTES: usize = 65_597;
const RAW_BUFFER_BYTES: usize = 65_575;
const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;
const TP_STATUS_CSUMNOTREADY: u32 = 1 << 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RawFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RawProtocol {
    Icmp,
    Tcp,
    Udp,
}

impl RawProtocol {
    pub(crate) const fn number(self, family: RawFamily) -> u8 {
        match (self, family) {
            (Self::Icmp, RawFamily::Ipv4) => 1,
            (Self::Icmp, RawFamily::Ipv6) => 58,
            (Self::Tcp, _) => 6,
            (Self::Udp, _) => 17,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PacketMessage {
    pub data: Vec<u8>,
    pub interface_index: u32,
    pub packet_type: u8,
    pub checksum_not_ready: bool,
}

#[derive(Debug)]
pub(crate) struct RawMessage {
    pub data: Vec<u8>,
    pub source: IpAddr,
    pub family: RawFamily,
    pub protocol: RawProtocol,
}

pub(crate) struct PortableSockets {
    packet: OwnedFd,
    ipv4_send: OwnedFd,
    ipv6_send: OwnedFd,
    raw_receivers: Vec<(RawFamily, RawProtocol, OwnedFd)>,
    packet_buffer: Vec<u8>,
    raw_buffer: Vec<u8>,
    packet_drops: u64,
}

impl PortableSockets {
    pub(crate) fn open() -> Result<Self, ScannerError> {
        let packet = open_socket(
            AddressFamily::PACKET,
            SocketType::RAW,
            ETH_P_ALL.to_be().into(),
        )?;
        set_int_option(
            &packet,
            libc::SOL_PACKET,
            libc::PACKET_AUXDATA,
            1,
            "enable PACKET_AUXDATA",
        )?;

        let ipv4_send = open_socket(
            AddressFamily::INET,
            SocketType::RAW,
            u32::try_from(libc::IPPROTO_RAW).unwrap_or_default(),
        )?;
        set_int_option(
            &ipv4_send,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            1,
            "enable IP_HDRINCL",
        )?;
        let ipv6_send = open_socket(
            AddressFamily::INET6,
            SocketType::RAW,
            u32::try_from(libc::IPPROTO_RAW).unwrap_or_default(),
        )?;
        set_int_option(
            &ipv6_send,
            libc::IPPROTO_IPV6,
            libc::IPV6_HDRINCL,
            1,
            "enable IPV6_HDRINCL",
        )?;

        let mut raw_receivers = Vec::with_capacity(6);
        for family in [RawFamily::Ipv4, RawFamily::Ipv6] {
            for protocol in [RawProtocol::Icmp, RawProtocol::Tcp, RawProtocol::Udp] {
                raw_receivers.push((
                    family,
                    protocol,
                    open_socket(
                        match family {
                            RawFamily::Ipv4 => AddressFamily::INET,
                            RawFamily::Ipv6 => AddressFamily::INET6,
                        },
                        SocketType::RAW,
                        u32::from(protocol.number(family)),
                    )?,
                ));
            }
        }

        Ok(Self {
            packet,
            ipv4_send,
            ipv6_send,
            raw_receivers,
            packet_buffer: vec![0; PACKET_BUFFER_BYTES],
            raw_buffer: vec![0; RAW_BUFFER_BYTES],
            packet_drops: 0,
        })
    }

    pub(crate) fn send_packet(
        &self,
        interface_index: u32,
        destination: [u8; 6],
        frame: &[u8],
    ) -> Result<(), ScannerError> {
        if interface_index == 0 || interface_index > i32::MAX.cast_unsigned() {
            return Err(ScannerError::invalid(
                "send packet",
                "invalid packet interface index",
            ));
        }
        let native = libc::sockaddr_ll {
            sll_family: u16::try_from(libc::AF_PACKET).unwrap_or_default(),
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: interface_index.cast_signed(),
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [
                destination[0],
                destination[1],
                destination[2],
                destination[3],
                destination[4],
                destination[5],
                0,
                0,
            ],
        };
        let length = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>())
            .map_err(|_| ScannerError::internal("send packet", "sockaddr_ll size overflow"))?;
        loop {
            // SAFETY: `native` is fully initialized and pointer-free; `frame` is
            // borrowed and remains valid for the exact duration of `sendto`.
            let result = unsafe {
                libc::sendto(
                    self.packet.as_raw_fd(),
                    frame.as_ptr().cast(),
                    frame.len(),
                    libc::MSG_NOSIGNAL,
                    (&raw const native).cast(),
                    length,
                )
            };
            if result >= 0 {
                if usize::try_from(result).ok() == Some(frame.len()) {
                    return Ok(());
                }
                return Err(ScannerError::internal(
                    "send packet",
                    "kernel reported a partial datagram send",
                ));
            }
            let error = nix::errno::Errno::last();
            if error != nix::errno::Errno::EINTR {
                return Err(ScannerError::system("send packet", error));
            }
        }
    }

    pub(crate) fn send_raw(&self, destination: IpAddr, packet: &[u8]) -> Result<(), ScannerError> {
        let sent = match destination {
            IpAddr::V4(address) => sendto(
                self.ipv4_send.as_raw_fd(),
                packet,
                &SockaddrIn::from(SocketAddrV4::new(address, 0)),
                MsgFlags::MSG_NOSIGNAL,
            ),
            IpAddr::V6(address) => sendto(
                self.ipv6_send.as_raw_fd(),
                packet,
                &SockaddrIn6::from(SocketAddrV6::new(address, 0, 0, 0)),
                MsgFlags::MSG_NOSIGNAL,
            ),
        }
        .map_err(|error| ScannerError::system("send raw IP packet", error))?;
        if sent != packet.len() {
            return Err(ScannerError::internal(
                "send raw IP packet",
                "kernel reported a partial datagram send",
            ));
        }
        Ok(())
    }

    pub(crate) fn receive_packet(&mut self) -> Result<Option<PacketMessage>, ScannerError> {
        let capacity = self.packet_buffer.len();
        let (actual, truncated, interface_index, packet_type, auxdata) = {
            let mut buffers = [IoSliceMut::new(&mut self.packet_buffer)];
            let mut control = vec![0_u8; 256];
            let message = match recvmsg::<LinkAddr>(
                self.packet.as_raw_fd(),
                &mut buffers,
                Some(&mut control),
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
            ) {
                Ok(value) => value,
                Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => return Ok(None),
                Err(error) => return Err(ScannerError::system("receive packet", error)),
            };
            let source = message.address.ok_or_else(|| {
                ScannerError::internal("receive packet", "kernel omitted packet address")
            })?;
            let native = source.as_ref();
            let interface_index = u32::try_from(native.sll_ifindex).map_err(|_| {
                ScannerError::internal("receive packet", "negative packet interface index")
            })?;
            let mut auxdata = None;
            for item in message.cmsgs().map_err(|error| {
                ScannerError::internal("receive packet", format!("invalid control data: {error}"))
            })? {
                if let ControlMessageOwned::Unknown(item) = item
                    && item.cmsg_header.cmsg_level == libc::SOL_PACKET
                    && item.cmsg_header.cmsg_type == libc::PACKET_AUXDATA
                {
                    auxdata = parse_auxdata(&item.data_bytes);
                }
            }
            (
                message.bytes,
                message
                    .flags
                    .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC),
                interface_index,
                native.sll_pkttype,
                auxdata,
            )
        };
        if truncated || actual > capacity {
            return Ok(None);
        }
        let checksum_not_ready =
            auxdata.is_some_and(|(status, _, _)| status & TP_STATUS_CSUMNOTREADY != 0);
        let mut data = self.packet_buffer[..actual].to_vec();
        if let Some((status, tci, tpid)) = auxdata
            && status & TP_STATUS_VLAN_VALID != 0
            && data.len() >= 14
            && !matches!(u16::from_be_bytes([data[12], data[13]]), 0x8100 | 0x88a8)
        {
            let protocol = if status & TP_STATUS_VLAN_TPID_VALID != 0 && tpid != 0 {
                tpid
            } else {
                0x8100
            };
            data.splice(
                12..12,
                protocol.to_be_bytes().into_iter().chain(tci.to_be_bytes()),
            );
        }
        Ok(Some(PacketMessage {
            data,
            interface_index,
            packet_type,
            checksum_not_ready,
        }))
    }

    pub(crate) fn receive_raw(&mut self) -> Result<Option<RawMessage>, ScannerError> {
        for (family, protocol, descriptor) in &self.raw_receivers {
            let capacity = self.raw_buffer.len();
            let (bytes, truncated, source) = {
                let mut buffers = [IoSliceMut::new(&mut self.raw_buffer)];
                let message = match recvmsg::<SockaddrStorage>(
                    descriptor.as_raw_fd(),
                    &mut buffers,
                    None,
                    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
                ) {
                    Ok(value) => value,
                    Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => continue,
                    Err(error) => return Err(ScannerError::system("receive raw packet", error)),
                };
                let source = message.address.and_then(|address| match family {
                    RawFamily::Ipv4 => address.as_sockaddr_in().map(|value| IpAddr::V4(value.ip())),
                    RawFamily::Ipv6 => address
                        .as_sockaddr_in6()
                        .map(|value| IpAddr::V6(value.ip())),
                });
                (
                    message.bytes,
                    message.flags.contains(MsgFlags::MSG_TRUNC),
                    source,
                )
            };
            if truncated || bytes > capacity {
                continue;
            }
            let Some(source) = source else {
                continue;
            };
            return Ok(Some(RawMessage {
                data: self.raw_buffer[..bytes].to_vec(),
                source,
                family: *family,
                protocol: *protocol,
            }));
        }
        Ok(None)
    }

    pub(crate) fn take_packet_drops(&mut self) -> Result<u64, ScannerError> {
        let mut stats = libc::tpacket_stats {
            tp_packets: 0,
            tp_drops: 0,
        };
        let mut length = libc::socklen_t::try_from(std::mem::size_of_val(&stats))
            .map_err(|_| ScannerError::internal("read packet statistics", "size overflow"))?;
        // SAFETY: `stats` is initialized writable storage and `length` exactly
        // describes it. The kernel may write no more than the supplied length.
        let result = unsafe {
            libc::getsockopt(
                self.packet.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                (&raw mut stats).cast(),
                &raw mut length,
            )
        };
        if result == -1 {
            return Err(ScannerError::system(
                "read packet statistics",
                nix::errno::Errno::last(),
            ));
        }
        self.packet_drops = self.packet_drops.saturating_add(u64::from(stats.tp_drops));
        Ok(self.packet_drops)
    }
}

fn open_socket(
    family: AddressFamily,
    socket_type: SocketType,
    protocol: u32,
) -> Result<OwnedFd, ScannerError> {
    let protocol = NonZeroU32::new(protocol)
        .map(Protocol::from_raw)
        .ok_or_else(|| ScannerError::internal("open scan socket", "zero protocol"))?;
    socket_with(
        family,
        socket_type,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        Some(protocol),
    )
    .map_err(|error| ScannerError::system_rustix("open scan socket", error))
}

fn set_int_option(
    descriptor: &OwnedFd,
    level: i32,
    name: i32,
    value: libc::c_int,
    operation: &'static str,
) -> Result<(), ScannerError> {
    let length = libc::socklen_t::try_from(std::mem::size_of_val(&value))
        .map_err(|_| ScannerError::internal(operation, "option size overflow"))?;
    // SAFETY: `value` is initialized and borrowed for its exact ABI size.
    let result = unsafe {
        libc::setsockopt(
            descriptor.as_raw_fd(),
            level,
            name,
            (&raw const value).cast(),
            length,
        )
    };
    if result == -1 {
        Err(ScannerError::system(operation, nix::errno::Errno::last()))
    } else {
        Ok(())
    }
}

fn parse_auxdata(bytes: &[u8]) -> Option<(u32, u16, u16)> {
    if bytes.len() < 20 {
        return None;
    }
    Some((
        u32::from_ne_bytes(bytes[0..4].try_into().ok()?),
        u16::from_ne_bytes(bytes[16..18].try_into().ok()?),
        u16::from_ne_bytes(bytes[18..20].try_into().ok()?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auxdata_parser_rejects_short_control_and_reads_native_order() {
        assert_eq!(parse_auxdata(&[0; 19]), None);
        let mut bytes = [0_u8; 20];
        bytes[0..4].copy_from_slice(&TP_STATUS_VLAN_VALID.to_ne_bytes());
        bytes[16..18].copy_from_slice(&7_u16.to_ne_bytes());
        bytes[18..20].copy_from_slice(&0x8100_u16.to_ne_bytes());
        assert_eq!(
            parse_auxdata(&bytes),
            Some((TP_STATUS_VLAN_VALID, 7, 0x8100))
        );
    }
}
