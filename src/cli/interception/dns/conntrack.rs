use anyhow::Result;

pub(super) fn clear_zone(zone: u16) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::clear_zone(zone)
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("DNS conntrack zone cleanup is unsupported on this platform: {zone}")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result, bail, ensure};

    const HEADER: usize = 16;
    const CT_NEW: u16 = 0x100;
    const CT_GET: u16 = 0x101;
    const CT_DELETE: u16 = 0x102;
    const ERROR: u16 = 2;
    const DONE: u16 = 3;
    const REQUEST_ACK: u16 = 1 | 4;
    const REQUEST_DUMP: u16 = 1 | 0x100 | 0x200;
    const DUMP_INTERRUPTED: u16 = 0x10;
    const TUPLE_ORIG: u16 = 1;
    const ID: u16 = 12;
    const ZONE: u16 = 18;

    pub(super) fn clear_zone(zone: u16) -> Result<()> {
        ensure!(zone != 0, "refusing to clear the default conntrack zone");
        let socket = Socket::open()?;
        socket.send(&request(CT_GET, REQUEST_DUMP, 1, &[]))?;
        let mut entries = Vec::new();
        loop {
            let buffer = socket.receive()?;
            for frame in frames(&buffer, 1)? {
                ensure!(
                    frame.flags & DUMP_INTERRUPTED == 0,
                    "conntrack dump was interrupted"
                );
                match frame.kind {
                    ERROR => check_ack(frame.payload, false)?,
                    DONE => {
                        if !frame.payload.is_empty() {
                            check_ack(frame.payload, false)?;
                        }
                        return delete_entries(&socket, entries);
                    }
                    CT_NEW => {
                        if let Some(attributes) = select_entry(frame.payload, zone)? {
                            entries.push(attributes);
                        }
                    }
                    _ => bail!("unexpected conntrack dump message {}", frame.kind),
                }
            }
        }
    }

    fn delete_entries(socket: &Socket, entries: Vec<Vec<u8>>) -> Result<()> {
        for (index, attributes) in entries.iter().enumerate() {
            let sequence = u32::try_from(index)?
                .checked_add(2)
                .context("conntrack sequence overflow")?;
            socket.send(&request(CT_DELETE, REQUEST_ACK, sequence, attributes))?;
            let response = socket.receive()?;
            let messages = frames(&response, sequence)?;
            ensure!(
                messages.len() == 1 && messages[0].kind == ERROR,
                "missing conntrack delete acknowledgement"
            );
            check_ack(messages[0].payload, true)?;
        }
        Ok(())
    }

    // Never issue a zone-only CT_DELETE: older kernels interpret it as a global flush.
    fn select_entry(payload: &[u8], zone: u16) -> Result<Option<Vec<u8>>> {
        ensure!(payload.len() >= 4, "truncated conntrack nfgenmsg");
        if payload[0] != libc::AF_INET as u8 {
            return Ok(None);
        }
        let mut selected = [None, None, None];
        for attribute in attributes(&payload[4..])? {
            let slot = match attribute.kind {
                TUPLE_ORIG => 0,
                ZONE => 1,
                ID => 2,
                _ => continue,
            };
            ensure!(
                selected[slot].replace(attribute).is_none(),
                "duplicate conntrack identifying attribute"
            );
        }
        let Some(zone_attribute) = selected[1] else {
            return Ok(None);
        };
        ensure!(
            zone_attribute.payload.len() == 2,
            "invalid conntrack zone attribute"
        );
        if u16::from_be_bytes(zone_attribute.payload.try_into()?) != zone {
            return Ok(None);
        }
        let tuple = selected[0].context("conntrack entry has no original tuple")?;
        ensure!(
            !tuple.payload.is_empty(),
            "conntrack original tuple is empty"
        );
        attributes(tuple.payload)?;
        let id = selected[2].context("conntrack entry has no ID")?;
        ensure!(id.payload.len() == 4, "invalid conntrack ID attribute");
        Ok(Some([tuple.raw, zone_attribute.raw, id.raw].concat()))
    }

    fn request(kind: u16, flags: u16, sequence: u32, attributes: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(HEADER + 4 + attributes.len());
        output.extend_from_slice(&((HEADER + 4 + attributes.len()) as u32).to_ne_bytes());
        output.extend_from_slice(&kind.to_ne_bytes());
        output.extend_from_slice(&flags.to_ne_bytes());
        output.extend_from_slice(&sequence.to_ne_bytes());
        output.extend_from_slice(&0_u32.to_ne_bytes());
        output.extend_from_slice(&[libc::AF_INET as u8, 0, 0, 0]);
        output.extend_from_slice(attributes);
        output
    }

    fn check_ack(payload: &[u8], allow_missing: bool) -> Result<()> {
        ensure!(payload.len() >= 4, "truncated conntrack acknowledgement");
        let error = i32::from_ne_bytes(payload[..4].try_into()?);
        ensure!(error <= 0, "invalid conntrack acknowledgement status");
        if error == 0 || (allow_missing && error == -libc::ENOENT) {
            return Ok(());
        }
        Err(io::Error::from_raw_os_error(
            error.checked_neg().context("invalid conntrack error")?,
        ))
        .context("conntrack netlink request failed")
    }

    struct Frame<'a> {
        kind: u16,
        flags: u16,
        payload: &'a [u8],
    }

    fn frames(mut input: &[u8], sequence: u32) -> Result<Vec<Frame<'_>>> {
        let mut output = Vec::new();
        while !input.is_empty() {
            ensure!(input.len() >= HEADER, "truncated conntrack netlink header");
            let length = u32::from_ne_bytes(input[..4].try_into()?) as usize;
            ensure!(
                length >= HEADER && aligned(length)? <= input.len(),
                "invalid conntrack netlink message length"
            );
            ensure!(
                u32::from_ne_bytes(input[8..12].try_into()?) == sequence,
                "unexpected conntrack netlink sequence"
            );
            output.push(Frame {
                kind: u16::from_ne_bytes(input[4..6].try_into()?),
                flags: u16::from_ne_bytes(input[6..8].try_into()?),
                payload: &input[HEADER..length],
            });
            input = &input[aligned(length)?..];
        }
        Ok(output)
    }

    #[derive(Clone, Copy)]
    struct Attribute<'a> {
        kind: u16,
        raw: &'a [u8],
        payload: &'a [u8],
    }

    fn attributes(mut input: &[u8]) -> Result<Vec<Attribute<'_>>> {
        let mut output = Vec::new();
        while !input.is_empty() {
            ensure!(input.len() >= 4, "truncated conntrack attribute header");
            let length = u16::from_ne_bytes(input[..2].try_into()?) as usize;
            ensure!(
                length >= 4 && aligned(length)? <= input.len(),
                "invalid conntrack attribute length"
            );
            output.push(Attribute {
                kind: u16::from_ne_bytes(input[2..4].try_into()?) & 0x3fff,
                raw: &input[..aligned(length)?],
                payload: &input[4..length],
            });
            input = &input[aligned(length)?..];
        }
        Ok(output)
    }

    fn aligned(length: usize) -> Result<usize> {
        Ok(length
            .checked_add(3)
            .context("conntrack message length overflow")?
            & !3)
    }

    struct Socket {
        fd: OwnedFd,
        started: Instant,
    }

    impl Socket {
        fn open() -> Result<Self> {
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    libc::NETLINK_NETFILTER,
                )
            };
            ensure!(
                fd >= 0,
                "failed to open conntrack netlink socket: {}",
                io::Error::last_os_error()
            );
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let timeout = libc::timeval {
                tv_sec: 5,
                tv_usec: 0,
            };
            for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
                let status = unsafe {
                    libc::setsockopt(
                        fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        option,
                        (&timeout as *const libc::timeval).cast(),
                        mem::size_of_val(&timeout) as libc::socklen_t,
                    )
                };
                ensure!(
                    status == 0,
                    "failed to set conntrack socket timeout: {}",
                    io::Error::last_os_error()
                );
            }
            let mut local: libc::sockaddr_nl = unsafe { mem::zeroed() };
            local.nl_family = libc::AF_NETLINK as u16;
            let status = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&local as *const libc::sockaddr_nl).cast(),
                    mem::size_of_val(&local) as libc::socklen_t,
                )
            };
            ensure!(
                status == 0,
                "failed to bind conntrack netlink socket: {}",
                io::Error::last_os_error()
            );
            Ok(Self {
                fd,
                started: Instant::now(),
            })
        }

        fn send(&self, message: &[u8]) -> Result<()> {
            ensure!(
                self.started.elapsed() < Duration::from_secs(15),
                "conntrack cleanup deadline exceeded"
            );
            let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
            kernel.nl_family = libc::AF_NETLINK as u16;
            let written = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    message.as_ptr().cast(),
                    message.len(),
                    0,
                    (&kernel as *const libc::sockaddr_nl).cast(),
                    mem::size_of_val(&kernel) as libc::socklen_t,
                )
            };
            ensure!(
                written >= 0,
                "failed to send conntrack netlink request: {}",
                io::Error::last_os_error()
            );
            ensure!(
                written as usize == message.len(),
                "incomplete conntrack netlink request"
            );
            Ok(())
        }

        fn receive(&self) -> Result<Vec<u8>> {
            ensure!(
                self.started.elapsed() < Duration::from_secs(15),
                "conntrack cleanup deadline exceeded"
            );
            let mut output = vec![0_u8; 65536];
            let mut peer: libc::sockaddr_nl = unsafe { mem::zeroed() };
            let mut peer_length = mem::size_of_val(&peer) as libc::socklen_t;
            let length = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    output.as_mut_ptr().cast(),
                    output.len(),
                    libc::MSG_TRUNC,
                    (&mut peer as *mut libc::sockaddr_nl).cast(),
                    &mut peer_length,
                )
            };
            ensure!(
                length >= 0,
                "failed to receive conntrack netlink response: {}",
                io::Error::last_os_error()
            );
            ensure!(
                length > 0 && length as usize <= output.len(),
                "truncated conntrack netlink datagram"
            );
            ensure!(
                peer_length as usize == mem::size_of_val(&peer) && peer.nl_pid == 0,
                "conntrack response did not originate from the kernel"
            );
            output.truncate(length as usize);
            Ok(output)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
            let mut bytes = ((4 + payload.len()) as u16).to_ne_bytes().to_vec();
            bytes.extend_from_slice(&kind.to_ne_bytes());
            bytes.extend_from_slice(payload);
            bytes.resize((bytes.len() + 3) & !3, 0);
            bytes
        }

        fn entry(zone: Option<u16>) -> Vec<u8> {
            let mut payload = vec![libc::AF_INET as u8, 0, 0, 0];
            payload.extend(attribute(
                TUPLE_ORIG | 0x8000,
                &attribute(1, &[127, 0, 0, 1]),
            ));
            payload.extend(attribute(ID, &123_u32.to_be_bytes()));
            if let Some(zone) = zone {
                payload.extend(attribute(ZONE, &zone.to_be_bytes()));
            }
            payload
        }

        #[test]
        fn only_selects_the_exact_explicit_zone() {
            for zone in [None, Some(0), Some(4054)] {
                assert!(select_entry(&entry(zone), 4053).unwrap().is_none());
            }
            assert!(clear_zone(0).is_err());
        }

        #[test]
        fn delete_always_contains_original_tuple_zone_and_id() {
            let selected = select_entry(&entry(Some(4053)), 4053).unwrap().unwrap();
            let bytes = request(CT_DELETE, REQUEST_ACK, 42, &selected);
            let frame = frames(&bytes, 42).unwrap().remove(0);
            assert_eq!(frame.kind, CT_DELETE);
            let values = attributes(&frame.payload[4..]).unwrap();
            assert_eq!(
                values
                    .iter()
                    .map(|attribute| attribute.kind)
                    .collect::<Vec<_>>(),
                [TUPLE_ORIG, ZONE, ID]
            );
            assert_eq!(values[1].payload, 4053_u16.to_be_bytes());
        }

        #[test]
        fn rejects_malformed_frames_and_attributes() {
            assert!(frames(&[0; 15], 1).is_err());
            assert!(frames(&request(CT_GET, REQUEST_DUMP, 2, &[]), 1).is_err());
            assert!(attributes(&[3, 0, 1, 0]).is_err());
            assert!(select_entry(&[2, 0, 0], 4053).is_err());
            let mut payload = entry(Some(4053));
            payload.extend(attribute(ZONE, &4053_u16.to_be_bytes()));
            assert!(select_entry(&payload, 4053).is_err());
            assert!(check_ack(&[0; 3], false).is_err());
            let zone = attribute(ZONE, &4053_u16.to_be_bytes());
            let id = attribute(ID, &123_u32.to_be_bytes());
            let prefix = [libc::AF_INET as u8, 0, 0, 0];
            assert!(select_entry(&[prefix.as_slice(), &zone, &id].concat(), 4053).is_err());
            let tuple = attribute(TUPLE_ORIG, &[]);
            assert!(select_entry(&[prefix.as_slice(), &tuple, &zone, &id].concat(), 4053).is_err());
        }

        #[test]
        fn accepts_missing_entries_only_when_deleting() {
            assert!(check_ack(&0_i32.to_ne_bytes(), false).is_ok());
            assert!(check_ack(&(-libc::ENOENT).to_ne_bytes(), true).is_ok());
            assert!(check_ack(&(-libc::ENOENT).to_ne_bytes(), false).is_err());
            assert!(check_ack(&(-libc::EPERM).to_ne_bytes(), true).is_err());
        }
    }
}
