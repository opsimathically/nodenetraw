use std::{io, os::fd::RawFd, time::Duration};

const UNSUPPORTED_SOCKET_OPTIONS: [i32; 2] = [libc::ENOPROTOOPT, libc::EINVAL];

#[allow(
    unsafe_code,
    reason = "Linux exposes SO_RCVTIMEO and SO_NETNS_COOKIE only through pointer-based socket APIs"
)]
pub(crate) fn set_receive_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
    let seconds = libc::time_t::try_from(timeout.as_secs())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "timeout seconds overflow"))?;
    let microseconds = libc::suseconds_t::from(timeout.subsec_micros());
    let value = libc::timeval {
        tv_sec: seconds,
        tv_usec: microseconds,
    };
    let length = libc::socklen_t::try_from(size_of::<libc::timeval>()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "socket option length overflow")
    })?;
    // SAFETY: `value` is initialized, its pointer remains valid for `length`, and `fd`
    // is borrowed from a live netlink socket for the duration of this call.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::from_ref(&value).cast(),
            length,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "Linux exposes SO_NETNS_COOKIE only through pointer-based getsockopt"
)]
pub(crate) fn netns_cookie(fd: RawFd) -> io::Result<Option<u64>> {
    let mut value = 0_u64;
    let mut length = libc::socklen_t::try_from(size_of::<u64>()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "socket option length overflow")
    })?;
    // SAFETY: both output pointers refer to initialized writable storage of the
    // advertised sizes, and `fd` is borrowed from a live netlink socket.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NETNS_COOKIE,
            std::ptr::from_mut(&mut value).cast(),
            std::ptr::from_mut(&mut length),
        )
    };
    if result == -1 {
        let error = io::Error::last_os_error();
        if error
            .raw_os_error()
            .is_some_and(|code| UNSUPPORTED_SOCKET_OPTIONS.contains(&code))
        {
            return Ok(None);
        }
        return Err(error);
    }
    if usize::try_from(length).ok() != Some(size_of::<u64>()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SO_NETNS_COOKIE returned an unexpected value length",
        ));
    }
    Ok(Some(value))
}
