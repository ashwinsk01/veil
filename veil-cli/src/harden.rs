//! Process and memory hardening. This is the only unsafe code in the project.

use std::io;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Disables core dumps and debugger attachment for the rest of the process's life.
pub fn process() -> io::Result<()> {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit only reads the rlimit struct it is given.
    check(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) })?;
    // SAFETY: PT_DENY_ATTACH ignores its pid, address and data arguments.
    #[cfg(target_os = "macos")]
    check(unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) })?;
    // SAFETY: PR_SET_DUMPABLE takes plain integer arguments.
    #[cfg(target_os = "linux")]
    check(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })?;
    Ok(())
}

fn check(ret: libc::c_int) -> io::Result<()> {
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn addr<T: ?Sized>(value: &T) -> *const libc::c_void {
    (value as *const T).cast()
}

/// A heap value pinned in RAM, so it is never written to swap, and zeroed before it is freed.
pub struct Locked<T: Zeroize + ?Sized> {
    value: Box<T>,
}

impl<T: Zeroize + ?Sized> Locked<T> {
    pub fn new(value: Box<T>) -> io::Result<Self> {
        // SAFETY: the range is exactly the boxed value, which stays allocated while `value` lives.
        check(unsafe { libc::mlock(addr(&*value), size_of_val(&*value)) })?;
        Ok(Self { value })
    }
}

impl<T: Zeroize + ?Sized> Drop for Locked<T> {
    fn drop(&mut self) {
        self.value.zeroize();
        // SAFETY: unlocks the range locked in `new`; the allocation is still live.
        unsafe { libc::munlock(addr(&*self.value), size_of_val(&*self.value)) };
    }
}

impl<T: Zeroize + ?Sized> Deref for Locked<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: Zeroize + ?Sized> DerefMut for Locked<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

/// Reads a secret from stdin. From a terminal, echo is off and one line is read; from a pipe,
/// everything up to the end is read.
pub fn read_secret() -> io::Result<zeroize::Zeroizing<String>> {
    use std::io::{BufRead, Read};
    let mut text = zeroize::Zeroizing::new(String::with_capacity(1024));
    // SAFETY: termios is plain data; tcgetattr only writes the struct it is given.
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let terminal = unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut saved) } == 0;
    if !terminal {
        io::stdin().read_to_string(&mut text)?;
        return Ok(text);
    }
    let mut quiet = saved;
    quiet.c_lflag &= !libc::ECHO;
    // SAFETY: tcsetattr only reads the struct it is given.
    check(unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &quiet) })?;
    let result = io::stdin().lock().read_line(&mut text);
    // SAFETY: as above, restoring the settings saved before.
    unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &saved) };
    eprintln!();
    result.map(|_| text)
}
