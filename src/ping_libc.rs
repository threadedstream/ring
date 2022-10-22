use libc::{socket, SOCK_RAW, wait, printf};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use serde::Serialize;
use crate::common::Packet;
use std::mem;
use signal_hook::flag;
use std::ptr;
use std::mem::MaybeUninit;
use std::ffi::{CString};
use std::os::raw;
use std::time::Duration;

const ETH_P_IP: i32 = 0x0800;
const AF_PACKET: i32 = 0x0F;
const PING_ERRMSG_LEN: usize = 256;
const PING_TABLE_LEN: usize = 5381;


static mut CMSG: cmsg = cmsg{
    cm: libc::cmsghdr{
        cmsg_len: (mem::size_of::<libc::cmsghdr>() +  mem::size_of::<libc::in_pktinfo>()) as u32,
        cmsg_level: libc::SOL_LOCAL,
        cmsg_type: libc::IP_PKTINFO
    },
    ipi: libc::in_pktinfo{
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr {
            s_addr: 0,
        },
        ipi_addr: libc::in_addr {
            s_addr: 0,
        }
    }
};

#[repr(C)]
struct PingObj {
    pub timeout: libc::c_double,
    pub ttl: libc::c_int,
    pub addr_family: libc::c_int,
    pub qos: u8,
    pub data: *mut libc::c_char,
    pub fd4: libc::c_int,
    pub fd6: libc::c_int,
    pub src_addr: *mut libc::sockaddr,
    pub src_addr_len: libc::socklen_t,
    pub device: *mut libc::c_char,
    pub set_mark: libc::c_char,
    pub mark: libc::c_int,
    pub errmsg: [libc::c_char; PING_ERRMSG_LEN],
    pub head: *mut libc::c_void, // pinghost_t *
    pub table: [*mut libc::c_void; PING_TABLE_LEN], // pinghost_t * array
}

impl PingObj {
    pub fn new() -> Self {
        Self {
            timeout: 0.0,
            ttl: -1,
            addr_family: -1,
            qos: 255,
            data: ptr::null_mut(),
            fd4: -1,
            fd6: -1,
            src_addr: ptr::null_mut(),
            src_addr_len: 0,
            device: ptr::null_mut(),
            set_mark: -1,
            mark: -1,
            errmsg: [0; PING_ERRMSG_LEN],
            head: ptr::null_mut(),
            table: [ptr::null_mut(); PING_TABLE_LEN]
        }
    }
}

impl Drop for PingObj {
    fn drop(&mut self) {
        unsafe { libc::free(mem::transmute(self.src_addr)) };
    }
}

unsafe fn setup_socket(obj: &PingObj) -> libc::c_int {
    let socket_fd = socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
    if socket_fd == -1 {
        eprintln!("in setup_socket: {}", std::io::Error::last_os_error());
        return -1;
    }
    if socket_fd as usize >= libc::FD_SETSIZE{
        libc::close(socket_fd);
        eprintln!("in setup_socket: fd returned is >= FD_SETSIZE");
        return -1;
    }

    if obj.src_addr != ptr::null_mut() {
        let res = libc::bind(socket_fd, obj.src_addr, obj.src_addr_len);
        if res == -1 {
            libc::close(socket_fd);
            eprintln!("in setup_socket: {}", std::io::Error::last_os_error());
            return -1;
        }
    }


    return socket_fd;
}

unsafe fn ping_set_qos(fd: libc::c_int, qos: libc::c_int) -> libc::c_int{
    if fd != -1 {
        return libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_TOS, mem::transmute(&qos), mem::size_of_val(&qos) as libc::socklen_t);
    }
    println!("socket uniinitialized!!");
    return -1;
}

pub struct cmsg {
    pub cm: libc::cmsghdr,
    pub ipi: libc::in_pktinfo,
}

enum PingObject {}
enum PingObjIter {}

#[link(name = "oping")]
extern "C" {
    fn ping_construct() -> *mut PingObject;
    fn ping_destroy(obj: *mut PingObject);
    fn ping_send(obj: *mut PingObject) -> libc::c_int;
    fn ping_host_add(obj: *mut PingObject, host: *const libc::c_char) -> libc::c_int;
    fn ping_host_remove(obj: *mut PingObject, host: *const libc::c_char) -> libc::c_int;
    fn ping_iterator_get(obj: *mut PingObj) -> *mut PingObjIter;
    fn ping_iterator_next(obj: *mut PingObj) -> *mut PingObjIter;
}


pub unsafe fn shoot_packet() -> Result<(), io::Error>{
    let ping_obj = ping_construct();
    if ping_obj == ptr::null_mut() {
        panic!("failed to construct ping_obj");
        // unreachable
    }
    let ping_obj_rust: &PingObj = mem::transmute(ping_obj);
    println!("{}", CString::from_raw(ping_obj_rust.data).to_str().unwrap());
    let term = Arc::new(AtomicBool::new(false));
    flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))?;

    let libc_host = CString::new("google.com").expect("expected to have google.com in it");
    let success = ping_host_add(ping_obj, libc_host.as_ptr());
    if success == -1 {
        panic!("ping_host_add: {}", io::Error::last_os_error());
    }

    while !term.load(Ordering::Relaxed) {
        let success = ping_send(ping_obj);
        if success < 0 {
            break
        }
        println!("received response from ");
        std::thread::sleep(Duration::from_secs(1));
    }

    ping_destroy(ping_obj);
    Ok(())
}