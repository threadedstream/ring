use libc::{socket, SOCK_RAW, wait, printf};
use std::io;
use serde::Serialize;
use std::mem;
use std::ptr;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::ffi::{CStr};

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

struct PingObj {
  pub timeout: libc::c_double,
  pub ttl: libc::c_int,
  pub addr_family: libc::c_int,
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

#[derive(Serialize, Debug)]
struct Packet {
  pub icmp_type: u8,
  pub icmp_code: u8,
  pub icmp_chksum: u16,
  pub icmp_identifier: u16,
  pub icmp_seq_number: u16,
  pub icmp_timestamp: [u8; 8],
}

pub struct cmsg {
  pub cm: libc::cmsghdr,
  pub ipi: libc::in_pktinfo,
}

enum PingObject {}

#[link(name = "oping")]
extern "C" {
  fn ping_construct() -> *mut PingObject;
  fn ping_destroy(obj: *mut PingObject);
}

pub fn main() {
  let raw = unsafe {  ping_construct() };
  if raw == ptr::null_mut() {
    eprintln!("in main: failed to initilize ping object");
    return
  }
  let ping_object: *mut PingObj = unsafe { mem::transmute(raw) };
  unsafe {
    println!("{}", (*ping_object).timeout);
    println!("{}", (*ping_object).ttl);
    println!("{}", (*ping_object).addr_family);
    println!("{:?}", CStr::from_ptr((*ping_object).data ));
    println!("{}", (*ping_object).fd4);
    println!("{}", (*ping_object).fd6);
  }

  unsafe { ping_destroy(raw) }

  let sockaddr: *mut libc::sockaddr = unsafe { mem::transmute(libc::malloc(mem::size_of::<libc::sockaddr>())) };
  if sockaddr == ptr::null_mut() {
    eprintln!("in main: failed to allocate memory for sockaddr struct");
    return
  }
  unsafe {
    (*sockaddr).sa_family = libc::AF_INET as libc::sa_family_t;
    (*sockaddr).sa_len = mem::size_of::<libc::sockaddr>() as u8;
  }

  let ping_obj = PingObj::new();
  let socket_fd = unsafe { setup_socket(&ping_obj) };
  if socket_fd == -1  {
    eprintln!("in main: failed to setup socket");
    return
  }

  let packet = Packet{
    icmp_type: 0x08,
    icmp_code: 0,
    icmp_chksum: 0x5B72,
    icmp_identifier: 0x8D2A,
    icmp_seq_number: 0x0,
    icmp_timestamp: [0x63, 0x48, 0x4d, 0x22, 0x00, 0x07, 0x73, 0xEE],
  };

  let blob: Vec<u8> = bincode::serialize(&packet).unwrap();
  unsafe {
    let buf = mem::transmute::<*const u8, *const libc::c_void>(blob.as_ptr());
    // let mut addr = &mut libc::sockaddr_in {
    //   sin_family: libc::AF_INET as u8,
    //   sin_addr: libc::in_addr {
    //     s_addr: 0x40e9a18a,
    //   },
    //   sin_port: 0,
    //   sin_zero: [0; 8],
    //   sin_len: 0,
    // };

    // let mut addr: *mut libc::sockaddr_storage;
    // addr = std::mem::transmute(libc::malloc(mem::size_of::<libc::sockaddr_storage>()));
    // if addr == std::ptr::null_mut() {
    //   panic!("failed to initialize libc::sockaddr_storage");
    // }
    // (*addr).ss_family = libc::AF_INET as libc::sa_family_t;
    // (*addr).ss_len = 0;

    // let vec = &mut libc::iovec {
    //   iov_base: buf as *mut libc::c_void,
    //   iov_len: 0,
    // };
    let i = match libc::sendto(socket_fd, buf, blob.len(),0, ping_obj.src_addr, ping_obj.src_addr_len) {
      -1 => {
        panic!("{}", std::io::Error::last_os_error())
      } ,
      n => n,
    };
  }
}