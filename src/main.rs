use crate::ping_libc::shoot_packet;

pub fn main() -> Result<(), std::io::Error>{
  unsafe {
    shoot_packet()
  }
}

mod common;
mod ping_libc;
mod ping_libpnet;