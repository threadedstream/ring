use serde::Serialize;


#[derive(Serialize, Debug)]
pub struct Packet {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_chksum: u16,
    pub icmp_identifier: u16,
    pub icmp_seq_number: u16,
    pub icmp_timestamp: [u8; 8],
}