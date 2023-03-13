use std::net::{Ipv4Addr, Ipv6Addr};

pub struct Question {
    pub url: String,
    pub dns_type: DnsType,
    pub dns_class: DnsClass,
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
#[derive(PartialEq, Debug)]
pub enum DnsClass {
    IN = 0x0001,
    CH = 0x0003,
    HS = 0x0004,
    UNKNOWN = -1,
}

impl DnsClass {
    pub fn from_u16(value: u16) -> DnsClass {
        match value {
            0x0001 => DnsClass::IN,
            0x0003 => DnsClass::CH,
            0x0004 => DnsClass::HS,
            _ => DnsClass::UNKNOWN,
        }
    }
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
#[derive(PartialEq, Debug)]
pub enum DnsType {
    A = 0x0001,
    NS = 0x0002,
    CNAME = 0x0005,
    SOA = 0x0006,
    PTR = 0x000c,
    MX = 0x000f,
    TXT = 0x0010,
    AAAA = 0x001c,
    SRV = 0x0021,
    OPT = 0x0029,
    AXFR = 0xfc00,
    MAILB = 0xfe00,
    MAILA = 0xfe01,
    ANY = 0xff00,
    UNKNOWN = -1,
}

impl DnsType {
    pub fn from_u16(value: u16) -> DnsType {
        match value {
            0x0001 => DnsType::A,
            0x0002 => DnsType::NS,
            0x0005 => DnsType::CNAME,
            0x0006 => DnsType::SOA,
            0x000c => DnsType::PTR,
            0x000f => DnsType::MX,
            0x0010 => DnsType::TXT,
            0x001c => DnsType::AAAA,
            0x0021 => DnsType::SRV,
            0x0029 => DnsType::OPT,
            0xfc00 => DnsType::AXFR,
            0xfe00 => DnsType::MAILB,
            0xfe01 => DnsType::MAILA,
            0xff00 => DnsType::ANY,
            _ => DnsType::UNKNOWN,
        }
    }
}

#[derive(Debug)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: DnsType,
    pub record_class: DnsClass,
    pub ttl: u32,
    pub data_length: u16,
    pub data: Vec<u8>,
}

impl DnsRecord {
    pub fn extract_ip_address(&self) -> Option<Ipv4Addr> {
        if self.record_type == DnsType::A && self.record_class == DnsClass::IN && self.data_length == 4 {
            Some(Ipv4Addr::new(
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ))
        } else {
            None
        }
    }

    pub fn parse_data(&self) -> String {
        match self.record_type {
            DnsType::A => {
                if self.data_length == 4 {
                    let ip = Ipv4Addr::new(self.data[0], self.data[1], self.data[2], self.data[3]);
                    format!("{}", ip)
                } else {
                    format!("Invalid data length: {}", self.data_length)
                }
            }
            DnsType::AAAA => {
                if self.data_length == 16 {
                    let ip = Ipv6Addr::new(
                        u16::from_be_bytes([self.data[0], self.data[1]]),
                        u16::from_be_bytes([self.data[2], self.data[3]]),
                        u16::from_be_bytes([self.data[4], self.data[5]]),
                        u16::from_be_bytes([self.data[6], self.data[7]]),
                        u16::from_be_bytes([self.data[8], self.data[9]]),
                        u16::from_be_bytes([self.data[10], self.data[11]]),
                        u16::from_be_bytes([self.data[12], self.data[13]]),
                        u16::from_be_bytes([self.data[14], self.data[15]]),
                    );
                    format!("{}", ip)
                } else {
                    format!("Invalid data length: {}", self.data_length)
                }
            }
            DnsType::CNAME => {
                String::from_utf8_lossy(&self.data).into_owned()
            }
            DnsType::NS => {
                String::from_utf8_lossy(&self.data).into_owned()
            }
            _ => format!("Unknown type: {:?}", self.record_type),
        }
    }
}

pub struct DnsResult {
    pub question: Question,
    pub answers: Vec<DnsRecord>,
    pub authority_records: Vec<DnsRecord>,
    pub additional_records: Vec<DnsRecord>,
}

impl DnsResult {
    pub fn log(&self) {
        println!("QUESTION SECTION:");
        println!("  {}\t{:?}\t{:?}", self.question.url, self.question.dns_class, self.question.dns_type);

        println!("\nANSWER SECTION:");
        for answer in &self.answers {
            let parsed_data = answer.parse_data();
            println!("  {}\t{}\t{:?}\t{:?}\t{}", answer.name, answer.ttl, answer.record_class, answer.record_type, parsed_data);
        }

        println!("\nAUTHORITY SECTION:");
        for record in &self.authority_records {
            let parsed_data = record.parse_data();
            println!("  {}\t{}\t{:?}\t{:?}\t{:?}", record.name, record.ttl, record.record_class, record.record_type, parsed_data);
        }

        println!("\nADDITIONAL SECTION:");
        for record in &self.additional_records {
            let parsed_data = record.parse_data();
            println!("  {}\t{}\t{:?}\t{:?}\t{:?}", record.name, record.ttl, record.record_class, record.record_type, parsed_data);
        }
    }
}
