use std::net::{Ipv4Addr, SocketAddr, UdpSocket, Ipv6Addr};

fn main() {
    // Create a UDP socket bound to any available local address
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Could not bind socket");

    // Specify the DNS server address and port
    let server_address: SocketAddr = "192.203.230.10:53".parse().unwrap();

    // Prepare the DNS query
    let id: u16 = 1234;
    let query = prepare_dns_query("www.example.com", id);

    println!("query: {:?}", query);

    // Send the DNS query to the server
    socket
        .send_to(&query, server_address)
        .expect("Could not send query");

    // Receive the DNS response from the server
    let mut response_buffer = [0; 512];
    let (response_size, _) = socket
        .recv_from(&mut response_buffer)
        .expect("Could not receive response");

    println!("response: {:?}", response_buffer);

    // Parse the DNS response and print the IP addresses associated with the domain name
    let response = parse_dns_response(&response_buffer[..response_size], id).unwrap();
    for answer in response.answers.iter() {
        if let Some(ip_address) = answer.extract_ip_address() {
            println!("{}", ip_address);
        }
    }
}

fn prepare_dns_query(domain_name: &str, id: u16) -> Vec<u8> {
    let mut query = Vec::new();

    query.extend_from_slice(&id.to_be_bytes());

    // Add the DNS header
    query.extend_from_slice(&[
        0x01, 0x00, // Flags (standard query, recursion desired)
        0x00, 0x01, // Number of questions
        0x00, 0x00, // Number of answer RRs
        0x00, 0x00, // Number of authority RRs
        0x00, 0x00, // Number of additional RRs
    ]);

    // Add the domain name to the query
    for label in domain_name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // End of domain name

    // Add the query type and class
    query.extend_from_slice(&[0x00, 0x01]); // Type A (IPv4 address)
    query.extend_from_slice(&[0x00, 0x01]); // Class IN (Internet)

    query
}

struct DnsResponse {
    answers: Vec<DnsAnswer>,
}

struct DnsAnswer {
    name: String,
    record_type: u16,
    record_class: u16,
    ttl: u32,
    data_length: u16,
    data: Vec<u8>,
}

impl DnsAnswer {
    fn extract_ip_address(&self) -> Option<Ipv4Addr> {
        if self.record_type == 0x0001 && self.record_class == 0x0001 && self.data_length == 4 {
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
}

fn parse_dns_response(response_buffer: &[u8], id: u16) -> Result<DnsResponse, &'static str> {
    // Make sure the response ID matches the query ID
    let response_id = parse_u16(&response_buffer[0..2]);
    if response_id != id {
        return Err("Invalid ID");
    }

    let response_flags_codes = parse_u16(&response_buffer[2..4]);
    if response_flags_codes & 0x8000 == 0 {
        return Err("Invalid header - not a response");
    }

    if response_flags_codes & 0xf != 0 {
        return Err("Response error");
    }

    let qd_count = parse_u16(&response_buffer[4..6]);
    let an_count = parse_u16(&response_buffer[6..8]);
    let ns_count = parse_u16(&response_buffer[8..10]);
    let ar_count = parse_u16(&response_buffer[10..12]);

    println!("{} {} {} {}", qd_count, an_count, ns_count, ar_count);

    let mut cursor = 12;

    let (response_url, o) = read_data(&response_buffer, cursor, None);
    let response_url = String::from_utf8_lossy(&response_url).into_owned();
    println!("{}", response_url);
    cursor += o;

    // let mut response_url = String::new();
    // while length != 0 {
    //     cursor += 1;
    //     let data = &response_buffer[cursor..cursor + length as usize];
    //     let data = String::from_utf8_lossy(data).into_owned();
    //     response_url.push_str(&data);
    //     response_url.push('.');
    //     cursor += length as usize;
    //     length = response_buffer[cursor];
    // }
    // response_url.pop();
    // println!("{}", response_url);

    let qtype = parse_u16(&response_buffer[cursor..cursor + 2]);
    let qclass = parse_u16(&response_buffer[cursor + 2..cursor + 4]);
    cursor += 4;

    for _ in 0..an_count {
        let (d, o) = parse_record(&response_buffer, cursor);
        cursor += o;
    }

    cursor += 1;
    for _ in 0..ns_count {
        let (d, o) = parse_record(&response_buffer, cursor);
        cursor += o;
    }

    println!("-------");

    for _ in 0..ar_count {
        let (d, o) = parse_record(&response_buffer, cursor);
        cursor += o;
    }

    // Parse the answers
    let mut answers = Vec::new();

    Ok(DnsResponse { answers })
}

fn parse_u16(buffer: &[u8]) -> u16 {
    u16::from_be_bytes([buffer[0], buffer[1]])
}

fn parse_u32(buffer: &[u8]) -> u32 {
    u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]])
}

fn parse_label_length(buffer: &[u8]) -> usize {
    if buffer[0] & 0xc0 == 0xc0 {
        2
    } else {
        buffer[0] as usize + 1
    }
}

fn read_data(buffer: &[u8], from: usize, to: Option<usize>) -> (Vec<u8>, usize) {
    let mut data = Vec::new();
    let mut cursor = from;

    while {
        if to.is_none() {
            buffer[cursor] != 0
        } else {
            cursor < from + to.unwrap()
        }
    } {
        let length = parse_label_length(&buffer[cursor..]);
        if buffer[cursor] & 0xc0 == 0xc0 {
            let offset = parse_u16(&buffer[cursor..cursor + 2]) & 0x3fff;
            let (label, _) = read_data(buffer, offset as usize, None);
            data.extend(label);
        } else {
            data.extend(&buffer[cursor + 1..cursor + length]);
            data.push(b'.');
        }
        cursor += length;
    }

    (data, cursor - from)
}

fn parse_record(buffer: &[u8], cursor: usize) -> (String, usize) {
    let mut cursor = cursor;

    let (name, _) = read_data(&buffer, cursor, Some(2));
    let name = String::from_utf8_lossy(&name).into_owned();
    let record_type = parse_u16(&buffer[cursor + 2..cursor + 4]);
    let record_class = parse_u16(&buffer[cursor + 4..cursor + 6]);
    let ttl = parse_u32(&buffer[cursor + 6..cursor + 10]);
    let length = parse_u16(&buffer[cursor + 10..cursor + 12]);
    cursor += 12;

    match record_type {
        1 => {
            let data = Ipv4Addr::new(
                buffer[cursor],
                buffer[cursor + 1],
                buffer[cursor + 2],
                buffer[cursor + 3],
            );
            println!(
                "name: {} type: {} class: {} ttl: {} length: {} data: {}",
                name, record_type, record_class, ttl, length, data
            );
            return (data.to_string(), 12 + length as usize);
        }
        2 => {
            let (data, o) = read_data(&buffer, cursor, Some(length as usize));
            let data = String::from_utf8_lossy(&data).into_owned();
            println!(
                "name: {} type: {} class: {} ttl: {} length: {} data: {}",
                name, record_type, record_class, ttl, length, data
            );
            return (data, 12 + o);
        }
        28 => {
            let data = Ipv6Addr::new(
                parse_u16(&buffer[cursor..cursor + 2]),
                parse_u16(&buffer[cursor + 2..cursor + 4]),
                parse_u16(&buffer[cursor + 4..cursor + 6]),
                parse_u16(&buffer[cursor + 6..cursor + 8]),
                parse_u16(&buffer[cursor + 8..cursor + 10]),
                parse_u16(&buffer[cursor + 10..cursor + 12]),
                parse_u16(&buffer[cursor + 12..cursor + 14]),
                parse_u16(&buffer[cursor + 14..cursor + 16]),
            );
            println!(
                "name: {} type: {} class: {} ttl: {} length: {} data: {}",
                name, record_type, record_class, ttl, length, data
            );
            return (data.to_string(), 12 + length as usize);
        }
        _ => {
            (String::from(""), 12 + length as usize)
        }
    }
}
