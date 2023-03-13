use std::{net::{SocketAddr, UdpSocket}, env};

mod dns;

fn main() {
    // Parse the domain name from the command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: dns_lookup <domain_name>");
        return;
    }

    let domain_name = &args[1];

    // Create a UDP socket bound to any available local address
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Could not bind socket");

    // Specify the DNS server address and port
    let server_address: SocketAddr = "192.203.230.10:53".parse().unwrap();

    // Prepare the DNS query
    let id: u16 = 1234;
    let query = prepare_dns_query(&domain_name, id);

    // Send the DNS query to the server
    socket
        .send_to(&query, server_address)
        .expect("Could not send query");

    // Receive the DNS response from the server
    let mut response_buffer = [0; 512];
    let (response_size, _) = socket
        .recv_from(&mut response_buffer)
        .expect("Could not receive response");

    // Parse the DNS response and print the IP addresses associated with the domain name
    let response = parse_dns_response(&response_buffer[..response_size], id).unwrap();
    response.log();
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

fn parse_dns_response(response_buffer: &[u8], id: u16) -> Result<dns::DnsResult, &'static str> {
    // Make sure the response ID matches the query ID
    let response_id = parse_u16(&response_buffer[0..2]);
    if response_id != id {
        return Err("Invalid ID");
    }

    // Make sure the response is a valid response
    let response_flags_codes = parse_u16(&response_buffer[2..4]);
    if response_flags_codes & 0x8000 == 0 {
        return Err("Invalid header - not a response");
    }

    // Make sure the response is not an error
    if response_flags_codes & 0xf != 0 {
        return Err("Response error");
    }

    let qd_count = parse_u16(&response_buffer[4..6]);
    let an_count = parse_u16(&response_buffer[6..8]);
    let ns_count = parse_u16(&response_buffer[8..10]);
    let ar_count = parse_u16(&response_buffer[10..12]);

    let mut cursor = 12;

    // Parse the question section
    let (question, o) = read_data(&response_buffer, cursor, None);
    let question = String::from_utf8_lossy(&question).into_owned();
    cursor += o + 1;

    let qtype = dns::DnsType::from_u16(parse_u16(&response_buffer[cursor..cursor + 2]));
    let qclass = dns::DnsClass::from_u16(parse_u16(&response_buffer[cursor + 2..cursor + 4]));
    cursor += 4;

    let question = dns::Question {
        url: question,
        dns_type: qtype,
        dns_class: qclass,
    };

    // Parse the answers
    let mut answers = Vec::new();
    for _ in 0..an_count {
        let dns_answer = parse_record(&response_buffer, cursor);
        cursor += 12 + dns_answer.data_length as usize;
        answers.push(dns_answer);
    }

    // Parse the authority records
    let mut authority_records = Vec::new();
    for _ in 0..ns_count {
        let dns_answer = parse_record(&response_buffer, cursor);
        cursor += 12 + dns_answer.data_length as usize;
        authority_records.push(dns_answer);
    }

    // Parse the additional records
    let mut additional_records = Vec::new();
    for _ in 0..ar_count {
        let dns_answer = parse_record(&response_buffer, cursor);
        cursor += 12 + dns_answer.data_length as usize;
        additional_records.push(dns_answer);
    }

    Ok(dns::DnsResult {
        question,
        answers,
        authority_records,
        additional_records,
    })
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

fn parse_record(buffer: &[u8], cursor: usize) -> dns::DnsRecord {
    let mut cursor = cursor;

    let (name, _) = read_data(&buffer, cursor, Some(2));
    let name = String::from_utf8_lossy(&name).into_owned();
    let record_type = dns::DnsType::from_u16(parse_u16(&buffer[cursor + 2..cursor + 4]));
    let record_class = dns::DnsClass::from_u16(parse_u16(&buffer[cursor + 4..cursor + 6]));
    let ttl = parse_u32(&buffer[cursor + 6..cursor + 10]);
    let length = parse_u16(&buffer[cursor + 10..cursor + 12]);
    cursor += 12;

    let mut data: Vec<u8> = Vec::new();

    match record_type {
        dns::DnsType::A => {
            data.extend(&buffer[cursor..cursor + length as usize]);
        }
        dns::DnsType::AAAA => {
            data.extend(&buffer[cursor..cursor + length as usize]);
        }
        dns::DnsType::NS => {
            let (d, _) = read_data(&buffer, cursor, Some(length as usize));
            data = d;
        }
        _ => {}
    }

    dns::DnsRecord {
        name,
        record_type,
        record_class,
        ttl,
        data_length: length,
        data,
    }
}
