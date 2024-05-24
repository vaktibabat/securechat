use num_bigint::BigUint;
use rsa::Keypair;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use std::env;

// Max message size in bytes
const MAX_MESSAGE_SIZE: usize = 2048;

trait MessageSender {
    async fn send_message(&mut self, msg: &mut Message) -> Result<usize, io::Error>;
    async fn receive_message(&mut self) -> Result<Message, io::Error>;
}

#[derive(Copy, Clone, PartialEq)]
enum MessageOpcode {
    HandshakeStart,
    CertificateShow,
    RequestCertificate,
    CertSigned,
    ValidateCertificate,
    ValidationResponse,
    CertificateAccepted,
    CertificateRejected,
    Other,
}

struct Message {
    op: MessageOpcode,
    payload: Vec<u8>,
}

impl MessageOpcode {
    fn index(&self) -> u8 {
        *self as u8
    }

    fn opcode_to_element(idx: u8) -> MessageOpcode {
        match idx {
            0 => Self::HandshakeStart,
            1 => Self::CertificateShow,
            2 => Self::RequestCertificate,
            3 => Self::CertSigned,
            4 => Self::ValidateCertificate,
            5 => Self::ValidationResponse,
            6 => Self::CertificateAccepted,
            7 => Self::CertificateRejected,
            _ => Self::Other,
        }
    }
}

/// Allow us to send/receive messages of our custom type
impl MessageSender for TcpStream {
    async fn send_message(&mut self, msg: &mut Message) -> Result<usize, io::Error> {
        let mut data = vec![msg.op.index()];
        data.append(&mut msg.payload);

        self.write(&data).await
    }

    async fn receive_message(&mut self) -> Result<Message, io::Error> {
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        let n = self.read(&mut buf).await?;
        let op = buf[0];
        let payload = buf[1..n].to_vec();

        Ok(Message {
            op: MessageOpcode::opcode_to_element(op),
            payload,
        })
    }
}

/// Listen for connections
async fn ttp_server(ip: String, port: u16) -> Result<(), io::Error> {
    let listener = TcpListener::bind(format!("{}:{}", ip, port)).await?;
    let ttp_keypair = Keypair::new(None, None);
    let ttp_keypair_clone = ttp_keypair.clone();

    println!("TTP Listening on {}:{}", ip, port);

    loop {
        let (mut socket, _) = listener.accept().await?;
        let keypair_clone = ttp_keypair_clone.clone();

        tokio::spawn(async move {
            let msg = socket
                .receive_message()
                .await
                .expect("Failed to receive message");
            let payload = msg.payload;
            match msg.op {
                MessageOpcode::RequestCertificate => {
                    let name_length = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                    // The name + the public key's n
                    let to_sign = &payload[4..4 + name_length as usize + 256];
                    // Calculate the MD5 digest
                    let digest = md5::compute(to_sign);
                    // Convert it to a BigUint and sign it using our private key
                    let signature = keypair_clone.sign(&BigUint::from_bytes_be(&digest.to_vec()));
                    // Print the signature
                    // Respond to the client
                    let mut resp = Message {
                        op: MessageOpcode::CertSigned,
                        payload: signature.to_bytes_be(),
                    };
                    socket
                        .send_message(&mut resp)
                        .await
                        .expect("Failed to send response to client");

                    socket.shutdown().await.expect("Failed to shutdown socket");
                }
                MessageOpcode::ValidateCertificate => {
                    let name_length = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                    // The signature is for the digest of this part
                    let signed_part = &payload[4..4 + name_length as usize + 256];
                    // The signature claimed by the certificate
                    let signature = &payload
                        [4 + name_length as usize + 256..4 + name_length as usize + 256 + 256];
                    // Calculate the MD5 digest
                    let digest = md5::compute(signed_part);
                    // Convert it to a BigUint and sign it using our private key
                    let is_signature_valid = keypair_clone.validate(
                        &BigUint::from_bytes_be(&digest.to_vec()),
                        &BigUint::from_bytes_be(signature),
                    );
                    // Respond to the client
                    let mut payload = vec![];
                    if is_signature_valid {
                        payload.push(1);
                    } else {
                        payload.push(0);
                    }
                    let mut resp = Message {
                        op: MessageOpcode::CertSigned,
                        payload,
                    };
                    socket
                        .send_message(&mut resp)
                        .await
                        .expect("Failed to send response to client");

                    socket.shutdown().await.expect("Failed to shutdown socket");
                }
                _ => println!("Unimplemented"),
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let args: Vec<String> = env::args().collect();
    println!("Usage: ./{} <IP Address> <Port>", args[0]);
    let ip = &args[1];
    let port = args[2].parse::<u16>().expect("Not a valid port");

    ttp_server(ip.to_string(), port).await?;

    Ok(())
}
