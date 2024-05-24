use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use num_bigint::BigUint;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rsa::{Keypair, PublicKey, N_SIZE};
use std::convert::TryInto;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const RSA_EXP: u64 = 65537u64;
const AES_BLOCK_SIZE: usize = 16;
const SIGNATURE_SIZE: usize = 256;

// Max message size in bytes
const MAX_MESSAGE_SIZE: usize = 2048;

/// Wrapper functions for sending and receiving our custom messages
trait MessageSender {
    async fn send_message(&mut self, msg: &mut Message) -> Result<usize, io::Error>;
    async fn receive_message(&mut self) -> Result<Message, io::Error>;
}

/// Convert a type to bytes
trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
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
    SymmetricKey,
    Text,
    Other,
}

pub struct Peer {
    keypair: Keypair,
    pub cert: Option<Certificate>,
    pub stream: Option<TcpStream>,
    pub cipher: Option<Aes128>, // The symmetric key
}

#[derive(Debug)]
pub struct Certificate {
    name: String,
    public: PublicKey,
    signature: Vec<u8>,
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
            8 => Self::SymmetricKey,
            9 => Self::Text,
            _ => Self::Other,
        }
    }
}

impl Message {
    fn new(op: MessageOpcode, payload: Vec<u8>) -> Message {
        Message { op, payload }
    }
}

impl MessageSender for TcpStream {
    async fn send_message(&mut self, msg: &mut Message) -> Result<usize, io::Error> {
        let mut data = vec![msg.op.index()];
        data.append(&mut msg.payload);

        self.write(&data).await
    }

    async fn receive_message(&mut self) -> Result<Message, io::Error> {
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        let n = self.read(&mut buf).await?;
        // First byte is the opcode
        let op = buf[0];
        let payload = buf[1..n].to_vec();

        Ok(Message {
            op: MessageOpcode::opcode_to_element(op),
            payload,
        })
    }
}

impl ToBytes for Certificate {
    fn to_bytes(&self) -> Vec<u8> {
        // Length of the name the certificate is issued to (4 BE bytes)
        let name_length = self.name.len() as u32;
        // The name, in bytes
        let name = &self.name;
        // Constant 2048 bits
        let n = pad_bigint(&self.public.n, 2048);
        // The signature from the issuer
        let signature = &self.signature;
        // Construct the payload
        let mut payload = vec![];
        // Append everything to the message's payload
        payload.append(&mut name_length.to_be_bytes().to_vec());
        payload.append(&mut name.as_bytes().to_vec());
        payload.append(&mut n.to_bytes_be());
        // We have to clone this because
        // we don't want to empty self.signature
        payload.append(&mut signature.clone());

        payload
    }
}

impl Certificate {
    /// Parse a certificate from a message
    fn from_message(msg: Message) -> Result<Certificate, io::Error> {
        // Certificates are only received from the CertficateShow message type
        if msg.op != MessageOpcode::CertificateShow {
            Err(io::Error::other(
                "Expected a certificate, but received something else",
            ))
        } else {
            let payload = msg.payload;
            // First four bytes are the length of the name
            // We have to specify this, because the length of the name is dynamic
            let name_length = u32::from_be_bytes(payload[0..4].try_into().unwrap());
            // The name itself, parsed from utf8
            let name = String::from_utf8(payload[4..4 + name_length as usize].to_vec()).unwrap();
            // The public key's n (2048 bits). We don't need to specify e, because it is a constant 65537
            let n = BigUint::from_bytes_be(
                &payload[4 + name_length as usize..4 + name_length as usize + N_SIZE],
            );
            // The length of the signature is always 256 bytes
            // Because we raise the digest (MD5 digest is always 128-bit = 16 bytes)
            // To the power of e=65537, and then take modulo n (2048 bits = 256 bytes)
            // We also pad the signature when sending it in case it is smaller than 256 bytes
            let signature = payload[4 + name_length as usize + N_SIZE
                ..4 + name_length as usize + N_SIZE + SIGNATURE_SIZE]
                .to_vec();

            // Return the certificate we parsed
            Ok(Certificate {
                name,
                public: PublicKey {
                    e: RSA_EXP.into(),
                    n,
                },
                signature,
            })
        }
    }

    /// Show our certificate to the other side of the stream
    /// This certificate is then parsed with Certificate::from_message()
    async fn display_cert(&self, msg: Message, stream: &mut TcpStream) -> Result<usize, io::Error> {
        // Certificates can only be shown in response to a HandshakeStart
        if msg.op != MessageOpcode::HandshakeStart {
            Err(io::Error::other(
                "Exepected a request for my certificate, but received something else",
            ))
        } else {
            // Convert the certificate to bytes
            let payload = self.to_bytes();
            
            // Construct the message
            let mut msg = Message {
                op: MessageOpcode::CertificateShow,
                payload,
            };
            // Send it
            Ok(stream.send_message(&mut msg).await?)
        }
    }

    /// Validate the certificate against the issuer
    async fn validate_certificate(&self, stream: &mut TcpStream) -> Result<bool, io::Error> {
        // Construct a payload
        let payload = self.to_bytes();        
        
        // Construct a message
        let mut msg = Message {
            op: MessageOpcode::ValidateCertificate,
            payload,
        };
        stream.send_message(&mut msg).await?;
        // Read the response
        // The response is with 1 byte, and either contains a 1
        // if the cert is valid, and a 0 otherwise
        let resp = stream.receive_message().await?;

        // Ok(true)
        Ok(if resp.payload[0] == 1 {true} else {false})
    }
}

impl Default for Peer {
    fn default() -> Self {
        Self::new()
    }
}

impl Peer {
    /// Initialize a new peer
    /// Only the keypair is generated
    pub fn new() -> Peer {
        let keypair = Keypair::new(None, None);

        Peer {
            keypair,
            cert: None,
            stream: None,
            cipher: None,
        }
    }

    /// Connect to another peer, and perform the handshake
    pub async fn connect(
        &mut self,
        host: &String,
        port: u16,
        ttp_host: &String,
        ttp_port: u16,
    ) -> Result<(), io::Error> {
        // Connect to the server
        let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
        // Connect to the TTP
        let mut ttp_stream = TcpStream::connect(format!("{}:{}", ttp_host, ttp_port)).await?;

        // Ask for the server's certificate
        let mut cert_req = Message::new(MessageOpcode::HandshakeStart, vec![]);
        stream.send_message(&mut cert_req).await?;
        // We expect this to be the certificate from the server
        let response = stream.receive_message().await?;
        // Parse it into the actual certificate
        let server_cert = Certificate::from_message(response).unwrap();
        // Validate the certificate against the TTP
        let is_cert_valid = server_cert.validate_certificate(&mut ttp_stream).await?;
        // Close the TTP stream
        ttp_stream.shutdown().await?;

        // If the signature is not valid, exit
        if !is_cert_valid {
            stream
                .send_message(&mut Message {
                    op: MessageOpcode::CertificateRejected,
                    payload: vec![],
                })
                .await?;
            stream.shutdown().await?;

            return Err(io::Error::other("Certificate is not valid"));
        }

        println!("Server\'s certificate is valid");
        // Otherwise, send a message to the server
        // To indicate that its certificate is valid
        // And we can continue to the next part of the handshake
        stream
            .send_message(&mut Message {
                op: MessageOpcode::CertificateAccepted,
                payload: vec![],
            })
            .await?;

        // Send the client's certificate to the server
        // We expect this to be a request for our certificate
        let request = stream.receive_message().await?;
        // Respond to it with our cert
        self.cert
            .as_mut()
            .unwrap()
            .display_cert(request, &mut stream)
            .await?;

        // Check if the server accepted our certificate
        let server_resp = stream.receive_message().await?;

        if server_resp.op != MessageOpcode::CertificateAccepted {
            stream.shutdown().await?;
            ttp_stream.shutdown().await?;
            return Err(io::Error::other("Handshake error"));
        }

        // At this point, we know the server's cert, and the server knows our cert.
        // The server is supposed to send a message containing
        // The symmetric key (bytes 0-15), and the IV for CBC (bytes 16-31)
        let symmetric_key_msg = stream.receive_message().await?;
        // The key we got is encrypted under our public key, so we need to decrypt it
        let encrypted_symmetric_key = symmetric_key_msg.payload;
        let symmetric_key = self
            .keypair
            .private
            .decrypt(&BigUint::from_bytes_be(&encrypted_symmetric_key));
        // Convert it into a GenericArray, to create a cipher
        let symmetric_key_bytes: [u8; AES_BLOCK_SIZE] =
            symmetric_key.to_bytes_be().try_into().unwrap();
        let symmetric_key_arr = GenericArray::from(symmetric_key_bytes);
        // Create a cipher from the symmetric key
        let cipher = Aes128::new(&symmetric_key_arr);

        // We now have a stream with the server, and a cipher under which to encrypt & decrypt messages
        self.stream = Some(stream);
        self.cipher = Some(cipher);
        Ok(())
    }

    /// Listen for another peer
    pub async fn listen(
        &mut self,
        host: &String,
        port: u16,
        ttp_host: &String,
        ttp_port: u16,
    ) -> Result<(), io::Error> {
        // Listen for clients
        let listener = TcpListener::bind(format!("{}:{}", host, port)).await?;

        // Wait for a client
        let (mut stream, _) = listener.accept().await?;
        // Connect to the TTP
        let mut ttp_stream = TcpStream::connect(format!("{}:{}", ttp_host, ttp_port)).await?;

        // We expect this to be a request for our certificate
        let request = stream.receive_message().await?;
        // Respond to it with our cert
        self.cert
            .as_mut()
            .unwrap()
            .display_cert(request, &mut stream)
            .await?;
        // The client's response
        let client_resp = stream.receive_message().await?;

        // If the client didn't accept our cert, some error happened
        if client_resp.op != MessageOpcode::CertificateAccepted {
            stream.shutdown().await?;
            ttp_stream.shutdown().await?;
            return Err(io::Error::other("Handshake error"));
        }

        // Ask for the client's certificate
        let mut cert_req = Message::new(MessageOpcode::HandshakeStart, vec![]);
        stream.send_message(&mut cert_req).await?;
        // The certificate of the client in bytes
        let response = stream.receive_message().await?;
        // Parse it into the actual certificate
        let client_cert = Certificate::from_message(response).unwrap();
        // Validate the certificate against the TTP
        let is_cert_valid = client_cert.validate_certificate(&mut ttp_stream).await?;
        // Close the TTP stream
        ttp_stream.shutdown().await?;

        // If the cert is not valid, exit
        if !is_cert_valid {
            // Indicate to the client that its cert is not valid
            stream
                .send_message(&mut Message {
                    op: MessageOpcode::CertificateRejected,
                    payload: vec![],
                })
                .await?;
            stream.shutdown().await?;

            return Err(io::Error::other("Certificate is not valid"));
        }

        // Otherwise, tell the client that its cert is valid
        stream
            .send_message(&mut Message {
                op: MessageOpcode::CertificateAccepted,
                payload: vec![],
            })
            .await?;

        // At this point, we know the client's cert and vice versa
        println!("Client\'s certificate is valid");

        // Generate a symmetric key
        let mut rng = ChaCha20Rng::from_entropy();
        let mut key = [0u8; AES_BLOCK_SIZE];
        rng.fill_bytes(&mut key);
        // Generate an IV
        let mut iv = [0u8; AES_BLOCK_SIZE];
        rng.fill_bytes(&mut iv);
        // Encrypt the symmetric key under the client's public key
        let client_public = client_cert.public;
        let encrypted_key = client_public.encrypt(&BigUint::from_bytes_be(&key));
        // Send it to the client
        let mut msg = Message {
            op: MessageOpcode::SymmetricKey,
            payload: encrypted_key.to_bytes_be(),
        };
        
        stream.send_message(&mut msg).await?;

        self.stream = Some(stream);
        // Create a GenericArray of the key
        let symmetric_key_arr = GenericArray::from(key);
        // Create a cipher to use to encrypt/decrypt messages
        let cipher = Aes128::new(&symmetric_key_arr);
        self.cipher = Some(cipher);

        Ok(())
    }

    /// Ask the TTP for a certificate
    pub async fn get_cert(
        &mut self,
        host: &String,
        port: u16,
        name: String,
    ) -> Result<(), io::Error> {
        // Connect to the TTP
        let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let mut payload = vec![];
        let name_len = name.len() as u32;
        // Name Length: 4 BE bytes
        payload.append(&mut name_len.to_be_bytes().to_vec());
        // The name
        payload.append(&mut name.as_bytes().to_vec());
        // Public key's n
        payload.append(&mut self.keypair.public.n.to_bytes_be());
        // Construct a message
        let mut msg = Message {
            op: MessageOpcode::RequestCertificate,
            payload,
        };
        // Send it
        stream.send_message(&mut msg).await?;
        // Read the response
        let resp = stream.receive_message().await?;

        // Cert has been succesfully signed
        if resp.op == MessageOpcode::CertSigned {
            self.cert = Some(Certificate {
                name,
                public: self.keypair.public.clone(),
                signature: resp.payload,
            })
        } else {
            return Err(io::Error::other("The TTP didn\'t sign the certificate"));
        }

        // Shutdown the stream
        stream.shutdown().await?;

        Ok(())
    }

    /// Encrypt a text and send it
    pub async fn send_text(&mut self, text: String) -> Result<(), io::Error> {
        // First we need to encrypt the text using AES-CBC
        // The client and the server both have a shared cipher
        let ciphertext = aes_cbc_encrypt(
            &mut text.as_bytes().to_vec(),
            self.cipher
                .as_mut()
                .expect("Connection Establishement failed"),
        );

        // Construct a message that contains the ciphertext
        let mut msg = Message {
            op: MessageOpcode::Text,
            payload: ciphertext.into_iter().flatten().collect(),
        };
        // Send it
        self.stream
            .as_mut()
            .expect("Connection establishmenet failed")
            .send_message(&mut msg)
            .await?;

        Ok(())
    }

    /// Decrypt an encrypted text
    pub async fn receive_text(&mut self) -> Result<String, io::Error> {
        // The message we got with the text
        let msg = self
            .stream
            .as_mut()
            .expect("Failed to establish connection")
            .receive_message()
            .await?;

        if msg.op == MessageOpcode::Text {
            // The ciphertext is the message's payload
            let mut ciphertext = msg.payload;
            // Decrypt it using the shared key
            let plaintext_blocks = aes_cbc_decrypt(
                &mut ciphertext,
                self.cipher
                    .as_mut()
                    .expect("Failed to establish connection"),
            );
            // Convert into a string
            let plaintext =
                String::from_utf8(plaintext_blocks.into_iter().flatten().collect()).unwrap();

            Ok(plaintext)
        } else {
            Err(io::Error::other(
                "Expected to find a text, but found another type of message",
            ))
        }
    }
}

/// Pad a BigUInt to a number of bits
fn pad_bigint(num: &BigUint, target_bits: usize) -> BigUint {
    let mut bytes = num.to_bytes_be();

    let padding_bytes = (target_bits + 7) / 8 - bytes.len();

    bytes.resize(bytes.len() + padding_bytes, 0);

    BigUint::from_bytes_be(&bytes)
}

/// Encrypt AES in CBC mode with a constant IV
fn aes_cbc_encrypt(m: &mut [u8], cipher: &Aes128) -> Vec<[u8; AES_BLOCK_SIZE]> {
    // Calculate the number of padding bytes
    let bytes_padding = if m.len() % AES_BLOCK_SIZE != 0 {
        AES_BLOCK_SIZE - (m.len() % AES_BLOCK_SIZE)
    } else {
        0
    };
    // Pad the message using PKCS#7 Padding
    let mut m_padded = m.to_owned();
    m_padded.append(&mut [bytes_padding.try_into().unwrap()].repeat(bytes_padding));
    // Split the plaintext into blocks, each of size 16 bytes
    let mut plaintext_blocks = m_padded.chunks_exact(AES_BLOCK_SIZE);
    // Construct the first ciphertext block, which we get by XORing the first plaintext block with the IV and then encrypting
    let iv = b"YELLOW SUBMARINE";
    let mut ciphertext_blocks: Vec<[u8; AES_BLOCK_SIZE]> = vec![];
    let first_block_slice = plaintext_blocks.next().unwrap();
    // XOR with the IV
    let first_block_vec: Vec<u8> = first_block_slice
        .iter()
        .zip(iv.iter())
        .map(|(x, y)| x ^ y)
        .collect();
    let first_block: [u8; AES_BLOCK_SIZE] = first_block_vec.try_into().unwrap();
    let mut first_block_arr = GenericArray::from(first_block);
    cipher.encrypt_block(&mut first_block_arr);
    // Push it to the list of blocks
    ciphertext_blocks.push(first_block_arr.into());

    // Iterate over every plaintext block. We've already done the first one manually
    for block in plaintext_blocks {
        // XOR with the last ciphertext block
        let last_c_block = ciphertext_blocks.last().unwrap();
        let block_xored_vec: Vec<u8> = block
            .iter()
            .zip(last_c_block.iter())
            .map(|(x, y)| x ^ y)
            .collect();
        let xored_block: [u8; AES_BLOCK_SIZE] = block_xored_vec.try_into().unwrap();
        // Convert to a GenericArray and encrypt
        let mut xored_block_arr = GenericArray::from(xored_block);
        cipher.encrypt_block(&mut xored_block_arr);
        // Push to the list of ciphertext blocks
        ciphertext_blocks.push(xored_block_arr.into());
    }

    ciphertext_blocks
}

/// Decrypt AES in CBC moed with a constant IV
fn aes_cbc_decrypt(m: &mut [u8], cipher: &Aes128) -> Vec<[u8; AES_BLOCK_SIZE]> {
    // These are the blocks we XOR each decrypted cipher block with
    let mut xor_with = vec![*b"YELLOW SUBMARINE"];
    // Split the ciphertext into blocks
    let ciphertext_blocks: Vec<[u8; AES_BLOCK_SIZE]> = m
        .chunks_exact(AES_BLOCK_SIZE)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();
    xor_with.append(&mut ciphertext_blocks.clone());
    // The first ciphertext block is XORed with the IV, the second is XORed with the 
    // First ciphertext block, etc. so we need to reverse the xor_with vector
    xor_with.reverse();
    // Plaintext blocks
    let mut plaintext_blocks = vec![];

    for block in ciphertext_blocks {
        let to_xor = xor_with.pop().unwrap();
        let mut block_arr = GenericArray::from(block);
        // Decrypt
        cipher.decrypt_block(&mut block_arr);
        // XOR
        let plain_block_vec: Vec<u8> = to_xor
            .iter()
            .zip(block_arr.iter())
            .map(|(x, y)| x ^ y)
            .collect();
        let plain_block: [u8; AES_BLOCK_SIZE] = plain_block_vec.try_into().unwrap();
        plaintext_blocks.push(plain_block);
    }

    // Number of bytes of padding
    let last_char = plaintext_blocks.last().unwrap()[AES_BLOCK_SIZE - 1];

    // If the message is padded
    if 0 < last_char && last_char < AES_BLOCK_SIZE as u8 {
        let mut last_block = plaintext_blocks.pop().unwrap();

        // Change all padding bytes to 0
        for i in AES_BLOCK_SIZE as u8 - last_char..AES_BLOCK_SIZE as u8 {
            last_block[i as usize] = 0;
        }

        plaintext_blocks.push(last_block);
    }

    plaintext_blocks
}