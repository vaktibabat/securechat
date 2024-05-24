use message::Peer;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::{self, select};

pub mod message;

#[derive(Debug)]
enum CommandOpcode {
    Help,
    Connect,
    Send,
    Leave,
    Quit,
    Listen,
    GetCert,
    Unknown,
}

#[derive(Debug)]
pub struct Command {
    op: CommandOpcode,
    args: Vec<String>,
}

macro_rules! skip_fail {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(e) => {
                println!("Error: {}", e);
                continue;
            }
        }
    };
}

/// We enter this loop after we established a connection
async fn peer_loop(peer: &mut Peer) -> Result<(), io::Error> {
    println!(
        "Connection established with peer {}",
        peer.stream.as_mut().unwrap().peer_addr().unwrap()
    );

    loop {
        let stdin = io::stdin();
        let br = BufReader::new(stdin);
        let mut lines = br.lines();

        // Select between whatever happened first:
        // The other side sent us a message, or we got command from stdin
        select! {
            line = lines.next_line() => {
                if let Some(cmd_str) = line.unwrap() {
                    let cmd = parse_cmd(cmd_str.split(' ').map(|s| s.trim()).collect());

                    // Handle the command
                    match cmd.op {
                        CommandOpcode::Help => help(),
                        CommandOpcode::Connect => println!("Please leave your current connection before connecting to another peer."),
                        CommandOpcode::Send => handle_send(cmd, peer).await?,
                        CommandOpcode::Leave => break,
                        CommandOpcode::Quit => std::process::exit(0),
                        CommandOpcode::Listen => println!("Please leave your current connecting before listening for a new peer."),
                        CommandOpcode::GetCert => println!("Please leave your current connection before asking for a cert."),
                        CommandOpcode::Unknown => println!("Unknown opcode. Please use help."),
                    }
                }
            }
            // Receive and decrypt the text
            text = peer.receive_text() => {
                let unwrap_text = text.unwrap();

                // The other end of the pipe is closed, so we shut down our end
                if unwrap_text.is_empty() {
                    break;
                }

                println!("GOT {}", unwrap_text);
            }
        }
    }

    // Shutdown the stream
    peer.stream.as_mut().unwrap().shutdown().await?;

    println!("Connection closed successfully");

    Ok(())
}

/// Parse a command into its opcode and its arguments
fn parse_cmd(cmd: Vec<&str>) -> Command {
    let op = match *cmd.first().unwrap() {
        "help" => CommandOpcode::Help,
        "connect" => CommandOpcode::Connect,
        "send" => CommandOpcode::Send,
        "leave" => CommandOpcode::Leave,
        "quit" => CommandOpcode::Quit,
        "exit" => CommandOpcode::Quit,
        "get_cert" => CommandOpcode::GetCert,
        "listen" => CommandOpcode::Listen,
        _ => CommandOpcode::Unknown,
    };

    // Collect the arguments of the command.
    // The skip() method is used because the first element of cmd is the operation, which we already parsed
    let args = cmd
        .into_iter()
        .skip(1)
        .map(|arg| arg.trim().to_string())
        .collect();

    Command { op, args }
}

/// Help message
fn help() {
    println!("Available Commands: ");
    println!("connect <host> <port> - Connect to a peer. When you send messages, they will be sent to this peer");
    println!("leave - Stop talking to the peer you are currently talking to");
    println!("listen <port> - Start listening for peers on port <port> and network address <network address>. Note that using loopback WILL NOT WORK!");
    println!("quit - Exit the program");
    println!("send <msg> - Send a message to the peer you are connected to. The message may have spaces.");
    println!("get_cert <TTP IP> <TTP PORT> <YOUR NAME> <FILENAME> - Ask the TTP @ TTP_IP:TTP_PORT for a cert licensed to <YOUR NAME> and save it under <FILENAME>");
    println!("help - show this help message");
}

/// Connect to the server
async fn handle_connect(cmd: Command, peer: &mut Peer) -> Result<(), io::Error> {
    if cmd.args.len() < 4 {
        return Err(io::Error::other("Invalid number of arguments"));
    }
    
    let host = &cmd.args[0];
    let port = match cmd.args[1].parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err(io::Error::other("Invalid port number")),
    };
    let ttp_host = &cmd.args[2];
    let ttp_port = match cmd.args[3].parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err(io::Error::other("Invalid port number")),
    };

    peer.connect(host, port, ttp_host, ttp_port).await?;

    peer_loop(peer).await?;

    Ok(())
}

/// Send a message
async fn handle_send(cmd: Command, peer: &mut Peer) -> Result<(), io::Error> {
    // To reduce the amount of TCP stream writes, we first concatanate the arguments to a new string
    let mut final_str = String::new();

    // Each argument is considered a word. We seperate them with spaces
    for word in cmd.args {
        final_str.push_str(&word);
        final_str.push(' ');
    }

    peer.send_text(final_str).await?;

    Ok(())
}

/// Listen for peers
async fn handle_listen(cmd: Command, peer: &mut Peer) -> Result<(), io::Error> {
    if cmd.args.len() < 4 {
        return Err(io::Error::other("Invalid number of arguments"));
    }
    
    let host = &cmd.args[0];
    let port = match cmd.args[1].parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err(io::Error::other("Invalid port number")),
    };
    let ttp_host = &cmd.args[2];
    let ttp_port = match cmd.args[3].parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err(io::Error::other("Invalid port number")),
    };
    println!("Listening for peers on port {}", port);

    peer.listen(host, port, ttp_host, ttp_port).await?;

    peer_loop(peer).await?;

    Ok(())
}

/// Get a certificate from the issuer
async fn handle_get_cert(cmd: Command, peer: &mut Peer) -> Result<(), io::Error> {
    if cmd.args.len() < 2 {
        return Err(io::Error::other("Invalid number of arguments"));
    }
    
    // Host and port of the TTP
    let host = &cmd.args[0];
    let port = match cmd.args[1].parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err(io::Error::other("Invalid port number")),
    };
    // Get the user's name
    print!("Enter your name: ");
    let stdin = io::stdin();
    let br = BufReader::new(stdin);
    io::stdout().flush().await?;
    let name = br.lines().next_line().await?.unwrap();

    peer.get_cert(host, port, name).await
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    println!("WELCOME TO RSACHAT!");
    // The user
    let mut peer = Peer::new();

    loop {
        let stdin = io::stdin();
        let br = BufReader::new(stdin);

        io::stdout().flush().await?;

        let line = br.lines().next_line().await?;

        if let Some(cmd_str) = line {
            let cmd = parse_cmd(cmd_str.split(' ').map(|s| s.trim()).collect());

            match cmd.op {
			    CommandOpcode::Connect => {skip_fail!(handle_connect(cmd, &mut peer).await)},
			    CommandOpcode::Help => help(),
			    CommandOpcode::Leave => println!("You can only use leave when you are connected to a peer!\n Try to connect first"),
			    CommandOpcode::Listen => skip_fail!(handle_listen(cmd, &mut peer).await),
			    CommandOpcode::Quit => break,
			    CommandOpcode::Send => println!("You can only send messages when you are already connected to a peer!\nTry to connect first"),
                CommandOpcode::GetCert => skip_fail!(handle_get_cert(cmd, &mut peer).await),
			    CommandOpcode::Unknown => println!("Unknown command. Please use help"),
		    }
        } else {
            continue;
        }
    }

    Ok(())
}
