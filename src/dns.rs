use std::process::{Command, Stdio};
use serde::{Serialize, Deserialize};
use std::fs::{File, OpenOptions};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Dns {
    pub if_name: String,
    pub gateway: String,
}

static FILENAME: &str = ".dns";

pub fn save_dns_file(dns: &Dns) -> std::io::Result<()> {
    // Create our file if it doesn't exist
    let file = OpenOptions::new().create_new(true).write(true).open(FILENAME)?;
    serde_yaml::to_writer(file, &dns).expect("Error writing to file");
    Ok(())
}

pub fn read_dns_file() -> std::io::Result<Dns> {
    let file = OpenOptions::new().read(true).write(false).create(false).open(FILENAME)?;
    let dns = serde_yaml::from_reader::<std::fs::File, Dns>(file).expect("Unable to read from dns file");
    std::fs::remove_file(FILENAME)?;
    Ok(dns)
}

pub fn read_dns() -> Dns {
    let output = Command::new("netsh")
        .arg("interface")
        .arg("show")
        .arg("interface")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .output().expect("Failed to spawn child process");

    let outstring = String::from_utf8(output.stdout).unwrap();
    //println!("cmd output: {}", outstring.clone());s
    let splits: Vec<&str> = outstring.split("-------------------------------------------------------------------------").collect();
    //println!("Splitting the dns string\n{:?}", splits);

    // remove the header
    let splits = Vec::from(&splits[1 .. ]);
    
    // split into lines
    let mut dns_vec:Vec<&str> = splits[0].lines().collect();
    dns_vec.retain(|&x| x != ""); // remove empty elements
    //println!("Dns vec:\n{:?}", dns_vec);
    let splitvec = dns_vec[0].split_whitespace().collect::<Vec<&str>>();

    //println!("{:?}", splitvec);

    let interface_name = splitvec[3];

    // okay... we got the interface name of our adapter... now we need its dns info
    let output = Command::new("netsh")
        .arg("interface")
        .arg("ipv4")
        .arg("show")
        .arg("config")
        .arg(interface_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .output().expect("Failed to spawn child process");

    let outstring = String::from_utf8(output.stdout).unwrap();
    //println!("cmd output: {}", outstring.clone());

    let linesplit: Vec<&str> = outstring.lines().collect();
    //println!("linesplit\n{:?}", linesplit);
    let line = linesplit[8].split_whitespace().collect::<Vec<&str>>();
    //println!("line\n{:?}", line);

    return Dns { 
        if_name: String::from(interface_name),
        gateway: String::from(line[4])
    }
}

pub fn set_vpn_dns() {
    let vpndns = Dns {
        if_name: String::from("nebula1"),
        gateway: String::from("1.1.1.1"),
    };
    set_dns(vpndns);
}

pub fn clear_dns(dns: Dns) {
    flush_dns();
    let emptydns = Dns {
        if_name: dns.if_name,
        gateway: String::from("0.0.0.0"),
    };
    set_dns(emptydns);
}

pub fn flush_dns() {
    let output = Command::new("ipconfig")
        .arg("/flushdns")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .output().expect("Failed to spawn child process (flush dns)");

}

pub fn set_dns(dns: Dns) {
    let output = Command::new("netsh")
        .arg("interface")
        .arg("ipv4")
        .arg("set")
        .arg("dnsserver")
        .arg(dns.if_name)
        .arg("static")
        .arg(dns.gateway)
        .arg("both")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .output().expect("Failed to spawn child process");
}