use std::process::{Command, Stdio};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::io::{BufReader, BufRead, ErrorKind};

use std::io::Read;
use serde_json::{Value, Map};

use std::sync::{Arc, Mutex};

use std::net::Ipv4Addr;

use windows::Win32::System::Console::*;

use std::thread;

mod routes;
use routes::*;
mod dns;
use dns::*;
mod neb_parse;
use neb_parse::*;

#[no_mangle]
unsafe extern "system" fn testhandle(x: u32) -> windows::Win32::Foundation::BOOL {
    //println!("Ate ctrl-c from {}", std::process::id());
    println!("Ate ctrl-c sig {} on pid {}", x, std::process::id());
    //println!("Exiting gracefully");
    windows::Win32::Foundation::BOOL::from(true)
    //std::process::exit(0);
}

/*
fn main() {
    //let mut forward_table = windows::Win32::NetworkManagement::IpHelper::MIB_IPFORWARDTABLE::default();
    //let mut forward_table_buf: [u8; 2000] = [0; 2000]; // a 500 byte buffer for the ip table
    //let mut forward_table_buf: [u8; 500] = [0; 500]; // a 500 byte buffer for the ip table
    //let mut pdw_size = std::mem::size_of_val(&forward_table_buf) as u32;
    //println!("Table size as bytes: {:?}", pdw_size);
    let sorted = false;
    unsafe {


        let tablesize = 15;


        let mut layout = Layout::new::<MIB_IPFORWARDTABLE>();
        let (l, _) = layout.extend(Layout::array::<MIB_IPFORWARDROW>(tablesize).expect("error declaring layout")).expect("Error extending layout");
        //layout = l;
        layout = l.pad_to_align();
        let mut layout_size_bytes = layout.size() as u32;
        println!("Allocated memory for table, bytes = {}", layout_size_bytes);
        let table_for_syscall = alloc(layout) as *mut MIB_IPFORWARDTABLE;
        (*table_for_syscall).dwNumEntries = 0; // Start with an empty table.
        let result = GetIpForwardTable(table_for_syscall, &mut layout_size_bytes, sorted);
        let actual_size = (*table_for_syscall).dwNumEntries;

        //let result = GetIpForwardTable(forward_table_buf.as_mut_ptr() as *mut windows::Win32::NetworkManagement::IpHelper::MIB_IPFORWARDTABLE, &mut pdw_size, sorted);
        println!("Call return val: {:?}", result);
        match result {
            0 => {
                println!("Success!");
                println!("Got MIB_IPFORWARDTABLE of size: {}", actual_size);
                let slice = std::slice::from_raw_parts_mut::<MIB_IPFORWARDROW>(addr_of_mut!((*table_for_syscall).table) as _, actual_size as usize);
                println!("slice size {:?}", slice.len());
                
                let rowsize = std::mem::size_of::<MIB_IPFORWARDROW>();
                println!("Row size in bytes {:?}", rowsize);
                println!("{:?}", std::slice::from_raw_parts_mut::<u8>(addr_of_mut!((*table_for_syscall).table) as _, (actual_size as usize) * rowsize )); // Cast this as a slice of u8's for the sake of debugging

                for row in slice {
                    println!("forward dest: {:?}", std::net::Ipv4Addr::from(u32::from_be(row.dwForwardDest)));
                    println!("forward mask: {:?}", std::net::Ipv4Addr::from(u32::from_be(row.dwForwardMask)));
                    println!("next hop: {:?}", std::net::Ipv4Addr::from(u32::from_be(row.dwForwardNextHop)));
                    println!("if index: {:?}", row.dwForwardIfIndex);
                    println!("metric1: {:?}\n", row.dwForwardMetric1);
                }
                
            },
            122 => println!("Required size reported: {:?}, have {:?}", layout_size_bytes, layout.size()),
            e => println!("Error, code is: {:?}", e),

        }
    };
    //drop(forward_table_buf); // drop for now, otherwise we get an access violation
}
*/

fn main_test() {
    routes::read_routes();

    let testroute = Route {
        destination: Ipv4Addr::new(192, 168, 1, 69),
        netmask: Ipv4Addr::new(255, 255, 255, 255),
        gateway: Ipv4Addr::new(192, 168, 1, 254), // BAD
        interface: 15, //BAAAAAD
        metric: 300, //BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD
    };

    routes::set_route(testroute);
}

fn main() {

    let route_table_lock: Arc<Mutex<Vec<Route>>> = Arc::new(Mutex::new(Vec::new()));
    let route_table_lock_for_thread = route_table_lock.clone();
    
    unsafe { SetConsoleCtrlHandler(Some(testhandle), true).ok() }.expect("Error setting our ctrl-c handler");

    // First thing, read our existing routes/dns and save them
    let original_dns = dns::read_dns();
    println!("Read dns record");
    match dns::save_dns_file(&original_dns) {
        Ok(_) => println!("backed up our dns to file"),
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
            println!("Unclean shutdown detected, dns file already exists, restoring and quitting");
            let dns = dns::read_dns_file().unwrap();
            dns::set_dns(dns);
            std::process::exit(1);
        }
        Err(e) => {
            println!("Some other error occured: {}", e);
            std::process::exit(1);
        }
    }
    println!("Saved dns file");

    let original_routes = routes::read_routes().expect("Failed to read routes");
    println!("Read our routes");
    for route in original_routes.iter() {
        println!("{:?}", route);
    }
    match routes::save_routes_file(&original_routes) {
        Ok(_) => println!("backed up our routes to file"),
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
            println!("Unclean shutdown detected, routes file already exists, restoring and quitting");
            let routes = routes::read_routes_file().unwrap();
            routes::set_routes(routes);
            std::process::exit(1);
        }
        Err(e) => {
            println!("Some other error occured: {}", e);
            std::process::exit(1);
        }
    }
    println!("Saved routes file");

    //routes::flush_routes();
    //println!("Flushed routing table");
    //std::thread::sleep_ms(10000);

    let mut child = Command::new("C:\\Users\\Dominic\\Desktop\\rust_projects\\nebula_client\\workdir\\nebula.exe")
        .args(["--config", "config.yml"])
        .current_dir("C:\\Users\\Dominic\\Desktop\\rust_projects\\nebula_client\\workdir")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn().expect("Failed to spawn child process");
    
    let cpid = child.id();

    // Spawn the thread that will listen to the output of nebula and act accordingly
    let handle = thread::spawn(move || { 
        //let mut child = neb_command.spawn().expect("Failed to spawn child process");
        let pid = child.id();
        println!("Spawned command with pid {}", pid);

        if let Some(stdout) = &mut child.stdout {
            // take the file handle
            let testhandle = stdout.as_raw_handle();
            //let mut reader = BufReader::new(stdout);
            let testfile = unsafe { std::fs::File::from_raw_handle(testhandle) };   
            let mut reader = BufReader::new(testfile);
            let mut buffer = String::new();
            loop {
                buffer.clear();
                match reader.by_ref().read_line(&mut buffer){
                    Ok(_) => {
                        match serde_json::from_str::<Map<String, Value>>(buffer.as_str()) {
                            //Ok(p) => println!("Parsed json\n{}", p),
                            Ok(p) => {
                                //println!("{:?}", p);
                                if let Some((action, route)) = neb_parse::parse_message(p) {
                                    println!("Returned route struct:\n{:?}", (action.clone(), route.clone()));
                                    // route table is shared outside thread, so we lock
                                    let mut route_table = route_table_lock_for_thread.lock().unwrap();
                                    process_route(action, route, &mut route_table);
                                    println!("Route table post mod:\n{:?}", route_table);
                                }
                            },
                            Err(e) => {
                                println!("Couldn't parse json: {:?}\nfrom string:\n{}", e, buffer);
                                println!("Probably EOF, dipping");
                                break;
                            },
                        }
                    },
                    Err(e) => println!("couldn't read: {:?}", e),
                }
                //std::thread::sleep_ms(100);
            }
            println!("Thread out of loop, it'll die");
            child.wait().expect("Error waiting for child in thread");
            println!("Successfully waited on nebula process");
        }
    });

    // Remove our original route after spawning nebula, otherwise it complains
    std::thread::sleep_ms(1000); // wait for nebula to get up to speed
    remove_routes(&original_routes);
    println!("Wiped original routes");

    // wipe our dns
    dns::clear_dns(original_dns.clone());
    println!("Wiped original dns");

    // set dns to network independent one
    dns::set_vpn_dns();
    println!("Set vpn dns");
    
    
    //println!("Sleeping before we kill");
    //std::thread::sleep_ms(60000);
    //kill_nebula_pid(cpid);
    
    //println!("Read buf: {}", buffer);
    println!("Waiting on our child pid...");
    match handle.join() {
        Ok(c) => println!("Exit success with code: {:?}", c),
        Err(e) => println!("Exit error with code (we want this): {:?}", e),
    }


    // Delete the routes we've added during our exection
    // route table is shared with the listening thread, so we lock
    {
        let route_table = route_table_lock.lock().unwrap();
        remove_routes(&route_table);
    }

    // Restore our original routing table and dns record
    println!("Setting dns back");
    // Read our dns file to make sure it matches and to ensure the file gets deleted
    let read_dns = dns::read_dns_file().unwrap();
    if original_dns != read_dns {
        println!("Something happened... our read routes don't match the original routes variable");
        println!("orig: {:?}\nread:{:?}", original_dns, read_dns);
        std::process::exit(1);
    }

    dns::set_dns(original_dns);

    println!("Setting routes back");
    // Read our routes file to make sure it matches and to ensure the file gets deleted
    let read_routes = routes::read_routes_file().unwrap();
    if original_routes != read_routes {
        println!("Something happened... our read routes don't match the original routes variable");
        println!("orig: {:?}\nread:{:?}", original_routes, read_routes);
        std::process::exit(1);
    }

    routes::set_routes(original_routes);

}


fn process_route(action: Action, route: Route, route_table: &mut Vec<Route>) {
    match action {
        Action::ADD => {
            if !route_table.contains(&route) {
                println!("Adding parsed route");
                set_route(route.clone());
                route_table.push(route);
            }
            else { println!("Parsed route already added") }
        }
        Action::REMOVE => {
            if route_table.contains(&route) {
                println!("Removing parsed route");
                remove_route(route.clone());
                route_table.retain(|r| r != &route);
            }
            else { println!("Parsed route already added") }
        }
    }
}

fn kill_nebula_pid(pid: u32) {
     // Clear ctrl-c handler
     match unsafe { SetConsoleCtrlHandler(None, true).ok() } {
        Ok(_) => println!("Set handler correctly"),
        Err(_) => println!("Error set handler"),
    };
    //child.kill().expect("Failed to kill kid");
    println!("Main process pid is {}, child pid is {}", std::process::id(), pid);

    //let ret = unsafe { GenerateConsoleCtrlEvent(0, pid).ok() };
    let ret = unsafe { GenerateConsoleCtrlEvent(0, pid).ok() };
    println!("Result of winapi call is: {:?}", ret);

    // Wait for our signal to propegate before we install the handler again (don't delete this, yes I know it's dumb)
    std::thread::sleep_ms(1);

    // restore handler
    match unsafe { SetConsoleCtrlHandler(None, false).ok() } {
    //match unsafe { SetConsoleCtrlHandler(Some(testhandle), false).ok() } {
        Ok(_) => println!("Cleared handler correctly"),
        Err(_) => println!("Error clearing handler"),
    };
}
