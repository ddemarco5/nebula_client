use std::process::{Command, Stdio};
use std::error::Error;
use std::fs::{File, OpenOptions};
use serde::{Serialize, Deserialize};
use std::io::{Write, Read};

use std::net::Ipv4Addr;

use windows::Win32::NetworkManagement::IpHelper::{
    MIB_IPFORWARDTABLE,
    MIB_IPFORWARDROW,
    MIB_IPFORWARDROW_0,
    MIB_IPFORWARDROW_1,
    MIB_IPROUTE_TYPE_DIRECT,
    GetIpForwardTable,
    CreateIpForwardEntry,
};
use windows::Win32::Networking::WinSock::MIB_IPPROTO_NETMGMT;
use std::alloc::{Layout, alloc};
use std::ptr::addr_of_mut;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Route {
    pub destination: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub interface: u32,
    pub metric: u32,
}

static FILENAME: &str = ".routes";

pub fn save_routes_file(routes: &Vec<Route>) -> std::io::Result<()> {
    // Create our file if it doesn't exist
    let file = OpenOptions::new().create_new(true).write(true).open(FILENAME)?;
    serde_yaml::to_writer(file, &routes).expect("Error writing to file");
    Ok(())
}

pub fn read_routes_file() -> std::io::Result<Vec<Route>> {
    let file = OpenOptions::new().read(true).write(false).create(false).open(FILENAME)?;
    let routes = serde_yaml::from_reader(file).expect("Unable to read from routes file");
    std::fs::remove_file(FILENAME)?;
    Ok(routes)
}

pub fn read_routes() -> Result<Vec<Route>, Box<dyn std::error::Error>> {

    let mut routes:Vec<Route> = Vec::new();
    let sorted = false;
    unsafe {
        let tablesize = 40; // Make a buffer with enough room for 40 routes, we shouldn't need more than this 
        let mut layout = Layout::new::<MIB_IPFORWARDTABLE>();
        let (l, _) = layout.extend(Layout::array::<MIB_IPFORWARDROW>(tablesize).expect("error declaring layout")).expect("Error extending layout");
        //layout = l;
        layout = l.pad_to_align();
        let mut layout_size_bytes = layout.size() as u32;
        println!("Allocated memory for table, bytes = {}", layout_size_bytes);
        let table_for_syscall = alloc(layout) as *mut MIB_IPFORWARDTABLE; // allocate memory we need to dealloc later
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
                
                // the 3 lines below are for debug output, uncomment if you want to see the actual layout in memory
                //let rowsize = std::mem::size_of::<MIB_IPFORWARDROW>();
                //println!("Row size in bytes {:?}", rowsize);
                //println!("{:?}", std::slice::from_raw_parts_mut::<u8>(addr_of_mut!((*table_for_syscall).table) as _, (actual_size as usize) * rowsize )); // Cast this as a slice of u8's for the sake of debugging
                for row in slice {
                    //println!("forward dest: {:?}", std::net::Ipv4Addr::from(u32::from_be(row.dwForwardDest)));
                    //println!("forward mask: {:?}", std::net::Ipv4Addr::from(u32::from_be(row.dwForwardMask)));
                    //println!("next hop: {:?}", std::net::Ipv4Addr::from(u32::from_be(row.dwForwardNextHop)));
                    //println!("if index: {:?}", row.dwForwardIfIndex);
                    //println!("metric1: {:?}\n", row.dwForwardMetric1);
                    routes.push(Route {
                        destination: Ipv4Addr::from(u32::from_be(row.dwForwardDest)),
                        netmask: Ipv4Addr::from(u32::from_be(row.dwForwardMask)),
                        gateway: Ipv4Addr::from(u32::from_be(row.dwForwardNextHop)),
                        interface: row.dwForwardIfIndex,
                        metric: row.dwForwardMetric1,
                    });
                }
                
            },
            122 => println!("Required size reported: {:?}, have {:?}", layout_size_bytes, layout.size()),
            e => panic!("Error, code is: {:?}", e),
        }
        // layouts need to be deallocated
        std::alloc::dealloc(table_for_syscall as *mut u8, layout);
    };
    println!("{:?}", routes);
    return Ok(routes);
}

/*
pub fn read_routes_old() -> Vec<Route> {
    let output = Command::new("route")
        //.current_dir("")
        .arg("print")
        .arg("0.0.0.0")
        //.args(["/C", "nebula.exe", "--config", "config.yml"])
        //.current_dir("C:\\Users\\Dominic\\Desktop\\rust_projects\\nebula_client\\workdir")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .output().expect("Failed to spawn child process (route print)");
    //println!("{}", String::from_utf8(output.stdout).unwrap());
    let outstring = String::from_utf8(output.stdout).unwrap();
    println!("cmd output: {}", outstring.clone());
    let splits: Vec<&str> = outstring.split("===========================================================================").collect();

    println!("Splitting the active routes string");

    // split the active routes
    let mut routes_vec:Vec<&str> = splits[3].lines().collect();
    
    // remove the headers
    routes_vec= Vec::from(&routes_vec[3 .. ]);

    let mut results_vec = Vec::<Route>::new();

    // split based on whitespace
    for element in routes_vec.iter() {
        let splitvec = element.split_whitespace().collect::<Vec<&str>>();
        results_vec.push(
            Route {
                destination: splitvec[0].to_string(),
                netmask: splitvec[1].to_string(),
                gateway: splitvec[2].to_string(),
                interface: splitvec[3].to_string(),
                metric: splitvec[4].to_string(),
            }
        );
    }

    return results_vec;
}
*/

/*
pub fn flush_routes() {
    let result =Command::new("route")
        .arg("-f")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .output().expect("Failed to spawn child process (route flush)");
    println!("cmd output: {}", String::from_utf8(result.stdout).unwrap());
}
*/

pub fn remove_route(route: Route) {
    remove_routes(&vec![route]);
}

pub fn remove_routes(routes: &Vec<Route>) {

    let mut result = Command::new("route");
    for route in routes {
        // example 
        // route ADD 8.8.8.8 MASK 255.255.255.0 0.0.0.0 IF 1 METRIC 69
        result.arg("DELETE");
        result.arg(route.destination.to_string().as_str());
        result.arg("MASK");
        result.arg(route.netmask.to_string().as_str());
        result.arg(route.gateway.to_string().as_str());
        result.stdout(Stdio::piped());
        result.stderr(Stdio::piped());
        result.stdin(Stdio::null());
        let output = result.output().expect("error running command (route add)");
        match output.status.code().unwrap() {
            0 => {
                println!("removed route: {}", route.destination)
            },
            something => {
                println!("Error executing command. Status: {}", something);
                println!("stderr: {}",String::from_utf8(output.stderr.clone()).unwrap());
            },
        }
        // print stderr anyway for now
        println!("stderr: {}",String::from_utf8(output.stderr).unwrap());
    }   
}

pub fn set_routes(routes: Vec<Route>) {
    for route in routes {
        set_route(route);
    }
}

pub fn set_route(route: Route) {

    println!("Trying to write route\n{:?}", route);


    let mut forward_row: MIB_IPFORWARDROW = MIB_IPFORWARDROW::default();
    forward_row.dwForwardDest = u32::from(route.destination).to_be();
    forward_row.dwForwardMask = u32::from(route.netmask).to_be();
    forward_row.dwForwardNextHop = u32::from(route.gateway).to_be();
    forward_row.dwForwardIfIndex = route.interface;
    forward_row.dwForwardMetric1 = route.metric;

    // Constants needed to make the syscall happy
    forward_row.Anonymous2 = MIB_IPFORWARDROW_1{ ForwardProto: MIB_IPPROTO_NETMGMT };
    let result = unsafe {
        // Debugging below, print the data we're passing as bytes
        //println!("{:?}", std::slice::from_raw_parts_mut::<u8>(addr_of_mut!(forward_row) as _, std::mem::size_of::<MIB_IPFORWARDROW>())); // Cast this as a slice of u8's for the sake of debugging
        CreateIpForwardEntry(&forward_row as *const MIB_IPFORWARDROW)
    };

    println!("result: {:?}", result);
}

pub fn set_routes_old(routes: Vec<Route>) {

    for route in routes {

        let mut args_vec: Vec<&str> = Vec::new();

        // example 
        // route ADD 8.8.8.8 MASK 255.255.255.0 0.0.0.0 IF 1 METRIC 69
        args_vec.push("ADD");
        let dest = route.destination.to_string();
        args_vec.push(dest.as_str());
        args_vec.push("MASK");
        let mask = route.netmask.to_string();
        args_vec.push(mask.as_str());
        // if gateway is set to "On-link", it needs to be 0.0.0.0 in the add command
        let gateway = route.gateway.to_string();
        if route.gateway.to_string().eq("On-link") {
            args_vec.push("0.0.0.0");
        } else {
            args_vec.push(gateway.as_str());
        }
        args_vec.push("IF");
        if route.interface.to_string().eq("127.0.0.1") {
            args_vec.push("1");
        }
        else {
            args_vec.push("15"); // TODO: DO NOT HARDCODE!!!!!!!!!!
        }
        // windows is a silly boy and the metric it commits is 25 more than the one you enter
        args_vec.push("METRIC");
        let metric_u32: u32 = route.metric;
        let answer_string = (metric_u32 - 25).to_string();
        args_vec.push(answer_string.as_str());

        let mut result = Command::new("route");
        result.args(args_vec);
        result.stdout(Stdio::piped());
        result.stderr(Stdio::piped());
        result.stdin(Stdio::null());
        let output = result.output().expect("error running command (route add)");

        match output.status.code().unwrap() {
            0 => println!("command executed successfully"),
            something => {
                println!("Error executing command. Status: {}", something);
                println!("stderr: {}",String::from_utf8(output.stderr.clone()).unwrap());
            },
        }
        println!("Added route {}", route.destination);
        println!("stdout: {}",String::from_utf8(output.stdout).unwrap());
        println!("stderr: {}",String::from_utf8(output.stderr).unwrap());
    }
}