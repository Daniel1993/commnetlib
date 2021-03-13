extern crate clap;

use clap::{Arg, App};

pub struct KeyManagerArgs {
    is_master : bool,
    target_dir : String,
}

pub fn parse_args() -> KeyManagerArgs {
    let input = App::new("key_manager")
        .version("0.1.0")
        .author("Daniel Castro")
        .about("Manages keys")
        .arg(Arg::with_name("is_master")
            .short("m")
            .long("master")
            .takes_value(false)
            .help("set this flag to create the top level key"))
        .arg(Arg::with_name("target_dir")
            .short("d")
            .long("dir")
            .takes_value(true)
            .help("set this flag to point the dir where to place the generated files"))
        .get_matches();

    let is_master = input.is_present("is_master");
    let target_dir = if input.is_present("target_dir") {
        input.value_of("target_dir")
    } else {
        None
    };
    return KeyManagerArgs {
        is_master,
        target_dir: String::from(if target_dir != None { target_dir.unwrap() } else { "" }),
    }
}
