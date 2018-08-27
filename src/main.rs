/*
 * Copyright 2018 Maya MacLean
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#[macro_use]
extern crate clap;
extern crate dialoguer;
extern crate indicatif;
extern crate rust_sodium;
extern crate sodium_stream;

use dialoguer::PasswordInput;
use indicatif::{ProgressBar, ProgressStyle};
use rust_sodium::{crypto::stream::xchacha20, randombytes, utils::memzero};
use sodium_stream::{xfile, util};
use std::{fs, io::prelude::*, io::SeekFrom};

fn set_secret(output: &str, hmac: &[u8], salt: &[u8]) {
    let mut out = fs::OpenOptions::new().write(true).open(output).expect("io err");
    out.seek(SeekFrom::Start(0)).expect("io err");
    out.write(&hmac[..]).expect("io err"); out.write(&salt[..]).expect("io err");
}

fn do_box(input: &str, threads: usize, max_mem: usize, max_argon: usize) {
    let output       = format!("{}.{}", input.split_at(input.rfind('.').unwrap()).0, "bin");
    let mut password = PasswordInput::new("Password").confirm("Confirm", "Mismatch").interact().expect("no password");
    let salt         = randombytes::randombytes(16);

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::default_spinner().template("{msg} {spinner}").tick_chars("☆ﾟ.*･｡ﾟ★"));
    spinner.enable_steady_tick(50);

    spinner.set_message("Checking password... ");
    let secret = util::secrets_from_argon(password.as_bytes(), &salt, &[], threads, max_argon).expect("argon err");
    memzero(unsafe { password.as_bytes_mut() } );
    spinner.set_message("Encrypting...");

    let key = xchacha20::Key::from_slice(&secret[..32]).expect("key err");
    let non = xchacha20::Nonce::from_slice(&secret[32..56]).expect("nonce err");
    let mac = &secret[56..];

    let hmac = xfile::encrypt_file(input, &output, &key, &non, threads, max_mem, mac);
    spinner.set_message("Tagging... ");
    set_secret(&output, &hmac[..], &salt[..]);
}

fn get_secret(input: &str) -> Vec<u8> {
    let mut f = fs::File::open(input).expect("io err");
    let mut b = [0;80];
    f.read(&mut b).expect("io err");
    b.to_vec()
}

fn do_unbox(input: &str, threads: usize, max_mem: usize, max_argon: usize) {
    let data         = get_secret(input);
    let mut password = PasswordInput::new("Password").confirm("Confirm", "Mismatch").interact().expect("no password");

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::default_spinner().template("{msg} {spinner}").tick_chars("☆ﾟ.*･｡ﾟ★"));
    spinner.enable_steady_tick(50);

    spinner.set_message("Checking password... ");
    let secret = util::secrets_from_argon(password.as_bytes(), &data[64..], &[], threads, max_argon).expect("argon err");
    memzero(unsafe { password.as_bytes_mut() } );
    spinner.set_message("Authenticating and decrypting... ");
    let output = format!("{}.{}", input.split_at(input.rfind('.').unwrap()).0, "out");

    let key = xchacha20::Key::from_slice(&secret[..32]).expect("key err");
    let non = xchacha20::Nonce::from_slice(&secret[32..56]).expect("nonce err");

    xfile::decrypt_file(input, &output, &key, &non, threads, max_mem, &data[..64], &secret[56..]);
}

fn main() {
    let config = clap_app!(obxr =>
                            (version: "0.1.0")
                            (author: "Maya MacLean <https://github.com/mayamaclean>")
                            (about: "\nplease note that thread and memory settings may affect authentication")
                            (@arg THREADS: -t --threads +takes_value "sets maximum worker threads (default: 4)")
                            (@arg MEMORY: -m --memory +takes_value "sets maximum buffer size in kb (default: 16 mb)")
                            (@arg ARGON: -a --argon +takes_value "sets memory usage for key derivation")
                            (@subcommand box =>
                                (about: "encrypts and tags")
                                (@arg INPUT: +required "no input!")
                            )
                            (@subcommand unbox =>
                                (about: "authenticates and decrypts")
                                (@arg INPUT: +required "no input!")
                            )
                        ).get_matches();

    let max_threads = config.value_of("THREADS").unwrap_or("4");

    let max_mem = config.value_of("MEMORY").unwrap_or("16384");

    let max_argon = config.value_of("ARGON").unwrap_or("131072");

    rust_sodium::init().expect("sodium error");

    if let Some(sub) = config.subcommand_matches("box") {
        do_box(sub.value_of("INPUT").unwrap(), max_threads.parse::<usize>().unwrap(), max_mem.parse::<usize>().unwrap()*1024, max_argon.parse::<usize>().unwrap());
    } else if let Some(sub) = config.subcommand_matches("unbox") {
        do_unbox(sub.value_of("INPUT").unwrap(), max_threads.parse::<usize>().unwrap(), max_mem.parse::<usize>().unwrap()*1024, max_argon.parse::<usize>().unwrap());
    } else {
        println!("no command!");
    }
}
