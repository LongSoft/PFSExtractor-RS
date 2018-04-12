//
// Parser
//
#[macro_use]
extern crate nom;
pub mod parser;

//
// Main
//
extern crate flate2;

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::error::Error;
use std::fs::DirBuilder;
use std::fs::OpenOptions;
use flate2::read::ZlibDecoder;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

fn main() {
    // Obtain program arguments
    let mut args = std::env::args_os();

    // Check if we have none
    if args.len() <= 1 {
        println!("
PFSExtractor v{} - extracts contents of Dell firmware update files in PFS format
Usage: pfsextractor pfs_file.bin", VERSION.unwrap_or("1.0.2"));
        std::process::exit(1);
    }
    
    // The only expected argument is a path to input file
    let arg = args.nth(1).expect("Failed to obtain file path");
    let path = Path::new(&arg);
    println!("Obtained file path: {:?}", path);
    
    // Open input file
    let mut file = match File::open(&path) {
        Err(e) => {println!("Can't open {:?}: {}", path, e.description()); std::process::exit(2);}
        Ok(f) => f
    };
    
    // Read the whole file as binary data
    let mut data = Vec::new();
    match file.read_to_end(&mut data) {
        Err(e) => {println!("Can't read {:?}: {}", path, e.description()); std::process::exit(3);}
        Ok(_) => {println!("Bytes read: 0x{:X}", &data.len());}
    }

    // Create directory for extracted components
    let mut new_arg = arg.clone();
    new_arg.push(".extracted");
    let dir = Path::new(&new_arg);
    match DirBuilder::new().create(&dir) {
        Err(e) => {println!("Can't create {:?}: {}", dir, e.description()); std::process::exit(4);}
        Ok(_) => {println!("Directory created: {:?}", &dir);}
    }
    
    // Set that created directory as current 
    match std::env::set_current_dir(&dir) {
        Err(e) => {println!("Can't change current directory: {}", e.description()); std::process::exit(5);}
        Ok(_) => {println!("Current directory changed")} 
    }

    // Call extraction function
    pfs_extract(&data, "");
}


fn write_file(data: &[u8], filename: &str) -> () {
    let mut file = OpenOptions::new().write(true)   
                             .create_new(true)
                             .open(filename)
                             .expect(&format!("Can't create file {:?}", filename));

    file.write(data).expect("Can't write data into file");
}


fn pfs_extract(data: &[u8], prefix: &str) -> () {
    match parser::pfs_file(data) {
        Ok((unp, mut file)) => {
            if unp.len() > 0 {
                println!("Unparsed size: {:X}", unp.len());
            }

            // Parse information section to obtain proper section names
            {
                // Information section is the last one
                let (info_section, other_sections) = (&mut file.sections).split_last_mut().unwrap();
                if info_section.data_size != 0 {
                    match parser::pfs_info(info_section.data.unwrap()) {
                        Ok((unp, info)) => {
                            if unp.len() > 0 {
                                println!("Unparsed size: {:X}", unp.len());
                            }

                            // Set section names
                            info_section.name = String::from("Section Info");
                            let mut i = 0;
                            for section in info {
                                if i < other_sections.len() {
                                    other_sections[i].name = section.name;
                                    i += 1;
                                }
                                else {
                                    break;
                                }
                            }
                            if i == other_sections.len() - 1 {
                                other_sections[i].name =  String::from("Model Properties");
                            }
                        }
                        _ => { println!("PFS info section parse error, falling back to generic names"); }
                    }
                }
            }

            let mut i = 0;
            for section in file.sections {
                println!("");
                i += 1;
                
                // Print infomation
                println!("GUID: {:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                        section.guid.data1,
                        section.guid.data2,
                        section.guid.data3,
                        section.guid.data4[0], section.guid.data4[1], section.guid.data4[2], section.guid.data4[3],
                        section.guid.data4[4], section.guid.data4[5], section.guid.data4[6], section.guid.data4[7]);
                println!("Header version: {:X}", section.header_version);
                println!("Data size: {:X}", section.data_size);
                println!("Data signature size: {:X}", section.data_sig_size);
                println!("Metadata size: {:X}", section.meta_size);
                println!("Metadata signature size: {:X}", section.meta_sig_size);
                
                // Print version
                let mut version = String::new();
                for j in 0..section.version_type.len() {
                    match section.version_type[j] {
                        0x41 => version.push_str(&format!("{:X}.", section.version[j])),
                        0x4E => version.push_str(&format!("{}.", section.version[j])),
                        0x20 | 0x00 => break,
                        t => {
                            println!("Unknown version type found: {:X}", t);
                            version.clear();
                            break;
                        }
                    }
                }
                if version.len() > 0 {
                    println!("Version: {}", version);
                }
                else {
                    version.push_str("0.");
                }
                
                // Save components into files
                if section.data_size == 0 {
                    continue;
                }
                let section_data = section.data.unwrap();

                let section_name = 
                if section.name.is_empty() {
                    format!("section_{}", i)
                } else {
                    format!("{}_{}", i, str::replace(&section.name, " ", "_"))
                };

                write_file(section_data, &format!("{}{}_{}data", prefix, section_name, version));
                
                if section.data_sig_size > 0 {
                    write_file(section.data_sig.unwrap(), &format!("{}{}_{}data.sig", prefix, section_name, version));
                }
                if section.meta_size > 0 {
                    write_file(section.meta.unwrap(), &format!("{}{}_{}meta", prefix, section_name, version));
                }
                if section.meta_sig_size > 0 {
                    write_file(section.meta_sig.unwrap(), &format!("{}{}_{}meta.sig", prefix, section_name, version));
                }

                // Check data to determine if and how it can be parsed further
                // Try parsing as PFS compressed section
                match parser::pfs_compressed_section(section_data) {
                    Ok((rest, comp)) => {
                        // This is a PFS compressed section
                        println!("PFS section type: zlib-compressed");
                        if rest.len() > 0 {
                            println!("Unparsed size: {:X}", rest.len());
                        }

                        // Decompress section data from Zlib-compressed data
                        let mut zlib_decoder = ZlibDecoder::new(comp.data);
                        let mut decompressed = Vec::new();
                        zlib_decoder.read_to_end(&mut decompressed).expect("Zlib decompression failed");

                        // Write decompressed data to a file
                        write_file(&decompressed, &format!("{}{}_{}decompressed", prefix, section_name, version));

                        // Extract decompressed data as PFS file
                        pfs_extract(&decompressed, &format!("{}{}_{}_", prefix, section_name, version));

                        // Continue iteration over sections
                        continue;
                    }
                    _ => ()
                }

                // Try parsing as PFS subsection
                match parser::pfs_file(section_data) {
                    Ok((rest, sub)) => {
                        // This is a PFS subsection
                        println!("PFS section type: subsection");
                        if rest.len() > 0 {
                            println!("Unparsed size: {:X}", rest.len());
                        }
                        
                        // Obtain chunks
                        let mut chunks = Vec::new();
                        for chunk in sub.sections {
                            if section.data_size == 0 {
                                continue;
                            }

                            match parser::pfs_chunk(chunk.data.unwrap()) {
                                Ok((_, ch)) => {
                                    chunks.push(ch);
                                }
                                _ => {
                                    chunks.clear();
                                    break;
                                }
                            }
                        }

                        // Construct and write payload
                        if chunks.len() > 0 {
                            // Sort the obtained chunks
                            chunks.sort();

                            // Combine sorted chunks into vector
                            let mut payload = Vec::new();
                            chunks.iter().for_each(|&x| payload.extend_from_slice(x.data));
                        
                            // Write payload to file
                            write_file(&payload, &format!("{}{}_{}data.payload", prefix, section_name, version));
                        }

                        // Continue iteration over sections
                        continue;
                    }
                    _ => ()
                }
            }
        }
        _ => { println!("PFS file parse error, this file can't be parsed"); }
    }
}
