use base64::engine::general_purpose;
use base64::Engine;
use glob::glob;
use regex::Regex;
use scraper::{Html, Selector};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use structopt::StructOpt;

// Declare a global AtomicBool for verbose mode
static VERBOSE_MODE: AtomicBool = AtomicBool::new(false);
static PROCESS_ALL: AtomicBool = AtomicBool::new(false);
static OVERWRITE: AtomicBool = AtomicBool::new(true);

trait AtomicBoolExt {
    fn read(&self) -> bool;
    fn write(&self, value: bool);
}

impl AtomicBoolExt for AtomicBool {
    fn read(&self) -> bool {
        self.load(Ordering::SeqCst)
    }

    fn write(&self, value: bool) {
        self.store(value, Ordering::SeqCst);
    }
}

/// A tool to generate Cloudflare _headers file with CSP hashes
#[derive(StructOpt, Debug)]
struct Cli {
    /// The Cloudflare _headers file to write to
    #[structopt(parse(from_os_str))]
    output: PathBuf,

    /// Verbose mode
    #[structopt(short, long)]
    verbose: bool,

    /// Optional: The directory to search for files in
    /// Defaults to the current directory
    #[structopt(parse(from_os_str), short, long)]
    directory: Option<PathBuf>,

    /// Optional: Process a single file
    #[structopt(parse(from_os_str), short, long, conflicts_with = "process-all-files")]
    // Fix this to kebab case, https://github.com/TeXitoi/structopt/issues/459
    file: Option<PathBuf>,

    /// Disable overwriting the _headers file
    #[structopt(short, long)]
    no_overwrite: bool,

    /// Process all files, disables the 100 000 file limit
    #[structopt(short, long)]
    process_all_files: bool,
}

const ALLOWED_FILES: [&str; 4] = ["html", "css", "js", "htm"];

fn main() -> io::Result<()> {
    let args = Cli::from_args();

    // Set the global verbose mode
    VERBOSE_MODE.write(args.verbose);
    PROCESS_ALL.write(args.process_all_files);
    OVERWRITE.write(!args.no_overwrite);

    if VERBOSE_MODE.read() {
        println!("{args:#?}");
    }
    let mut hashes: Hashes = Hashes {
        script_hashes: vec![],
        style_hashes: vec![],
    };

    // Change the working directory if specified
    if let Some(dir) = args.directory {
        std::env::set_current_dir(dir)?;
    }

    // Act if a single file is specified
    if args.file.is_some() {
        let file = args.file.unwrap();
        if VERBOSE_MODE.read() {
            println!("Processing single file: {file:#?}");
        }
        let ext = file.extension().unwrap_or_default().to_str().unwrap();
        if file.is_file() && ALLOWED_FILES.contains(&ext) {
            let file_hashes = process_file(&file, ext)?;
            hashes.push(file_hashes);
        }
        add_hashes(&args.output, hashes.script_hashes, hashes.style_hashes)?;
        process::exit(0);
    }

    // Process all files
    for (iteration_count, entry) in glob("**/*")
        .expect("Failed to read glob pattern")
        .enumerate()
    {
        if iteration_count >= 100_000 && !args.process_all_files {
            eprintln!("Too many files to process");
            process::exit(1);
        }
        match entry {
            Ok(path) => {
                // Check if the current path is the output file and skip it
                if path == args.output {
                    continue;
                }

                if VERBOSE_MODE.read() {
                    println!("Searching file: {path:#?}");
                }
                let ext = path.extension().unwrap_or_default().to_str().unwrap();
                if path.is_file() && ALLOWED_FILES.contains(&ext) {
                    if VERBOSE_MODE.read() {
                        println!("Processing file: {path:#?}");
                    }
                    let file_hashes = process_file(&path, ext)?;
                    hashes.push(file_hashes);
                }
            }
            Err(e) => eprintln!("{e:?}"),
        }
    }

    // Add the hashes to the _headers file
    if VERBOSE_MODE.read() {
        println!("Adding hashes to the _headers file");
        println!("{hashes:#?}");
    }

    add_hashes(&args.output, hashes.script_hashes, hashes.style_hashes)?;

    Ok(())
}

#[derive(Debug)]
struct Hashes {
    script_hashes: Vec<String>,
    style_hashes: Vec<String>,
}

fn process_file(input: &PathBuf, extension: &str) -> io::Result<Hashes> {
    println!("Processing file: {input:#?}");
    if extension == "html" || extension == "htm" {
        return process_html_file(input);
    } else if extension == "css" {
        return Ok(Hashes {
            script_hashes: vec![],
            style_hashes: vec![process_single_file(input)?],
        });
    } else if extension == "js" {
        return Ok(Hashes {
            script_hashes: vec![process_single_file(input)?],
            style_hashes: vec![],
        });
    }
    Ok(Hashes {
        script_hashes: vec![],
        style_hashes: vec![],
    })
}

fn process_html_file(input: &PathBuf) -> io::Result<Hashes> {
    // Read the HTML file
    let mut file = File::open(input)?;
    let mut html_content = String::new();
    file.read_to_string(&mut html_content)?;

    // Parse the HTML and generate CSP hashes
    let document = Html::parse_document(&html_content);
    let script_selector = Selector::parse("script").unwrap();
    let style_selector = Selector::parse("style").unwrap();

    let mut script_hashes = Vec::new();
    let mut style_hashes = Vec::new();

    for script in document.select(&script_selector) {
        if let Some(script_text) = script.text().next() {
            let hash = Sha256::digest(script_text.as_bytes());
            script_hashes.push(format!("sha256-{}", general_purpose::URL_SAFE.encode(hash)));
        }
    }

    for style in document.select(&style_selector) {
        if let Some(style_text) = style.text().next() {
            let hash = Sha256::digest(style_text.as_bytes());
            style_hashes.push(format!("sha256-{}", general_purpose::URL_SAFE.encode(hash)));
        }
    }
    Ok(Hashes {
        script_hashes,
        style_hashes,
    })
}

fn process_single_file(input: &PathBuf) -> io::Result<String> {
    // Read the CSS or JS file
    let mut file = File::open(input)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let hash = Sha256::digest(content.as_bytes());
    Ok(format!("sha256-{}", general_purpose::URL_SAFE.encode(hash)))
}

fn add_hashes(
    output: &PathBuf,
    script_hashes: Vec<String>,
    style_hashes: Vec<String>,
) -> io::Result<()> {
    // Read the existing _headers file
    let mut output_file = OpenOptions::new().read(true).write(true).open(output)?;
    let mut headers_content = String::new();
    output_file.read_to_string(&mut headers_content)?;

    // Find and update the CSP header
    let csp_re = Regex::new(r"(?i)Content-Security-Policy:[^\n]+").unwrap();
    if VERBOSE_MODE.read() {
        println!("{headers_content:#?}");
        println!(
            "Does the CSP header exist? {}",
            csp_re.is_match(&headers_content)
        );
    }
    let mut new_headers_content = headers_content.clone();

    if let Some(caps) = csp_re.captures(&headers_content) {
        let existing_csp = caps.get(0).unwrap().as_str();

        // Extract the script-src and style-src directives
        let script_re = Regex::new(r"script-src\s+[^;]*").unwrap();
        let style_re = Regex::new(r"style-src\s+[^;]*").unwrap();

        let mut new_csp = existing_csp.to_string();

        if let Some(script_caps) = script_re.captures(existing_csp) {
            let existing_script_src = script_caps.get(0).unwrap().as_str();
            let mut new_script_src = "script-src 'self'".to_string();

            // Keep valid existing hashes and add new ones (also checks if this hash has just been added by the program)

            let mut valid_hashes: Vec<String> = existing_script_src
                .split_whitespace()
                .skip(1)
                .filter(|hash| {
                    // Check if the OVERWRITE flag is set, if it is set (default value) it will
                    // overwrite existing (outdated) hashes, if not it will keep them
                    if OVERWRITE.read() {
                        script_hashes.contains(&(*hash).to_string())
                    } else {
                        true
                    }
                })
                .map(std::string::ToString::to_string)
                .collect();
            if VERBOSE_MODE.read() {
                println!("Script hashes: {valid_hashes:#?}");
            }

            for hash in &script_hashes {
                if !valid_hashes.contains(hash) {
                    valid_hashes.push(hash.clone());
                }
            }

            new_script_src.push_str(&format!(" '{}'", valid_hashes.join(" ")));
            new_csp = script_re
                .replace(&new_csp, new_script_src.as_str())
                .to_string();
        }

        if let Some(style_caps) = style_re.captures(existing_csp) {
            let existing_style_src = style_caps.get(0).unwrap().as_str();
            let mut new_style_src = "style-src 'self'".to_string();

            // Keep valid existing hashes and add new ones
            let existing_hashes: Vec<&str> =
                existing_style_src.split_whitespace().skip(1).collect();
            let mut valid_hashes: Vec<String> = existing_hashes
                .into_iter()
                .filter(|hash| style_hashes.contains(&(*hash).to_string()))
                .map(std::string::ToString::to_string)
                .collect();

            for hash in &style_hashes {
                if !valid_hashes.contains(hash) {
                    valid_hashes.push(hash.clone());
                }
            }

            new_style_src.push_str(&format!(" '{}'", valid_hashes.join(" ")));
            new_csp = style_re
                .replace(&new_csp, new_style_src.as_str())
                .to_string();
        }

        new_headers_content = csp_re
            .replace(&headers_content, new_csp.as_str())
            .to_string();
    } else {
        // Create a new CSP header if none exists
        let new_csp_header = format!(
            "/*\n\tContent-Security-Policy: script-src 'self' '{}'; style-src 'self' '{}';",
            script_hashes.join(" "),
            style_hashes.join(" ")
        );
        new_headers_content.push_str(&new_csp_header);
    }

    // Write the updated content to the _headers file
    let mut output_file = OpenOptions::new().write(true).truncate(true).open(output)?;
    output_file.write_all(new_headers_content.as_bytes())?;
    Ok(())
}

// impl push for hashes
impl Hashes {
    fn push(&mut self, others: Self) {
        self.script_hashes.extend(others.script_hashes);
        self.style_hashes.extend(others.style_hashes);
    }
}
