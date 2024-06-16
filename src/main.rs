use base64::engine::general_purpose;
use base64::Engine;
use regex::Regex;
use scraper::{Html, Selector};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Cli {
    /// The HTML file to process
    #[structopt(parse(from_os_str))]
    input: PathBuf,
    /// The Cloudflare _headers file to write to
    #[structopt(parse(from_os_str))]
    output: PathBuf,
}

fn main() -> io::Result<()> {
    let args = Cli::from_args();

    // Read the HTML file
    let mut file = File::open(&args.input)?;
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

    // Read the existing _headers file
    let mut output_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.output)?;
    let mut headers_content = String::new();
    output_file.read_to_string(&mut headers_content)?;

    // Find and update the CSP header
    let csp_re = Regex::new(r"(?i)Content-Security-Policy:[^\n]+").unwrap();
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

            // Keep valid existing hashes and add new ones
            let existing_hashes: Vec<&str> =
                existing_script_src.split_whitespace().skip(1).collect();
            let mut valid_hashes: Vec<String> = existing_hashes
                .into_iter()
                .filter(|hash| script_hashes.contains(&hash.to_string()))
                .map(|s| s.to_string())
                .collect();

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
                .filter(|hash| style_hashes.contains(&hash.to_string()))
                .map(|s| s.to_string())
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
            "\n\tContent-Security-Policy: script-src 'self' '{}'; style-src 'self' '{}';",
            script_hashes.join(" "),
            style_hashes.join(" ")
        );
        new_headers_content.push_str(&new_csp_header);
    }

    // Write the updated content to the _headers file
    let mut output_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&args.output)?;
    output_file.write_all(new_headers_content.as_bytes())?;

    Ok(())
}
