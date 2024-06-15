# rust_generate_csp_hash
rust_hasher is a Rust application that reads an HTML file, generates Content Security Policy (CSP) hashes for script and style elements, and writes these hashes to a Cloudflare _headers file.

## Usage
The application takes two command-line arguments:

* The path to the HTML file to process.
* The path to the Cloudflare _headers file to write to.
Here is an example of how to use the application:
```bash
rust_generate_csp_hash index.html _headers
```

### Recommend Usage
This service was meant to run with Vite and (Vite single file)[https://github.com/richardtallent/vite-plugin-singlefile], which is where the entire `index.html` is generated from. So put this in your `package.json`:
```json
"build": "vite build && rust_generate_csp_hash dist/index.html dist/_headers"
```

## Install
To install the application, run the following command:
```bash
cargo install --git https://github.com/Hysterelius/Cloudflare-CSP-Hash-Gen
```
