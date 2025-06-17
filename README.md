# Domain-Patrol 🛡️

A simple, fast, command-line tool for auditing the security hygiene of a list of domains. Created by Triage Security Labs.

`Domain-Patrol` quickly checks for essential security configurations, providing a clear report on email security records, web security headers, and best practices. It's designed for security researchers, system administrators, and blue teams to get a rapid overview of an organization's security posture.

---

### Features

- **Concurrent Scanning:** Uses threads to scan multiple domains quickly.
- **Email Security Check:** Verifies the presence of `SPF` and `DMARC` DNS records.
- **Web Security Check:**
  - Detects the `security.txt` file in accordance with RFC 9116.
  - Checks for the presence of key HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`).
- **Clean, Color-Coded Output:** Uses a clear table format for easy-to-read results.

---

### Installation

`Domain-Patrol` is a Python 3 tool.

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/TriageSecLabs/Domain-Patrol.git
    cd Domain-Patrol
    ```

2.  **Install the dependencies:**
    ```sh
    pip3 install -r requirements.txt
    ```

---

### Usage

1.  Create a text file (e.g., `domains.txt`) with the domains you want to scan, one per line.
    ```
    uber.com
    google.com
    github.com
    ```

2.  Run the tool and point it to your file.

    ```sh
    python3 domain_patrol.py -f domains.txt
    ```

#### Options

- `-f`, `--file`: (Required) Path to the file containing domains.
- `-t`, `--threads`: (Optional) Number of concurrent threads to use. Defaults to 5.
- `-v`, `--version`: Show the tool's version.
- `-h`, `--help`: Show the help message.

---

### Example Output

<blockquote class="imgur-embed-pub" lang="en" data-id="a/YTpLQ1w" data-context="false" ><a href="//imgur.com/a/YTpLQ1w"></a></blockquote><script async src="//s.imgur.com/min/embed.js" charset="utf-8"></script>

---

### Disclaimer

This tool is provided for educational and authorized security auditing purposes only. Do not use it for any illegal activity. The user is responsible for their own actions.

---

© Triage Security Labs
