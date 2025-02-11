# Honeypot-Suite

## Description
Honeypot-Suite is a modular Python-based tool that simulates multiple network protocols (HTTPS, DNS, SSH, FTP, PostgreSQL) to attract and analyze malicious activities.

---

## Features
- Simulates **HTTPS**, **DNS**, **SSH**, **FTP**, and **PostgreSQL** services.
- Real-time logging of interactions with attackers.
- Customizable configurations for each protocol.
- Centralized GUI (`menu.py`) for easy management.
- Automatically generates self-signed SSL/TLS certificates for secure simulations.

---

## Installation

### Prerequisites
Ensure you have the following installed on your system:
- Python 3.8 or higher
- Pip (Python package installer)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/Diogo-Lages/Honeypot-Suite.git
   cd Honeypot-Suite
   ```

2. Install dependencies:
   ```bash
   pip install twisted cryptography bcrypt tksupport beautifulsoup4 requests dnspython pyftpdlib asyncpg
   ```

3. Run the centralized management GUI:
   ```bash
   python menu.py
   ```

---

## Usage

### Starting a Honeypot
1. Open the `menu.py` GUI.
2. Select a protocol (e.g., DNS, SSH).
3. Configure settings such as host, port, and additional parameters.
4. Click **"Start Honeypot"** to begin monitoring.

### Stopping a Honeypot
- Click **"Stop Honeypot"** in the GUI.
- Alternatively, terminate the Python process running the honeypot script.

---

## Requirements
- Python 3.8+
- Required Libraries:
  - `twisted`: Event-driven networking engine.
  - `cryptography`: For generating SSL/TLS certificates.
  - `bcrypt`: Password hashing for SSH.
  - `tksupport`: Integrates Twisted with Tkinter for the GUI.
  - `beautifulsoup4`: For parsing and modifying HTML content (HTTPS honeypot).
  - `requests`: For downloading resources (HTTPS honeypot).
  - `dnspython`: For DNS query handling.
  - `pyftpdlib`: For simulating FTP services.
  - `asyncpg`: For simulating PostgreSQL databases.

---

## Directory Structure
```
Honeypot-Suite/
├── https_honeypot.py       # HTTPS honeypot implementation
├── dns_honeypot.py         # DNS honeypot implementation
├── ssh_honeypot.py         # SSH honeypot implementation
├── ftp_honeypot.py         # FTP honeypot implementation
├── postgresql_honeypot.py  # PostgreSQL honeypot implementation
├── menu.py                 # Centralized GUI for managing honeypots
└── README.md               # Project documentation
```

---

## Example Output

#### DNS Honeypot Log:
```
[2023-10-15 12:34:56] DNS Query Received - Query Name: example.com, Type: A, Class: IN, From: ('192.168.1.100', 5353)
```

#### SSH Honeypot Log:
```
[2023-10-15 12:35:00] Login attempt - Username: admin, Password: password123
```

---

## Limitations
- Only one honeypot can run at a time due to Twisted's reactor limitations.
- Logs are stored locally and may require manual analysis.
- Simulated services provide basic functionality and may not fully replicate real-world scenarios.

---

## Ethical Considerations
- Deploy honeypots only in environments where you have explicit permission.
- Avoid logging sensitive information from legitimate users.
- Ensure compliance with local laws and regulations regarding data collection.

---

## Contributing
 Contributions are welcome! To contribute:
 1. Fork the repository.
 2. Create a new branch for your changes.
 3. Submit a pull request with detailed descriptions of your updates.



