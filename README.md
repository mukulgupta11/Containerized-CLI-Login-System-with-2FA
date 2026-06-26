# Secure Containerized CLI Login System with Optional 2FA

A highly secure command-line interface (CLI) registration and authentication application written in Go. The system operates on a client-database architecture inside Docker containers and incorporates cybersecurity best practices including cryptographic password hashing, brute-force lockout protection, sliding session timeouts, and Time-based One-Time Passwords (TOTP) compatible with Google Authenticator.

## 📌 Features

### 1. Authentication & Security
* **Secure Password Storage:** User passwords are hashed using `bcrypt` with a cost factor of `12` to prevent offline brute-force attacks in case of database leaks.
* **Brute-Force Lockout Protection:** Accounts are locked for 15 minutes after 5 consecutive failed login attempts (both parameters are configurable via environment variables). Side-channel timing attacks are mitigated by executing dummy bcrypt operations when users are not found.
* **Optional 2FA (TOTP):** Users can activate Google Authenticator-compatible Time-based One-Time Passwords (RFC 6238). Setting up 2FA renders a high-quality, scannable **ASCII QR Code** directly in the terminal along with a manual entry key.
* **Postgres-Backed Session Management:** Active sessions are tracked inside the database using secure 32-byte cryptographically random session tokens (64-character hex strings).
* **Configurable Sliding Timeout:** Sessions expire after 15 minutes of inactivity. Valid user activity on the CLI dynamically extends the session window.

### 2. Sleek Interactive CLI
* **Interactive Terminal Prompt:** Built with tab-completion and input history navigation (using up/down arrow keys).
* **Command Autocompletion:** Tab-completion matches commands dynamically based on whether you are logged in or out.
* **Masked Passwords:** Secure input masking for password entry during registration, login, and 2FA disablement.
* **Colorized Output:** Clear visual cues using cyan/green/yellow/red styling for success, logs, and error responses.

---

## 🛠 Project Architecture

```
├── cmd/
│   └── cli/
│       └── main.go           # Application Entry Point
├── internal/
│   ├── config/
│   │   └── config.go         # Configuration parsing
│   ├── db/
│   │   └── db.go             # DB connection pool & Schema Auto-migration
│   ├── models/
│   │   └── models.go         # User and Session database structs
│   ├── auth/
│   │   └── service.go        # Secure Registration, Auth, Lockout, and Session logic
│   ├── totp/
│   │   └── totp.go           # Secret Generation, Verification, & ASCII QR Code rendering
│   └── cli/
│       └── shell.go          # Interactive Readline Shell loop & commands routing
├── Dockerfile                # Multi-stage secure runner container
├── docker-compose.yml        # Orchestration containing app & Postgres containers
└── README.md
```

---

## 🚀 Quick Start (Running in Docker)

To run this application, you only need **Docker** and **Docker Compose** installed on your host system.

### Step 1: Spin up the PostgreSQL Database
Before starting the interactive CLI, run the database in the background:
```bash
docker compose up -d db
```
The database will execute health checks until it is fully ready to accept connections. You can check the health status via:
```bash
docker compose ps
```

### Step 2: Run the Interactive CLI App
Once the database container is healthy, run the CLI application container in interactive TTY mode:
```bash
docker compose run --rm cli
```
*Note: We use `run --rm` to ensure that standard input (`stdin`) and terminal allocation (`tty`) are routed directly to your shell, letting you use features like tab completion and history.*

---

## 📖 CLI Commands Guide

### Unauthenticated Commands (Before Login)
Upon booting up the shell, you will see the `osto-secure>` prompt.
* `register`: Creates a new account. Prompts for a username and password.
  * *Security Note: The password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.*
* `login`: Logs you in. Prompts for username and password. If TOTP 2FA is active, it prompts for your 6-digit TOTP token.
* `help`: Lists all unauthenticated commands.
* `exit`: Safely terminates the CLI shell.

### Authenticated Commands (After Login)
Once logged in, the prompt changes to `[username] osto-secure>`.
* `whoami`: Displays details of the current session:
  * Username
  * Registration date
  * 2FA Status (Enabled / Disabled)
  * Current session expiration time
  * Last login time (if available)
* `enable-2fa`: Displays a terminal-friendly **ASCII QR Code** and a manual setup key. Scan this with Google Authenticator or a similar authenticator app, and verify with a 6-digit code to enable 2FA.
* `disable-2fa`: Disables 2FA. Requires you to type in your account password to confirm.
* `logout`: Logs you out, destroys your database session record, and returns you to the unauthenticated prompt.
* `help`: Lists all authenticated commands.
* `exit`: Destroys your session and quits the program.

---

## ⚙️ Configuration Variables

You can customize the application behaviour in the `environment:` section of the `cli` service in [docker-compose.yml](file:///d:/osto_go_backend/docker-compose.yml):

| Environment Variable | Description | Default Value |
| --- | --- | --- |
| `SESSION_TIMEOUT_MINUTES` | Minutes of inactivity before a session expires (sliding window) | `15` |
| `LOCKOUT_ATTEMPTS` | Number of consecutive failed attempts allowed before lockout | `5` |
| `LOCKOUT_DURATION_MINUTES` | Lockout duration in minutes for locked accounts | `15` |
| `DB_HOST` | Hostname of the Postgres container | `db` |
| `DB_PORT` | Port of the Postgres container | `5432` |
| `DB_USER` | Postgres user | `postgres` |
| `DB_PASSWORD` | Postgres password | `postgres_secure_pass` |
| `DB_NAME` | Postgres database name | `cli_login_db` |
| `DB_SSLMODE` | Postgres SSL mode configuration | `disable` |

---

## 🧪 Running Unit & Integration Tests

The project includes a robust test suite in `internal/auth/service_test.go` and `internal/totp/totp_test.go` verifying core auth logic, brute-force lockouts, sliding session timeouts, password strength validation, and TOTP key creation.

To run the unit tests inside the Go builder container:
```bash
docker compose run --entrypoint "go test -v ./..." cli
```
This command spins up the dependencies, sets the DB environment parameters, runs the test runner, and prints the result.
