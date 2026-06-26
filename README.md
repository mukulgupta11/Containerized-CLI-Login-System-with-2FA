# Secure Containerized CLI Login System with Optional 2FA

A robust, highly secure, command-line interface (CLI) registration and authentication application written in Go. The system operates on a client-database architecture inside Docker containers and incorporates modern cybersecurity best practices. It features cryptographic password hashing, brute-force lockout protection, sliding session timeouts, and Time-based One-Time Passwords (TOTP) compatible with Google Authenticator.

This project demonstrates professional software engineering principles, emphasizing modular design, security-first architecture, and comprehensive containerization.

---

## Comprehensive Feature List

### 1. Advanced Authentication & Security Measures
* **Cryptographic Password Storage:** User passwords are not stored in plaintext. They are hashed using `bcrypt` with a work factor (cost) of `12`. This intentionally slow hashing algorithm prevents offline brute-force attacks in the event of a database leak.
* **Brute-Force Lockout Protection:** The system tracks consecutive failed login attempts. After a configurable threshold (default: 5 attempts), the account is locked for a specific duration (default: 15 minutes). 
* **Timing Attack Mitigation:** To prevent malicious actors from enumerating valid usernames through response time analysis, the authentication service executes dummy bcrypt operations when a login is attempted for an unrecognized username. This ensures the authentication request takes the same amount of time regardless of whether the user exists.
* **Enforced Password Complexity:** Registration enforces strict password policies requiring a minimum of 8 characters, including at least one uppercase letter, one lowercase letter, one numeric digit, and one special character.
* **Secure Session Management:** Rather than using stateless JWTs (which cannot be revoked instantly), the application uses stateful, database-backed sessions. Sessions use secure 32-byte cryptographically random session tokens (represented as 64-character hex strings).
* **Configurable Sliding Session Timeouts:** Sessions expire after a period of inactivity (default: 15 minutes). Every valid user action within the CLI dynamically extends the session window, ensuring active users remain logged in while idle sessions are automatically terminated.

### 2. Time-Based One-Time Passwords (TOTP / 2FA)
* **RFC 6238 Compliant:** The application implements standard TOTP logic, making it fully compatible with major authenticator apps like Google Authenticator, Authy, and Duo.
* **Terminal ASCII QR Code Rendering:** Upon enabling 2FA, the system dynamically generates a secure base32 secret and renders an interactive, scannable ASCII QR Code directly in the user's terminal, bypassing the need for a web browser or external image viewer.
* **Secure Fallback Key:** A manual entry key is provided alongside the QR code for users who cannot scan it.
* **Strict Verification:** Disabling 2FA requires the user to re-authenticate with their password, preventing an attacker who gains access to an unlocked terminal session from disabling security measures.

### 3. Professional Interactive CLI Interface
* **Interactive Terminal Environment:** Built on top of the robust `readline` library, providing a seamless shell-like experience. It supports up/down arrow keys for command history navigation.
* **Context-Aware Autocompletion:** Tab-completion is dynamically aware of the user's state. Unauthenticated users receive autocompletion for `login` and `register`, while authenticated users receive suggestions for `whoami`, `enable-2fa`, etc.
* **Masked Password Input:** Password prompts (during registration, login, and 2FA disablement) use secure terminal masking. User keystrokes are hidden from the screen to prevent shoulder-surfing.
* **Color-Coded Status Output:** Terminal responses utilize cyan, green, yellow, and red color formatting to provide clear visual cues for success, general information, warnings, and critical errors.

---

## Project Architecture & Directory Structure

The repository follows standard Go project layout conventions, separating the application into distinct, focused packages:

```
├── cmd/
│   └── cli/
│       └── main.go           # Application Entry Point: Wires dependencies and boots the shell
├── internal/
│   ├── config/
│   │   └── config.go         # Configuration parsing: Reads and parses environment variables
│   ├── db/
│   │   └── db.go             # Database connection pool, Postgres driver setup, and schema auto-migration
│   ├── models/
│   │   └── models.go         # GORM database structs for Users and Sessions
│   ├── auth/
│   │   └── service.go        # Secure Registration, Auth logic, Lockout states, and Session management
│   ├── totp/
│   │   └── totp.go           # Secret Generation, Verification, & ASCII QR Code rendering logic
│   └── cli/
│       └── shell.go          # Interactive Readline Shell loop, command routing, and state tracking
├── Dockerfile                # Multi-stage secure Go builder container
├── docker-compose.yml        # Orchestration containing application & PostgreSQL containers
└── README.md
```

---

## Quick Start Guide (Docker)

To run this application, you must have **Docker** and **Docker Compose** installed on your host system. The entire environment is containerized, meaning you do not need Go or PostgreSQL installed locally.

### Step 1: Spin up the PostgreSQL Database
Before starting the interactive CLI, boot the database in the background:
```bash
docker compose up -d db
```
The database container is configured with internal health checks. It will prepare the schema and accept connections once healthy. You can verify its status by running `docker compose ps`.

### Step 2: Launch the Interactive CLI Client
Once the database container is running, launch the CLI application container in interactive TTY mode:
```bash
docker compose run --rm cli
```
*Note: The `--rm` flag ensures the container is cleaned up after you exit. `run` routes standard input (`stdin`) and terminal allocation (`tty`) directly to your shell, allowing features like tab completion and masked passwords to work perfectly.*

---

## Comprehensive Command Reference

### Unauthenticated Commands (Pre-Login)
Upon booting up the shell, you will be greeted with the `osto-secure>` prompt.

* `register`
  * **Description:** Initiates the account creation workflow. 
  * **Input:** Prompts for a username, a secure password, and a password confirmation.
* `login`
  * **Description:** Authenticates an existing user.
  * **Input:** Prompts for username and password. If the user has 2FA enabled, an additional prompt for a 6-digit TOTP token will appear.
* `help`
  * **Description:** Lists all available unauthenticated commands.
* `exit`
  * **Description:** Safely terminates the CLI shell and exits the container.

### Authenticated Commands (Post-Login)
Once logged in, your prompt will change dynamically to `[your_username] osto-secure>`.

* `whoami`
  * **Description:** Displays detailed information regarding the current active session.
  * **Output:** Shows Username, Account Registration Date, 2FA Status, Current Session Expiration Time, and Last Login Time.
* `enable-2fa`
  * **Description:** Initiates the Two-Factor Authentication setup process.
  * **Action:** Generates a secure secret, displays a scannable ASCII QR Code, provides the manual text key, and asks for a verification code to finalize activation.
* `disable-2fa`
  * **Description:** Deactivates Two-Factor Authentication.
  * **Action:** Prompts the user to re-enter their account password to confirm the deactivation, adding an extra layer of security.
* `logout`
  * **Description:** Securely terminates the current session.
  * **Action:** Destroys the database session record immediately, rendering the session token invalid, and returns the user to the unauthenticated prompt.
* `help`
  * **Description:** Lists all available authenticated commands.
* `exit`
  * **Description:** Automatically logs the user out, destroys the session, and exits the application.

---

## Configuration & Environment Variables

The application is highly configurable via the `environment:` block in the `cli` service defined within `docker-compose.yml`.

| Environment Variable | Description | Default Value |
| --- | --- | --- |
| `SESSION_TIMEOUT_MINUTES` | Minutes of inactivity before a session expires (sliding window) | `15` |
| `LOCKOUT_ATTEMPTS` | Number of consecutive failed attempts allowed before an account is locked | `5` |
| `LOCKOUT_DURATION_MINUTES` | Duration (in minutes) that a locked account remains inaccessible | `15` |
| `DB_HOST` | Hostname of the Postgres container within the Docker network | `db` |
| `DB_PORT` | Port of the Postgres container | `5432` |
| `DB_USER` | Postgres administrative user | `postgres` |
| `DB_PASSWORD` | Postgres administrative password | `postgres_secure_pass` |
| `DB_NAME` | Target Postgres database name | `cli_login_db` |
| `DB_SSLMODE` | Postgres SSL mode configuration | `disable` |

---

## Automated Testing Suite

The repository includes a comprehensive, automated test suite located within `internal/auth/service_test.go` and `internal/totp/totp_test.go`.

**Test Coverage Includes:**
1. Successful registration and password complexity validation.
2. Successful login flows (both standard and TOTP-required).
3. Brute-force lockout enforcement (simulating multiple failed attempts and verifying the lockout duration).
4. Sliding session timeout logic (verifying tokens expire and extend correctly).
5. TOTP secret generation, QR code formatting, and token verification accuracy.

**To run the test suite inside the isolated Docker build environment:**
```bash
docker compose run --entrypoint "go test -v ./..." cli
```
This command mounts the code, resolves dependencies, links to the running PostgreSQL database, and executes the Go test runner, printing verbose success/failure metrics to the terminal.
