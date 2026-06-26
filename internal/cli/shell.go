package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/osto-cybersecurity/cli-login/internal/auth"
	"github.com/osto-cybersecurity/cli-login/internal/models"
	"github.com/osto-cybersecurity/cli-login/internal/totp"
)

type Shell struct {
	authService  *auth.AuthService
	sessionToken string
	currentUser  *models.User
}

func NewShell(authService *auth.AuthService) *Shell {
	return &Shell{
		authService: authService,
	}
}

// stateCompleter implements readline.AutoCompleter dynamically based on login state
type stateCompleter struct {
	shell *Shell
}

func (c *stateCompleter) Do(line []rune, pos int) ([][]rune, int) {
	var options []string
	if c.shell.sessionToken == "" {
		options = []string{"register", "login", "help", "exit"}
	} else {
		options = []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help", "exit"}
	}

	lineStr := string(line)
	// We only complete the first word
	if strings.Contains(lineStr, " ") {
		return nil, 0
	}

	var matches [][]rune
	for _, opt := range options {
		if strings.HasPrefix(opt, lineStr) {
			matches = append(matches, []rune(opt[len(lineStr):]))
		}
	}
	return matches, len(lineStr)
}

// PrintBanner outputs a professional startup banner
func (s *Shell) PrintBanner() {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	white := color.New(color.FgWhite)

	cyan.Println("┌────────────────────────────────────────────────────────┐")
	cyan.Println("│             OSTO CYBERSECURITY SECURE CLI              │")
	cyan.Println("└────────────────────────────────────────────────────────┘")
	white.Print("  Version: ")
	green.Print("1.0.0")
	white.Print(" | Engine: ")
	green.Println("Go 1.21")
	white.Println("  Type 'help' to view available commands. Press Tab for completion.")
	fmt.Println()
}

// Run starts the readline interactive shell loop
func (s *Shell) Run() {
	s.PrintBanner()

	// Configure readline
	config := &readline.Config{
		Prompt:          s.getPrompt(),
		AutoComplete:    &stateCompleter{shell: s},
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	}

	rl, err := readline.NewEx(config)
	if err != nil {
		fmt.Printf("Error initializing terminal shell: %v\n", err)
		return
	}
	defer rl.Close()

	for {
		// Periodically refresh the prompt to show current username if state changed
		rl.SetPrompt(s.getPrompt())

		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				if len(line) == 0 {
					color.Green("Exiting session securely. Goodbye!")
					break
				}
				continue
			} else if err == io.EOF {
				color.Green("EOF received. Exiting securely. Goodbye!")
				break
			}
			color.Red("Readline error: %v", err)
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Verify session before executing ANY command if logged in.
		// If verification fails, session is cleared automatically.
		if s.sessionToken != "" {
			_, user, err := s.authService.VerifySession(s.sessionToken)
			if err != nil {
				color.Red("\n[Session Expired] You have been logged out due to inactivity.")
				s.sessionToken = ""
				s.currentUser = nil
				rl.SetPrompt(s.getPrompt())
				// If the command is a restricted one, skip execution
				fields := strings.Fields(line)
				if len(fields) > 0 && s.isRestrictedCommand(fields[0]) {
					continue
				}
			} else {
				// Update current cached user info
				s.currentUser = user
			}
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		cmd := strings.ToLower(fields[0])

		if s.sessionToken == "" {
			s.handleBeforeLogin(cmd, rl)
		} else {
			s.handleAfterLogin(cmd, rl)
		}
	}
}

func (s *Shell) getPrompt() string {
	if s.currentUser != nil {
		return fmt.Sprintf("\033[32m[%s]\033[0m \033[36mosto-secure>\033[0m ", s.currentUser.Username)
	}
	return "\033[36mosto-secure>\033[0m "
}

func (s *Shell) isRestrictedCommand(cmd string) bool {
	restricted := map[string]bool{
		"whoami":      true,
		"enable-2fa":  true,
		"disable-2fa": true,
		"logout":      true,
	}
	return restricted[cmd]
}

func (s *Shell) handleBeforeLogin(cmd string, rl *readline.Instance) {
	switch cmd {
	case "register":
		s.cmdRegister(rl)
	case "login":
		s.cmdLogin(rl)
	case "help":
		s.printHelpBefore()
	case "exit":
		color.Green("Exiting securely. Goodbye!")
		rl.Close()
		// Exit the process
		panic(nil) // Handled in main.go recovery or let it exit naturally.
	default:
		color.Red("Unknown command: %q. Type 'help' for options.", cmd)
	}
}

func (s *Shell) handleAfterLogin(cmd string, rl *readline.Instance) {
	switch cmd {
	case "whoami":
		s.cmdWhoami()
	case "enable-2fa":
		s.cmdEnable2FA(rl)
	case "disable-2fa":
		s.cmdDisable2FA(rl)
	case "logout":
		s.cmdLogout()
	case "help":
		s.printHelpAfter()
	case "exit":
		s.cmdLogout()
		color.Green("Logged out and exiting. Goodbye!")
		rl.Close()
		panic(nil)
	default:
		color.Red("Unknown command: %q. Type 'help' for options.", cmd)
	}
}

func (s *Shell) printHelpBefore() {
	color.Cyan("Available Commands (Unauthenticated):")
	fmt.Println("  register     Create a new user account")
	fmt.Println("  login        Login to your account (requests TOTP code if enabled)")
	fmt.Println("  help         Show this command list")
	fmt.Println("  exit         Quit the program")
}

func (s *Shell) printHelpAfter() {
	color.Cyan("Available Commands (Authenticated):")
	fmt.Println("  whoami       Display details of the currently logged in user")
	fmt.Println("  enable-2fa   Set up and activate TOTP-based 2FA")
	fmt.Println("  disable-2fa  Deactivate 2FA (requires password validation)")
	fmt.Println("  logout       Terminate your active session")
	fmt.Println("  help         Show this command list")
	fmt.Println("  exit         Securely logout and quit the program")
}

func (s *Shell) cmdRegister(rl *readline.Instance) {
	fmt.Print("Enter Username: ")
	usernameLine, err := rl.Readline()
	if err != nil {
		return
	}
	username := strings.TrimSpace(usernameLine)
	if username == "" {
		color.Red("[Error] Username cannot be empty")
		return
	}

	passBytes, err := rl.ReadPassword("Enter Password: ")
	if err != nil {
		return
	}
	password := string(passBytes)

	confirmBytes, err := rl.ReadPassword("Confirm Password: ")
	if err != nil {
		return
	}
	confirm := string(confirmBytes)

	if password != confirm {
		color.Red("[Error] Passwords do not match")
		return
	}

	user, err := s.authService.Register(username, password)
	if err != nil {
		color.Red("[Error] Registration failed: %v", err)
		return
	}

	color.Green("[Success] User %s registered successfully! You can now login.", user.Username)
}

func (s *Shell) cmdLogin(rl *readline.Instance) {
	fmt.Print("Enter Username: ")
	usernameLine, err := rl.Readline()
	if err != nil {
		return
	}
	username := strings.TrimSpace(usernameLine)
	if username == "" {
		color.Red("[Error] Username cannot be empty")
		return
	}

	passBytes, err := rl.ReadPassword("Enter Password: ")
	if err != nil {
		return
	}
	password := string(passBytes)

	// Attempt login without TOTP first
	session, user, err := s.authService.Login(username, password, "")
	if err != nil {
		// If it's a 2FA required prompt, ask for the code
		if err == auth.ErrTOTPRequired {
			fmt.Print("Enter 2FA TOTP Code (6 digits): ")
			codeLine, err := rl.Readline()
			if err != nil {
				return
			}
			code := strings.TrimSpace(codeLine)

			session, user, err = s.authService.Login(username, password, code)
			if err != nil {
				color.Red("[Error] Login failed: %v", err)
				return
			}
		} else {
			color.Red("[Error] Login failed: %v", err)
			return
		}
	}

	s.sessionToken = session.ID
	s.currentUser = user

	color.Green("[Success] Login successful! Welcome back, %s.", user.Username)
	fmt.Println()
	s.displayUserDetails(session, user)
}

func (s *Shell) cmdWhoami() {
	if s.sessionToken == "" || s.currentUser == nil {
		color.Red("[Error] You are not logged in.")
		return
	}

	// We fetch a fresh session state to show correct current expiration time
	session, user, err := s.authService.VerifySession(s.sessionToken)
	if err != nil {
		color.Red("[Error] Failed to retrieve current session: %v", err)
		return
	}

	s.displayUserDetails(session, user)
}

func (s *Shell) displayUserDetails(session *models.Session, user *models.User) {
	yellow := color.New(color.FgYellow)
	white := color.New(color.FgWhite)

	yellow.Println("┌──────────────── User Information ────────────────┐")
	fmt.Printf("  %-22s : ", "Username")
	white.Println(user.Username)
	fmt.Printf("  %-22s : ", "Registration Date")
	white.Println(user.CreatedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("  %-22s : ", "2FA Status")
	if user.TOTPEnabled {
		color.Green("Enabled")
	} else {
		color.Red("Disabled")
	}

	fmt.Printf("  %-22s : ", "Session Expiration")
	white.Println(session.ExpiresAt.Format("2006-01-02 15:04:05 MST"))

	fmt.Printf("  %-22s : ", "Last Login Time")
	if user.LastLoginAt != nil {
		white.Println(user.LastLoginAt.Format("2006-01-02 15:04:05 MST"))
	} else {
		white.Println("N/A")
	}
	yellow.Println("└──────────────────────────────────────────────────┘")
}

func (s *Shell) cmdEnable2FA(rl *readline.Instance) {
	if s.currentUser.TOTPEnabled {
		color.Yellow("[Info] 2FA is already enabled for your account.")
		return
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		color.Red("[Error] Failed to generate 2FA secret: %v", err)
		return
	}

	uri := totp.GenerateURI(s.currentUser.Username, secret)
	qrCode, err := totp.GenerateASCIIQRCode(uri)
	if err != nil {
		color.Red("[Error] Failed to generate QR code: %v", err)
		return
	}

	color.Cyan("\n--- Two-Factor Authentication Setup ---")
	fmt.Println("Scan the following QR code using Google Authenticator, Duo, or any TOTP app:")
	fmt.Println()
	fmt.Print(qrCode)
	fmt.Println()
	fmt.Printf("Manual Secret Key: %s\n", secret)
	fmt.Println()

	fmt.Print("Enter verification code from your TOTP app to activate: ")
	codeLine, err := rl.Readline()
	if err != nil {
		return
	}
	code := strings.TrimSpace(codeLine)

	err = s.authService.Enable2FA(s.currentUser.ID, secret, code)
	if err != nil {
		color.Red("[Error] Failed to enable 2FA: %v", err)
		return
	}

	s.currentUser.TOTPEnabled = true
	color.Green("[Success] Two-Factor Authentication (2FA) is now ENABLED!")
}

func (s *Shell) cmdDisable2FA(rl *readline.Instance) {
	if !s.currentUser.TOTPEnabled {
		color.Yellow("[Info] 2FA is not enabled.")
		return
	}

	passBytes, err := rl.ReadPassword("Enter your Password to confirm disabling 2FA: ")
	if err != nil {
		return
	}
	password := string(passBytes)

	err = s.authService.Disable2FA(s.currentUser.ID, password)
	if err != nil {
		color.Red("[Error] Failed to disable 2FA: %v", err)
		return
	}

	s.currentUser.TOTPEnabled = false
	color.Green("[Success] Two-Factor Authentication (2FA) has been DISABLED.")
}

func (s *Shell) cmdLogout() {
	if s.sessionToken == "" {
		return
	}

	err := s.authService.InvalidateSession(s.sessionToken)
	if err != nil {
		color.Red("[Error] Failed to close session: %v", err)
	}

	s.sessionToken = ""
	s.currentUser = nil
	color.Green("[Success] Logged out successfully.")
}
