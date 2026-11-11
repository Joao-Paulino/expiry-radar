package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/admin"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
)

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}
	if cfg.DBPath == "" {
		return Config{}, errors.New("config has no db_path")
	}
	return cfg, nil
}

// sttyCommand and isTerminal are variables so tests can simulate a
// terminal without stty (stdlib only: no golang.org/x/term).
var (
	sttyCommand = "stty"
	isTerminal  = func(in io.Reader) bool {
		f, ok := in.(*os.File)
		if !ok || runtime.GOOS == "windows" {
			return false
		}
		fi, err := f.Stat()
		return err == nil && fi.Mode()&os.ModeCharDevice != 0
	}
)

// setEcho turns terminal echo on or off for in.
func setEcho(in io.Reader, on bool) error {
	arg := "-echo"
	if on {
		arg = "echo"
	}
	cmd := exec.Command(sttyCommand, arg)
	if f, ok := in.(*os.File); ok {
		cmd.Stdin = f
	}
	return cmd.Run()
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readSecret(in io.Reader, r *bufio.Reader, out io.Writer, prompt string) (string, error) {
	if !isTerminal(in) {
		fmt.Fprint(out, prompt)
		return readLine(r)
	}
	if err := setEcho(in, false); err != nil {
		fmt.Fprintln(out, "Warning: could not hide input (stty unavailable); what you type will be visible.")
	} else {
		// Restore echo if the user presses Ctrl-C at the prompt.
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
		done := make(chan struct{})
		go func() {
			select {
			case <-sigs:
				setEcho(in, true)
				fmt.Fprintln(out)
				os.Exit(130)
			case <-done:
			}
		}()
		defer func() {
			signal.Stop(sigs)
			close(done)
			setEcho(in, true)
			fmt.Fprintln(out)
		}()
	}
	fmt.Fprint(out, prompt)
	return readLine(r)
}

func openAdminStores(cfgPath string) (*admin.Store, *session.Store, func(), error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, nil, nil, err
	}
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return nil, nil, nil, err
	}
	return &admin.Store{DB: database}, &session.Store{DB: database, Now: time.Now}, func() { database.Close() }, nil
}

// runSetAdminPassword asks for the new Administrator password twice
// (without echo on a terminal), stores only its hash, and signs out
// every dashboard session.
func runSetAdminPassword(cfgPath string, in io.Reader, out io.Writer) error {
	r := bufio.NewReader(in)
	first, err := readSecret(in, r, out, "New administrator password: ")
	if err != nil {
		return err
	}
	second, err := readSecret(in, r, out, "Repeat password: ")
	if err != nil {
		return err
	}
	if first != second {
		return errors.New("passwords do not match; nothing was changed")
	}
	hash, err := admin.HashPassword(first)
	if err != nil {
		return err
	}

	as, ss, closeDB, err := openAdminStores(cfgPath)
	if err != nil {
		return err
	}
	defer closeDB()
	ctx := context.Background()
	if err := as.SetPassword(ctx, hash); err != nil {
		return err
	}
	if err := ss.DeleteAll(ctx); err != nil {
		return err
	}
	fmt.Fprintln(out, "Administrator password set. All dashboard sessions were signed out.")
	return nil
}

// runSetAdminTOTP creates a TOTP secret, shows it for the authenticator
// app, and stores it only after a valid code proves the app has it. It
// then prints 8 single-use recovery codes and signs out every session.
func runSetAdminTOTP(cfgPath string, in io.Reader, out io.Writer, now func() time.Time) error {
	as, ss, closeDB, err := openAdminStores(cfgPath)
	if err != nil {
		return err
	}
	defer closeDB()

	secret, err := admin.NewTOTPSecret()
	if err != nil {
		return err
	}
	uri := admin.TOTPURI(secret)
	fmt.Fprintf(out, "Add this account to your authenticator app.\n\n  Key: %s\n  URI: %s\n\n", secret, uri)
	fmt.Fprintf(out, "Tip: qrencode -t ansiutf8 '%s'\n\n", uri)
	fmt.Fprint(out, "Enter the 6-digit code from the app: ")

	code, err := readLine(bufio.NewReader(in))
	if err != nil {
		return err
	}
	step, ok := admin.VerifyTOTP(secret, strings.TrimSpace(code), now(), 0)
	if !ok {
		return errors.New("the code did not match; nothing was changed (check the device clock and try again)")
	}

	plain, hashes, err := admin.NewRecoveryCodes()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := as.SetTOTP(ctx, secret, hashes); err != nil {
		return err
	}
	// The confirmation code must not also work for a login.
	if _, err := as.ClaimTOTPStep(ctx, step); err != nil {
		return err
	}
	if err := ss.DeleteAll(ctx); err != nil {
		return err
	}

	fmt.Fprintln(out, "\nTOTP enabled. All dashboard sessions were signed out.")
	fmt.Fprintln(out, "Recovery codes (each works once; store them somewhere safe):")
	for _, c := range plain {
		fmt.Fprintf(out, "  %s\n", c)
	}
	return nil
}
