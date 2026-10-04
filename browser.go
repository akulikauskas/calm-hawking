package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

// openBrowser attempts to open the specified URL in the system's default browser.
func openBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		// rundll32 url.dll,FileProtocolHandler directly calls ShellExecute without spawning cmd.exe
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default: // linux, bsd, etc.
		cmd = exec.Command("xdg-open", url)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to launch browser command: %w", err)
	}
	return nil
}
