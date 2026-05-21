package cmd

import (
	"crypto/ed25519"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
	"lukechampine.com/blake3"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the signature of a data packet.",
	Long: `Verify the signature of a data packet using the embedded public key.
This command reads the .public and .sign files from the specified directory (or custom paths),
hashes all other files (excluding .gitignore, .public, .sign) in sorted order,
and checks the ED25519 signature.`,
	Run: func(cmd *cobra.Command, args []string) {
		dir, _ := cmd.Flags().GetString("dir")
		if dir == "" {
			dir = "."
		}
		publicFlag, _ := cmd.Flags().GetString("public")
		signFlag, _ := cmd.Flags().GetString("sign")

		publicKeyPath := publicFlag
		if publicKeyPath == "" {
			publicKeyPath = filepath.Join(dir, ".public")
		}
		signPath := signFlag
		if signPath == "" {
			signPath = filepath.Join(dir, ".sign")
		}

		dirInfo, err := os.Stat(dir)
		if err != nil {
			fmt.Printf("Error: Directory '%s' does not exist.\n", dir)
			return
		}
		if !dirInfo.IsDir() {
			fmt.Printf("Error: '%s' is not a directory.\n", dir)
			return
		}

		publicKeyBytes, err := os.ReadFile(publicKeyPath)
		if err != nil {
			fmt.Printf("Error: Failed to read public key file '%s': %v\n", publicKeyPath, err)
			return
		}
		if len(publicKeyBytes) != ed25519.PublicKeySize {
			fmt.Printf("Error: Invalid public key length in '%s' (expected %d, got %d).\n",
				publicKeyPath, ed25519.PublicKeySize, len(publicKeyBytes))
			return
		}

		signature, err := os.ReadFile(signPath)
		if err != nil {
			fmt.Printf("Error: Failed to read signature file '%s': %v\n", signPath, err)
			return
		}
		if len(signature) != ed25519.SignatureSize {
			fmt.Printf("Error: Invalid signature length in '%s' (expected %d, got %d).\n",
				signPath, ed25519.SignatureSize, len(signature))
			return
		}

		var fileList []string
		skipFiles := map[string]bool{
			".gitignore": true,
			".public":    true,
			".sign":      true,
		}

		err = filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(dir, path)
			if skipFiles[rel] {
				return nil
			}
			fileList = append(fileList, rel)
			return nil
		})
		if err != nil {
			fmt.Printf("Error walking directory: %v\n", err)
			return
		}

		sort.Strings(fileList)

		if len(fileList) == 0 {
			fmt.Println("No files to verify (only .gitignore, .public, .sign found).")
			return
		}

		var allHashData []byte
		for _, relPath := range fileList {
			fullPath := filepath.Join(dir, relPath)
			fileData, err := os.ReadFile(fullPath)
			if err != nil {
				fmt.Printf("Skipping file %s: Read failed %v\n", relPath, err)
				continue
			}
			hash := blake3.Sum256(fileData)
			allHashData = append(allHashData, hash[:]...)
		}

		if ed25519.Verify(publicKeyBytes, allHashData, signature) {
			fmt.Println("Signature verification PASSED.")
		} else {
			fmt.Println("Signature verification FAILED.")
		}
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringP("dir", "d", ".", "Directory containing the data packet (used as base for default .public/.sign paths)")
	verifyCmd.Flags().StringP("public", "p", "", "Path to the public key file (overrides default: <dir>/.public)")
	verifyCmd.Flags().StringP("sign", "s", "", "Path to the signature file (overrides default: <dir>/.sign)")
}
