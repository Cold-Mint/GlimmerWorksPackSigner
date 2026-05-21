package cmd

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"lukechampine.com/blake3"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign the data packets.",
	Long:  `Sign the data packets.`,
	Run: func(cmd *cobra.Command, args []string) {
		publicKeyPath, _ := cmd.Flags().GetString("public-key-path")
		if publicKeyPath == "" {
			fmt.Println("Error: The public key path has not been specified. Use -p instead.")
			return
		}
		publicInfo, publicErr := os.Stat(publicKeyPath)
		if publicErr != nil {
			fmt.Println("Error: The public key file does not exist.")
			return
		}
		if publicInfo.IsDir() {
			fmt.Println("Error: The public key path is a directory.")
			return
		}
		publicKeyBytes, err := os.ReadFile(publicKeyPath)
		if err != nil {
			fmt.Printf("Error: Failed to read the public key %v\n", err)
			return
		}
		if len(publicKeyBytes) != ed25519.PublicKeySize {
			fmt.Println("Error: Invalid ED25519 public key. The length must be 32 bytes.")
			return
		}
		privateKeyPath, _ := cmd.Flags().GetString("private-key-path")
		if privateKeyPath == "" {
			fmt.Println("Error: The private key path has not been specified. Use -k instead.")
			return
		}
		privateInfo, privateErr := os.Stat(privateKeyPath)
		if privateErr != nil {
			fmt.Println("Error: The private key file does not exist.")
			return
		}
		if privateInfo.IsDir() {
			fmt.Println("Error: The private key path is a directory.")
			return
		}
		privateKeyBytes, err := os.ReadFile(privateKeyPath)
		if err != nil {
			fmt.Printf("Error: Failed to read the private key %v\n", err)
			return
		}
		if len(privateKeyBytes) != ed25519.PrivateKeySize {
			fmt.Println("Error: Invalid ED25519 private key. The length must be 64 bytes.")
			return
		}
		dir, _ := cmd.Flags().GetString("dir")
		if dir == "" {
			dir = "."
		}
		dirInfo, dirErr := os.Stat(dir)
		if dirErr != nil {
			fmt.Println("Error: The dir does not exist.")
			return
		}
		if !dirInfo.IsDir() {
			fmt.Println("Error: The dir is not a directory.")
			return
		}
		privateKeyEd25519 := ed25519.PrivateKey(privateKeyBytes)
		var fileList []string
		_ = filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(dir, path)
			if strings.HasPrefix(info.Name(), ".") {
				return nil
			}
			fileList = append(fileList, rel)
			return nil
		})

		//Sort the files to ensure consistent hash order
		//文件排序，保证哈希顺序一致
		sort.Strings(fileList)
		if len(fileList) == 0 {
			fmt.Println("There are no files in the directory that require signature.")
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
		signature := ed25519.Sign(privateKeyEd25519, allHashData)
		signatureDest := filepath.Join(dir, ".sign")
		err = os.WriteFile(signatureDest, signature, 0600)
		if err != nil {
			fmt.Println("Failed to save .pack-sign file:", err)
			return
		}
		publicKeyDest := filepath.Join(dir, ".public")

		srcPublic, err := os.Open(publicKeyPath)
		if err != nil {
			fmt.Printf("Error: Failed to open the public key %v\n", err)
			return
		}
		defer func(srcPublic *os.File) {
			err := srcPublic.Close()
			if err != nil {
				fmt.Printf("Error: Failed to close the source public key file. %v\n", err)
			}
		}(srcPublic)
		destPublic, err := os.Create(publicKeyDest)
		if err != nil {
			fmt.Printf("Error: Failed to copy the public key %v\n", err)
			return
		}
		defer func(destPublic *os.File) {
			err := destPublic.Close()
			if err != nil {
				fmt.Printf("Error: Failed to close the target public key file. %v\n", err)
			}
		}(destPublic)
		_, err = io.Copy(destPublic, srcPublic)
		if err != nil {
			fmt.Printf("Error: Failed to write public key file %v\n", err)
			return
		}
		fmt.Println("Signature completed.")
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().StringP("private-key-path", "k", "", "Private key file path")
	signCmd.Flags().StringP("public-key-path", "p", "", "Public key file path")
	signCmd.Flags().StringP("dir", "d", ".", "The path of the document to be signed ,default: current directory")
}
