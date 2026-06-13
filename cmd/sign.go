package cmd

import (
	"crypto/ed25519"
	"encoding/hex"
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
		hexMode, _ := cmd.Flags().GetBool("hex")

		privateKeyValue, _ := cmd.Flags().GetString("private-key")
		if privateKeyValue == "" {
			fmt.Println("Error: The private key has not been specified. Use -k instead.")
			return
		}
		publicKeyValue, _ := cmd.Flags().GetString("public-key")
		if publicKeyValue == "" {
			fmt.Println("Error: The public key has not been specified. Use -p instead.")
			return
		}

		var privateKeyBytes []byte
		var publicKeyBytes []byte
		var err error

		if hexMode {
			// 十六进制模式：解码私钥
			privateKeyBytes, err = hex.DecodeString(privateKeyValue)
			if err != nil {
				fmt.Printf("Error: Failed to decode private key hex string: %v\n", err)
				return
			}
			if len(privateKeyBytes) != ed25519.PrivateKeySize {
				fmt.Printf("Error: Invalid ED25519 private key length (hex decoded). Expected %d bytes, got %d.\n",
					ed25519.PrivateKeySize, len(privateKeyBytes))
				return
			}
			// 解码公钥
			publicKeyBytes, err = hex.DecodeString(publicKeyValue)
			if err != nil {
				fmt.Printf("Error: Failed to decode public key hex string: %v\n", err)
				return
			}
			if len(publicKeyBytes) != ed25519.PublicKeySize {
				fmt.Printf("Error: Invalid ED25519 public key length (hex decoded). Expected %d bytes, got %d.\n",
					ed25519.PublicKeySize, len(publicKeyBytes))
				return
			}
		} else {
			// 文件路径模式：从文件读取
			privateInfo, privateErr := os.Stat(privateKeyValue)
			if privateErr != nil {
				fmt.Println("Error: The private key file does not exist.")
				return
			}
			if privateInfo.IsDir() {
				fmt.Println("Error: The private key path is a directory.")
				return
			}
			privateKeyBytes, err = os.ReadFile(privateKeyValue)
			if err != nil {
				fmt.Printf("Error: Failed to read the private key %v\n", err)
				return
			}
			if len(privateKeyBytes) != ed25519.PrivateKeySize {
				fmt.Println("Error: Invalid ED25519 private key. The length must be 64 bytes.")
				return
			}

			publicInfo, publicErr := os.Stat(publicKeyValue)
			if publicErr != nil {
				fmt.Println("Error: The public key file does not exist.")
				return
			}
			if publicInfo.IsDir() {
				fmt.Println("Error: The public key path is a directory.")
				return
			}
			publicKeyBytes, err = os.ReadFile(publicKeyValue)
			if err != nil {
				fmt.Printf("Error: Failed to read the public key %v\n", err)
				return
			}
			if len(publicKeyBytes) != ed25519.PublicKeySize {
				fmt.Println("Error: Invalid ED25519 public key. The length must be 32 bytes.")
				return
			}
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

		// Sort the files to ensure consistent hash order
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
			fmt.Println("Failed to save .sign file:", err)
			return
		}

		publicKeyDest := filepath.Join(dir, ".public")

		//Write the public key binary directly to the file in hexadecimal mode.
		//Copy the file in path mode.
		//十六进制模式下，直接将公钥二进制写入文件；路径模式下，复制文件
		if hexMode {
			err = os.WriteFile(publicKeyDest, publicKeyBytes, 0600)
			if err != nil {
				fmt.Printf("Error: Failed to write public key file: %v\n", err)
				return
			}
		} else {
			srcPublic, err := os.Open(publicKeyValue)
			if err != nil {
				fmt.Printf("Error: Failed to open the public key %v\n", err)
				return
			}
			defer srcPublic.Close()
			destPublic, err := os.Create(publicKeyDest)
			if err != nil {
				fmt.Printf("Error: Failed to copy the public key %v\n", err)
				return
			}
			defer destPublic.Close()
			_, err = io.Copy(destPublic, srcPublic)
			if err != nil {
				fmt.Printf("Error: Failed to write public key file %v\n", err)
				return
			}
		}

		fmt.Println("Signature completed.")
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().StringP("private-key", "k", "", "Private key (file path or hex string, see --hex)")
	signCmd.Flags().StringP("public-key", "p", "", "Public key (file path or hex string, see --hex)")
	signCmd.Flags().StringP("dir", "d", ".", "The path of the document to be signed, default: current directory")
	signCmd.Flags().BoolP("hex", "x", false, "Interpret --private-key and --public-key as hexadecimal strings (instead of file paths)")
}
