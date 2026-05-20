/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// genKeyCmd represents the genKey command
var genKeyCmd = &cobra.Command{
	Use:   "genKey",
	Short: "Generate ed25519 signature file",
	Long:  `Generate ed25519 signature file.`,
	Run: func(cmd *cobra.Command, args []string) {
		path, _ := cmd.Flags().GetString("path")
		force, _ := cmd.Flags().GetBool("force")
		baseName, _ := cmd.Flags().GetString("name")
		if path == "" {
			path = "."
		}
		if baseName == "" {
			baseName = "ed25519"
		}
		privName := fmt.Sprintf("%s.private", baseName)
		pubName := fmt.Sprintf("%s.public", baseName)

		privateFile := filepath.Join(path, privName)
		publicFile := filepath.Join(path, pubName)
		if !force {
			if _, err := os.Stat(privateFile); err == nil {
				fmt.Println("Error: private key already exists, use -f to overwrite")
				return
			}
			if _, err := os.Stat(publicFile); err == nil {
				fmt.Println("Error: public key already exists, use -f to overwrite")
				return
			}
		}
		err := os.MkdirAll(path, 0700)
		if err != nil {
			fmt.Println("Failed to create directory:", err)
			return
		}
		pubKey, privKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			fmt.Println("Failed to generate key:", err)
			return
		}

		err = os.WriteFile(privateFile, privKey, 0600)
		if err != nil {
			fmt.Println("Failed to save private key:", err)
			return
		}

		err = os.WriteFile(publicFile, pubKey, 0644)
		if err != nil {
			fmt.Println("Failed to save public key:", err)
			return
		}
		fmt.Println("Key pair generated successfully!")
		fmt.Println("Private key:", privateFile)
		fmt.Println("Public key:", publicFile)
	},
}

func init() {
	rootCmd.AddCommand(genKeyCmd)
	//Specify the directory for saving the key.
	//指定密钥保存目录。
	genKeyCmd.Flags().StringP("path", "p", "", "Specify directory to save key files, use current dir by default.")
	genKeyCmd.Flags().BoolP("force", "f", false, "Force overwrite existing key files")
	genKeyCmd.Flags().StringP("name", "n", "ed25519", "Set base name of key files")
}
