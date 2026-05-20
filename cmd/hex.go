package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// hexCmd represents the hex command
var hexCmd = &cobra.Command{
	Use:   "hex",
	Short: "Convert the binary file to a hexadecimal string output.",
	Long:  `Convert the binary file to a hexadecimal string output.`,
	Run: func(cmd *cobra.Command, args []string) {
		filePath, _ := cmd.Flags().GetString("file")
		upper, _ := cmd.Flags().GetBool("upper")

		if filePath == "" {
			fmt.Println("Corrected sentence: Please use the -f option to specify the file path.")
			return
		}

		info, err := os.Stat(filePath)
		if err != nil {
			fmt.Println("Error: The file does not exist or cannot be accessed.")
			return
		}
		if info.IsDir() {
			fmt.Println("Corrected text: Error: Cannot pass in a directory. Please specify a file.")
			return
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Failed to read the file：%v\n", err)
			return
		}

		hexStr := hex.EncodeToString(data)
		if upper {
			hexStr = strings.ToUpper(hexStr)
		}

		fmt.Printf("File size: %d bytes\n", len(data))
		fmt.Println("Hex:")
		fmt.Println(hexStr)
	},
}

func init() {
	rootCmd.AddCommand(hexCmd)
	hexCmd.Flags().StringP("file", "f", "", "Binary file path")
	hexCmd.Flags().BoolP("upper", "u", false, "Output in uppercase hexadecimal format")
	_ = hexCmd.MarkFlagRequired("file")
}
