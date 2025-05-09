package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"re/MD5"
	"re/SHA256"
	"re/SM3"
)

func main() {
	hashStr := flag.String("hash", "", "Hash to crack (hex encoded, case-insensitive)")
	length := flag.Int("length", 5, "Length of the plaintext")
	mod := flag.String("mod", "unknown", "Hash algorithm to use (md5, sha256, sm3, or unknown for all)")
	charset := flag.String("charset", "letters", "Character set to use (letters, alphanumeric, ascii)")

	flag.Parse()

	if *hashStr == "" {
		fmt.Println("Usage: ./hash-cracker -hash <target_hash_hex> -length <plain_length> -mod <mod_type> -charset <charset_type>")
		os.Exit(1)
	}

	// Normalize the hash to lowercase
	normalizedHash := strings.ToLower(*hashStr)

	// Define the character sets
	var charsetString string
	switch *charset {
	case "letters":
		charsetString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case "alphanumeric":
		charsetString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	case "ascii":
		charsetString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c"
	default:
		fmt.Println("[-] Invalid charset. Supported charsets: letters, alphanumeric, ascii.")
		os.Exit(1)
	}

	// Choose the hash algorithm based on mod argument
	switch *mod {
	case "md5":
		MD5.CrackMD5(normalizedHash, *length, charsetString)
	case "sha256":
		SHA256.CrackSHA256(normalizedHash, *length, charsetString)
	case "sm3":
		SM3.CrackSM3(normalizedHash, *length, charsetString)
	case "unknown":
		fmt.Println("[*] Trying all available hash algorithms (MD5, SHA-256, SM3)...")
		go MD5.CrackMD5(normalizedHash, *length, charsetString)
		go SHA256.CrackSHA256(normalizedHash, *length, charsetString)
		go SM3.CrackSM3(normalizedHash, *length, charsetString)
		select {} // Block forever
	default:
		fmt.Println("[-] Invalid mode. Supported modes: md5, sha256, sm3, unknown.")
		os.Exit(1)
	}
}
