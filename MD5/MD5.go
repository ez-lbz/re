package MD5

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	targetHash []byte
	maxLen     int
	found      = false
	wg         sync.WaitGroup
	mu         sync.Mutex

	totalCount int64
	triedCount int64
)

// 判断是否为 ascii 模式下的爆破结果
func isASCIICharset(s string) bool {
	for _, r := range s {
		if r > 0x7F {
			return false
		}
	}
	return true
}

// CrackMD5 attempts to brute-force an MD5 hash.
func CrackMD5(hashStr string, length int, charset string) {
	normalized := strings.ToLower(hashStr)
	var err error
	targetHash, err = hex.DecodeString(normalized)
	if err != nil || len(targetHash) != 16 {
		fmt.Println("[-] Invalid MD5 hash (must be 16-byte hex string)")
		return
	}

	maxLen = length
	totalCount = int64(pow(len(charset), maxLen))

	fmt.Printf("[*] Cracking MD5 hash: %s (length=%d, total=%d combinations)\n", normalized, maxLen, totalCount)

	go progressPrinter()

	// Try all prefixes of the charset
	for i := 0; i < len(charset); i++ {
		prefix := string(charset[i])
		wg.Add(1)
		go brute(prefix, charset)
	}

	wg.Wait()

	if !found {
		fmt.Println("\n[!] No matching plaintext found.")
	}
}

// brute starts a brute-force attempt for all combinations starting with the given prefix.
func brute(prefix string, charset string) {
	defer wg.Done()
	dfs(prefix, 1, charset)
}

// dfs performs depth-first search for possible plaintexts.
func dfs(current string, depth int, charset string) {
	if isFound() {
		return
	}
	if depth == maxLen {
		tryMatch(current)
		return
	}
	for i := 0; i < len(charset); i++ {
		next := current + string(charset[i])
		dfs(next, depth+1, charset)
	}
}

// tryMatch compares the candidate string against the target hash.
func tryMatch(candidate string) {
	hash := md5.Sum([]byte(candidate))

	atomic.AddInt64(&triedCount, 1)

	if bytes.Equal(hash[:], targetHash) {
		mu.Lock()
		if !found {
			if isASCIICharset(candidate) {
				fmt.Printf("\n[FOUND] Plaintext (hex): %x\n", []byte(candidate))
			} else {
				fmt.Printf("\n[FOUND] Plaintext: %s\n", candidate)
			}

			found = true
		}
		mu.Unlock()
	}
}

func isFound() bool {
	mu.Lock()
	defer mu.Unlock()
	return found
}

func progressPrinter() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if isFound() {
			return
		}
		tried := atomic.LoadInt64(&triedCount)
		percent := float64(tried) / float64(totalCount) * 100
		fmt.Printf("\r[*] Progress: %.2f%% (%d / %d)", percent, tried, totalCount)
	}
}

func pow(base, exp int) int {
	result := 1
	for i := 0; i < exp; i++ {
		result *= base
	}
	return result
}
