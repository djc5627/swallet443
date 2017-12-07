////////////////////////////////////////////////////////////////////////////////
//
//  File           : swallet443.go
//  Description    : This is the implementaiton file for the swallet password
//                   wallet program program.  See assignment details.
//
//  Collaborators  : James Frazier, Daniel Colom, James Cunningham, Sahil Mishra
//  Last Modified  : 12/6/17
//

// Package statement
package main

// Imports
import (
	"fmt"
	"os"
	"time"
	"strings"
	"math/rand"
	"github.com/pborman/getopt"
	"bufio"
	"io"
	"io/ioutil"
	"strconv"
	"crypto/sha1"
	"crypto/hmac"
	"crypto/aes"
	cryptorand "crypto/rand"
	//"reflect"
	"encoding/base64"
	//"github.com/nsf/termbox-go"
	// There will likely be several mode APIs you need
)

// Type definition  ** YOU WILL NEED TO ADD TO THESE **

// A single password
type walletEntry struct {
	password []byte    // Should be exactly 32 bytes with zero right padding+
	salt []byte        // Should be exactly 16 bytes
	comment []byte     // Should be exactly 128 bytes with zero right padding
}

// The wallet as a whole
type wallet struct {
	filename string
	masterPassword []byte   // Should be exactly 32 bytes with zero right padding
	passwords []walletEntry
}

// Global data
var usageText string = `USAGE: swallet443 [-h] [-v] <wallet-file> [create|add|del|show|chpw|reset|list]

where:
    -h - help mode (display this message)
    -v - enable verbose output

    <wallet-file> - wallet file to manage
    [create|add|del|show|chpw] - is a command to execute, where

     create - create a new wallet file
     add - adds a password to the wallet
     del - deletes a password from the wallet
     show - show a password in the wallet
     chpw - changes the password for an entry in the wallet
     reset - changes the password for the wallet
     list - list the entries in the wallet (without passwords)`

var verbose bool = true

// You may want to create more global variables

//
// Functions

// Up to you to decide which functions you want to add

////////////////////////////////////////////////////////////////////////////////
//
// Function     : walletUsage
// Description  : This function prints out the wallet help
//
// Inputs       : none
// Outputs      : none

func walletUsage() {
	fmt.Fprintf(os.Stderr, "%s\n\n", usageText)
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : createWallet
// Description  : This function creates a wallet if it does not exist
//
// Inputs       : filename - the name of the wallet file
// Outputs      : the wallet if created, nil otherwise

func createWallet(filename string) *wallet {

	// Setup the wallet
	var wal443 wallet
	wal443.filename = filename
	wal443.masterPassword = make([]byte, 32, 32) // You need to take it from here

	// Confirm master password from user input
	reader := bufio.NewReader(os.Stdin)
  fmt.Println("Please enter the master password: ")
  passIn1, _ := reader.ReadString('\n')

	fmt.Println("Please re-enter the master password: ")
	passIn2, _ := reader.ReadString('\n')

	if strings.Compare(passIn1, passIn2) == 0 {
		fmt.Println("They match")
	}

	wal443.masterPassword = []byte(passIn2)


	// Return the wall
	return &wal443
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : loadWallet
// Description  : This function loads an existing wallet
//
// Inputs       : filename - the name of the wallet file
// Outputs      : the wallet if created, nil otherwise

func loadWallet(filename string) *wallet {

	// Setup the wallet
	var wal443 wallet

	//Open wallet file for loading
	wal443.filename = filename
	f, err := os.Open(filename)
	defer f.Close()

	//Check if wallet file exists
	if err != nil {
		println("ERROR: The file doesn't exist!")
	} else {
		// Store all lines of wallet file in string array
		var lines []string
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		fmt.Printf("Line count is: %d\n" , len(lines))

		// Split the scanned lines into password fields
		for i:=1; i<len(lines)-1; i++ {
			splitLine := strings.Split(lines[i], "||")
			var  temp walletEntry
			temp.salt = []byte(splitLine[1])
	    temp.password = []byte(splitLine[2])
			temp.comment = []byte(splitLine[3])
			wal443.passwords = append(wal443.passwords,temp)
			println(string(temp.salt) + string(temp.password) + string(temp.comment))
		}

		// Extract master password HMAC from last line
		wal443.masterPassword = []byte(lines[len(lines)-1])
	}

	// Return the wallet
	return &wal443
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : saveWallet
// Description  : This function save a wallet to the file specified
//
// Inputs       : walletFile - the name of the wallet file
// Outputs      : true if successful test, false if failure

func (wal443 wallet) saveWallet() bool {
	println("Wallet Len = " + strconv.Itoa(len(wal443.passwords)))

	// Setup the wallet
	timeString := time.Now().String()

	// Open the wallet file
	file, err := os.Open(wal443.filename)
	// If error opening (files doesn't exist) instantiate first line, else update it
	if err != nil {
		firstLine := timeString + "||1||\n"
		// Create and store HMAC
		sha1pass := sha1.New()
		io.WriteString(sha1pass, string(wal443.masterPassword))
		wal443.masterPassword = sha1pass.Sum(nil)[:16]
		mac := hmac.New(sha1.New, wal443.masterPassword)
		mac.Write([]byte(firstLine))
		lastLine := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	  ioutil.WriteFile(wal443.filename, []byte(firstLine + lastLine), 0644)
	} else {
		// Read lines from existing wallet file
		var lines []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		println(lines[0])
		// Process first line; Update access count
		splitLine := strings.Split(lines[0], "||")
		accessInt, _ := strconv.Atoi(splitLine[1])
		accessCount :=  accessInt + 1
    println("AccessCount = " + strconv.Itoa(accessCount))

		// Prepare writeLines for Write-back; prepare first line and passwords
		var writeLines string
		firstLine := timeString + "||" + strconv.Itoa(accessCount) + "||"
		writeLines = firstLine + "\n"
		var currentLine string
		for i:=0; i < len(wal443.passwords); i++ {
			currentLine =  strconv.Itoa(i) + "||" + string(wal443.passwords[i].salt) + "||" + string(wal443.passwords[i].password) + "||" + string(wal443.passwords[i].comment)
			writeLines = writeLines + currentLine + "\n"
		}

		// Create the last line; use HMAC
		sha1pass := sha1.New()
		io.WriteString(sha1pass, string(wal443.masterPassword))
		wal443.masterPassword = sha1pass.Sum(nil)[:16]
		mac := hmac.New(sha1.New, wal443.masterPassword)
		mac.Write([]byte(writeLines))
		lastLine := base64.StdEncoding.EncodeToString(mac.Sum(nil))

		fmt.Printf("Write lines:" + writeLines)

		// Append last line and write-back
		writeLines = writeLines + lastLine

		ioutil.WriteFile(wal443.filename, []byte(writeLines), 0644)


	}

	defer file.Close()

	//if _, err = file.WriteString("This was appended\n"); err != nil {
	//    panic(err)
	//}
	// Return successfully
	return true
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : processWalletCommand
// Description  : This is the main processing function for the wallet
//
// Inputs       : walletFile - the name of the wallet file
//                command - the command to execute
// Outputs      : true if successful test, false if failure

func (wal443 *wallet) processWalletCommand(command string) bool {

	// Confirm master password from userInput
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Please enter the master password: ")
	passIn, _ := reader.ReadString('\n')

	// Open wallet file and scan all lines into string array
	file, _ := os.Open(wal443.filename)
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Prepare all preceeding lines into string for HMAC generation
	var preceeding string
	for i:=0;i<len(lines)-1;i++ {
		preceeding = preceeding + lines[i] + "\n"
	}

	//create HMAC from user input
	fmt.Printf("preceeding is :" + preceeding)
	sha1pass := sha1.New()
	io.WriteString(sha1pass, string(passIn))
	tempSha := sha1pass.Sum(nil)[:16]
	mac := hmac.New(sha1.New, tempSha)
	mac.Write([]byte(preceeding))
	finalHmac := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	println("The final hmac is -> " + finalHmac + "\n")

	//Compare HMAC from User input to stored HMAC
	if strings.Compare(finalHmac, lines[len(lines)-1]) == 0 {
		wal443.masterPassword = []byte(passIn)
		// Process the command
		switch command {
		case "add":
			// DO SOMETHING HERE, e.g., wal443.addPassword(...)
			var  temp walletEntry
			temp.salt = make([]byte, 16)
			io.ReadFull(cryptorand.Reader, temp.salt)
			temp.salt = []byte(base64.StdEncoding.EncodeToString(temp.salt))
			temp.password = []byte("Password")
			temp.comment = []byte("Comment")

			wal443.passwords = append(wal443.passwords, temp)
			println("Wallet Len = " + strconv.Itoa(len(wal443.passwords)))

		case "del":
			deleteIndex := 4
			before := wal443.passwords[0:deleteIndex]
			after := wal443.passwords[deleteIndex+1:]
			wal443.passwords = append(before,after...)

		case "show":
			showIndex := 2
			println(string(wal443.passwords[showIndex].password))

		case "chpw":
			changeIndex := 2
			newPass := "newPassword"

			wal443.passwords[changeIndex].password = []byte(newPass)


		case "reset":
			newMasterPass := "pass"

			wal443.masterPassword = []byte(newMasterPass)

		case "list":
			for i:=0;i<len(wal443.passwords);i++ {
				println(strconv.Itoa(i) + ": " + string(wal443.passwords[i].comment))
			}

		default:
			// Handle error, return failure
			fmt.Fprintf(os.Stderr, "Bad/unknown command for wallet [%s], aborting.\n", command)
			return false
		}
		return true

	} else {
		println("Incorrect Password! Stopping...")
		return false
	}
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the password generator program
//
// Inputs       : none
// Outputs      : 0 if successful test, -1 if failure

func main() {

	// Setup options for the program content
	getopt.SetUsage(walletUsage)
	rand.Seed(time.Now().UTC().UnixNano())
	helpflag := getopt.Bool('h', "", "help (this menu)")
	verboseflag := getopt.Bool('v', "", "enable verbose output")

	// Now parse the command line arguments
	err := getopt.Getopt(nil)
	if err != nil {
		// Handle error
		fmt.Fprintln(os.Stderr, err)
		getopt.Usage()
		os.Exit(-1)
	}

	// Process the flags
	fmt.Printf("help flag [%t]\n", *helpflag)
	fmt.Printf("verbose flag [%t]\n", *verboseflag)
	verbose = *verboseflag
	if *helpflag == true {
		getopt.Usage()
		os.Exit(-1)
	}

	// Check the arguments to make sure we have enough, process if OK
	if getopt.NArgs() < 2 {
		fmt.Printf("Not enough arguments for wallet operation.\n")
		getopt.Usage()
		os.Exit(-1)
	}
	fmt.Printf("wallet file [%t]\n", getopt.Arg(0))
	filename := getopt.Arg(0)
	fmt.Printf("command [%t]\n", getopt.Arg(1))
	command := strings.ToLower(getopt.Arg(1))

	// Now check if we are creating a wallet
	if command == "create" {

		// Create and save the wallet as needed
		wal443 := createWallet(filename)
		if wal443 != nil {
			wal443.saveWallet()
		}

	} else {

		// Load the wallet, then process the command
		wal443 := loadWallet(filename)
		if wal443 != nil && wal443.processWalletCommand(command) {
			wal443.saveWallet()
		}

	}

	// Return (no return code)
	return
}
