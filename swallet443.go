////////////////////////////////////////////////////////////////////////////////
//
//  File           : swallet443.go
//  Description    : This is the implementaiton file for the swallet password
//                   wallet program program.  See assignment details.
//
//  Collaborators  : James Frazier, Daniel Colom, James Cunningham, Sahil Mishra
//  Last Modified  : 12/7/17
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
	"crypto/cipher"
	cryptorand "crypto/rand"
	//"reflect"
	"encoding/base64"
	"github.com/marcusolsson/tui-go"
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
// Function     : launchUI
// Description  : This function creates a UI for user input and program output
//
// Inputs       : String defining usage
// Outputs      : String from user input

func launchUI(usage string, funcInput string) (string) {
	var output string

	history := tui.NewVBox()
	history.SetBorder(true)
	history.Append(tui.NewSpacer())

	input := tui.NewEntry()
	input.SetFocused(true)
	input.SetSizePolicy(tui.Expanding, tui.Maximum)

	inputBox := tui.NewHBox(input)
	inputBox.SetBorder(true)
	inputBox.SetSizePolicy(tui.Expanding, tui.Maximum)

	chat := tui.NewVBox(history, inputBox)
	chat.SetSizePolicy(tui.Expanding, tui.Expanding)

	switch (usage) {
		case "create" :
			history.Append(tui.NewHBox(
				tui.NewLabel("Please enter the master password:"),
				tui.NewSpacer()))

			var passwordChars1 string
			var passwordChars2 string
			secondTime := false

			input.OnChanged(func(e *tui.Entry) {
				if (!secondTime) {
					passwordChars1 = passwordChars1 + input.Text()
				} else {
					passwordChars2 = passwordChars2 + input.Text()
				}

				input.SetText("")
			})
			root := tui.NewHBox(chat)

			ui := tui.New(root)
			ui.SetKeybinding("Esc", func() { ui.Quit() })

			input.OnSubmit(func(e *tui.Entry) {
				input.SetText("")
				history.Append(tui.NewHBox(
					tui.NewLabel("Please re-enter the master password:"),
					tui.NewSpacer()))
				if (secondTime) {
					if (strings.Compare(passwordChars1, passwordChars2) == 0) {
						output = passwordChars1
						ui.Quit()
					} else {
						history.Append(tui.NewHBox(
							tui.NewLabel("The passwords don't match!\nPress esc to quit"),
							tui.NewSpacer()))
							ui.SetKeybinding("Esc", func() { ui.Quit() })
							output = "error"
					}
				} else {
					secondTime = true;
				}
			})

			if err := ui.Run(); err != nil {
				panic(err)
			}

		case "verify" :
			history.Append(tui.NewHBox(
				tui.NewLabel("Please enter the master password:"),
				tui.NewSpacer()))

			var passwordChars string

			input.OnChanged(func(e *tui.Entry) {
				passwordChars = passwordChars + input.Text()
				input.SetText("")
			})
			root := tui.NewHBox(chat)

			ui := tui.New(root)
			ui.SetKeybinding("Esc", func() { ui.Quit() })

			input.OnSubmit(func(e *tui.Entry) {
				input.SetText("")
				output = passwordChars
				ui.Quit()
			})

			if err := ui.Run(); err != nil {
				panic(err)
			}
		case "add" :

			commentBool := true
			history.Append(tui.NewHBox(
				tui.NewLabel("Please enter a comment for new password"),
				tui.NewSpacer()))

			var commentChars string

			root := tui.NewHBox(chat)

			ui := tui.New(root)
			ui.SetKeybinding("Esc", func() { ui.Quit() })

			input.OnChanged(func(e *tui.Entry) {
				if (!commentBool) {
					commentChars = commentChars + input.Text()
					input.SetText("")
				}
			})

			input.OnSubmit(func(e *tui.Entry) {

				if (commentBool) {
					commentChars = commentChars + input.Text()
					input.SetText("")
					output = commentChars
					commentChars = ""
					commentBool = false
					history.Append(tui.NewHBox(
						tui.NewLabel("Please enter the new password"),
						tui.NewSpacer()))
				} else {
					input.SetText("")
					output += "||" + commentChars
					ui.Quit()
				}

			})

			if err := ui.Run(); err != nil {
				panic(err)
			}

		case "delete" :
			history.Append(tui.NewHBox(
				tui.NewLabel("Please enter index of password to delete:"),
				tui.NewSpacer()))

			root := tui.NewHBox(chat)

			ui := tui.New(root)
			ui.SetKeybinding("Esc", func() { ui.Quit() })

			input.OnSubmit(func(e *tui.Entry) {
				output = input.Text()
				input.SetText("")
				ui.Quit()
			})

			if err := ui.Run(); err != nil {
				panic(err)
			}


		case "show1" :
			history.Append(tui.NewHBox(
				tui.NewLabel("Please enter index of password to show:"),
				tui.NewSpacer()))

			root := tui.NewHBox(chat)

			ui := tui.New(root)
			ui.SetKeybinding("Esc", func() { ui.Quit() })

			input.OnSubmit(func(e *tui.Entry) {
				output = input.Text()
				input.SetText("")
				ui.Quit()
			})

			if err := ui.Run(); err != nil {
				panic(err)
			}

		case "show2" :
			history.Append(tui.NewHBox(
				tui.NewLabel("Here is the password:"),
				tui.NewSpacer(),
				))
			history.Append(tui.NewHBox(
				tui.NewLabel(funcInput),
				tui.NewSpacer(),
				))
			history.Append(tui.NewHBox(
				tui.NewLabel("Press ESC to quit"),
				))

			root := tui.NewHBox(chat)

			ui := tui.New(root)
			ui.SetKeybinding("Esc", func() { ui.Quit() })

			if err := ui.Run(); err != nil {
				panic(err)
			}

		case "change1" :
			history.Append(tui.NewHBox(
				tui.NewLabel("Please enter index of password to change:"),
				tui.NewSpacer()))

			root := tui.NewHBox(chat)

			ui := tui.New(root)
			ui.SetKeybinding("Esc", func() { ui.Quit() })

			input.OnSubmit(func(e *tui.Entry) {
				output = input.Text()
				input.SetText("")
				ui.Quit()
			})

			if err := ui.Run(); err != nil {
				panic(err)
			}

		case "change2" :
			history.Append(tui.NewHBox(
				tui.NewLabel("Please enter the password:"),
				tui.NewSpacer()))

			root := tui.NewHBox(chat)

			ui := tui.New(root)
			ui.SetKeybinding("Esc", func() { ui.Quit() })

			input.OnSubmit(func(e *tui.Entry) {
				output = input.Text()
				input.SetText("")
				ui.Quit()
			})

			if err := ui.Run(); err != nil {
				panic(err)
			}

		case "reset" :
			history.Append(tui.NewHBox(
				tui.NewLabel("Please enter the new master password:"),
				tui.NewSpacer(),
				tui.NewLabel("WARNING: PLEASE CLICK ON INPUT BAR BEFORE TYPING (best UI ever)"),
				tui.NewSpacer()))

			var passwordChars string

			input.OnChanged(func(e *tui.Entry) {
				passwordChars = passwordChars + input.Text()
				input.SetText("")
			})
			root := tui.NewHBox(chat)

			ui := tui.New(root)
			ui.SetKeybinding("Esc", func() { ui.Quit() })

			input.OnSubmit(func(e *tui.Entry) {
				input.SetText("")
				output = passwordChars
				ui.Quit()
			})

			if err := ui.Run(); err != nil {
				panic(err)
			}

		case "list" :
			history.Append(tui.NewHBox(
				tui.NewLabel("Here are the wallet entries:"),
				tui.NewSpacer(),
				))
			history.Append(tui.NewHBox(
				tui.NewLabel(funcInput),
				tui.NewSpacer(),
				))
			history.Append(tui.NewHBox(
				tui.NewLabel("Press ESC to quit"),
				))

			root := tui.NewHBox(chat)

			ui := tui.New(root)
			ui.SetKeybinding("Esc", func() { ui.Quit() })

			if err := ui.Run(); err != nil {
				panic(err)
			}
	}


	return output
}

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




	// Confirm master password from user input using UI
	password := launchUI("create", "")
	if (strings.Compare(password, "error") == 0) {
		return nil
	} else {
		wal443.masterPassword = []byte(password)

		// Return the wall
		return &wal443
	}
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
	} else {
		// Store all lines of wallet file in string array
		var lines []string
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		// Split the scanned lines into password fields
		for i:=1; i<len(lines)-1; i++ {
			splitLine := strings.Split(lines[i], "||")
			var  temp walletEntry
			temp.salt = []byte(splitLine[1])
	    temp.password = []byte(splitLine[2])
			temp.comment = []byte(splitLine[3])
			wal443.passwords = append(wal443.passwords,temp)
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
		// Process first line; Update access count
		splitLine := strings.Split(lines[0], "||")
		accessInt, _ := strconv.Atoi(splitLine[1])
		accessCount :=  accessInt + 1

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

	passIn := launchUI("verify", "")


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
	sha1pass := sha1.New()
	io.WriteString(sha1pass, string(passIn))
	tempSha := sha1pass.Sum(nil)[:16]
	mac := hmac.New(sha1.New, tempSha)
	mac.Write([]byte(preceeding))
	finalHmac := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	//Compare HMAC from User input to stored HMAC
	if strings.Compare(finalHmac, lines[len(lines)-1]) == 0 {
		wal443.masterPassword = []byte(passIn)
		// Process the command
		switch command {
		case "add":
			// DO SOMETHING HERE, e.g., wal443.addPassword(...)
			var  temp walletEntry
			originalSalt := make([]byte, 16)
			io.ReadFull(cryptorand.Reader, originalSalt)
			temp.salt = []byte(base64.StdEncoding.EncodeToString(originalSalt))

			splitInput := strings.Split(launchUI("add", ""), "||")

			pass := []byte(splitInput[1])

			temp.password = make([]byte, 32, 32)
			for j:=0;j<32;j++ {
				temp.password[j] = 0;
			}
			for i:=0;i< len(pass);i++{
				temp.password[i] = pass[i]
			}

			aesblock, _ := aes.NewCipher(tempSha)
			mode := cipher.NewCBCEncrypter(aesblock, originalSalt)
			cipherText := make([]byte, 32)
			mode.CryptBlocks(cipherText, temp.password)

			temp.password = cipherText

			temp.password = []byte(base64.StdEncoding.EncodeToString(temp.password))

			temp.comment = []byte(splitInput[0])

			wal443.passwords = append(wal443.passwords, temp)

		case "del":
			deleteIndex, _ := strconv.Atoi(launchUI("delete", ""))
			before := wal443.passwords[0:deleteIndex]
			after := wal443.passwords[deleteIndex+1:]
			wal443.passwords = append(before,after...)

		case "show":
			showIndex, _ := strconv.Atoi(launchUI("show1", ""))
			enPass := wal443.passwords[showIndex].password
			base64enPass, _ := base64.StdEncoding.DecodeString(string(enPass))

			aesblock, _ := aes.NewCipher(tempSha)
			base64Salt, _ := base64.StdEncoding.DecodeString(string(wal443.passwords[showIndex].salt))
			mode2 := cipher.NewCBCDecrypter(aesblock, base64Salt)
			mode2.CryptBlocks([]byte(base64enPass), []byte(base64enPass))

			dePass := base64enPass

			launchUI("show2", string(dePass))

		case "chpw":
			changeIndex, _ := strconv.Atoi(launchUI("change1", ""))
			newPass := launchUI("change2", "")

			var  temp walletEntry
			originalSalt := make([]byte, 16)
			io.ReadFull(cryptorand.Reader, originalSalt)
			temp.salt = []byte(base64.StdEncoding.EncodeToString(originalSalt))

			pass := []byte(newPass)

			temp.password = make([]byte, 32, 32)
			for j:=0;j<32;j++ {
				temp.password[j] = 0;
			}
			for i:=0;i< len(pass);i++{
				temp.password[i] = pass[i]
			}

			aesblock, _ := aes.NewCipher(tempSha)
			mode := cipher.NewCBCEncrypter(aesblock, originalSalt)
			cipherText := make([]byte, 32)
			mode.CryptBlocks(cipherText, temp.password)

			temp.password = cipherText

			temp.password = []byte(base64.StdEncoding.EncodeToString(temp.password))

			temp.comment = wal443.passwords[changeIndex].comment

			wal443.passwords[changeIndex].password = []byte(temp.password)
			wal443.passwords[changeIndex].salt = []byte(temp.salt)


		case "reset":
			newMasterPass := launchUI("reset", "")

			wal443.masterPassword = []byte(newMasterPass)

		case "list":
			var showList string
			for i:=0;i<len(wal443.passwords);i++ {
				showList = showList + strconv.Itoa(i) + ": " + string(wal443.passwords[i].comment) + "\n"
			}
			launchUI("list", showList)

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
		getopt.Usage()
		os.Exit(-1)
	}

	// Process the flags
	verbose = *verboseflag
	if *helpflag == true {
		getopt.Usage()
		os.Exit(-1)
	}

	// Check the arguments to make sure we have enough, process if OK
	if getopt.NArgs() < 2 {
		getopt.Usage()
		os.Exit(-1)
	}
	filename := getopt.Arg(0)
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
