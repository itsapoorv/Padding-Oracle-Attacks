/*
	Author: Apoorv Krishak
	email: akrisha1@jhu.edu
*/

package main

import (
	"os"
	"fmt"
	"io/ioutil"
	"os/exec"
	"crypto/aes"
)

func showUsage() {
	fmt.Print("\n* AES-CBC Attack Tool *\n")
	fmt.Print("\nusage: ./decrypt-attack -i <input-file>\n\n")
}

// XOR two blocks
func XorBlocks(byteArray1, byteArray2 []byte) []byte {
	xor_result := make([]byte, len(byteArray1))
	for i:=0; i<len(byteArray1); i++ {
		xor_result[i] = byteArray1[i] ^ byteArray2[i]
	}
	return xor_result
}

// Divide a big_block into small blocks of size blockSize
func divideBlock(big_block []byte, blockSize int) [][]byte {
    blockCount := len(big_block) / blockSize
    smallblocks := make([][]byte, blockCount)
    
    for i := 0; i < blockCount; i++ {
        index := i * blockSize
        smallblocks[i] = make([]byte, blockSize)
        copy(smallblocks[i], big_block[index : index + blockSize])
    }
    return smallblocks
}

// Concatenate an array of blocks into a single block
func concatenateBlocks(blocks [][]byte) []byte {
	output := make([]byte, 0)
	for i:=0; i<len(blocks); i++ {
		for j:=0; j<len(blocks[i]); j++ {
			output = append(output, blocks[i][j])
		}
	}
	return output
}

// Copy the contents of a block into a new block upto the limit
func copyBlocks(blocks [][]byte, limit int) [][]byte {
    newBlocks := make([][]byte, limit + 1) 
    for i:=0; i<=limit; i++ {
        newBlocks[i] = make([]byte, len(blocks[i]))
        for j:=0; j<len(blocks[i]); j++ {
            newBlocks[i][j] = blocks[i][j]
        }
    }
    //fmt.Println("\tcopy complete")
    return newBlocks
}

// Strip the message for processing
func stripMessage(msg []byte) []byte {
    n := int(msg[len(msg) - 1])
    msg_ := msg[:len(msg) - n]
    out := msg_[:len(msg_) - 32]
    return out
}

// Process the attack on the blocks
func processBlocks(ctBlocks [][]byte, block_index int, tempFile string) []byte {
    decrypted_block := make([]byte, aes.BlockSize)
    guessVal := 0x01

    for byte_index := aes.BlockSize - 1; byte_index >= 0; byte_index-- {
        for i := 0x01; i <= 0xFF; i++ {
            copiedBlocks := copyBlocks(ctBlocks, block_index + 1)
            
            // Do not test the padding as 1 on the last block
            if byte_index == aes.BlockSize - 1 && len(copiedBlocks) == len(ctBlocks) && i == 0x01 && guessVal == 0x01 {
                i++
            }
            
            for j := 0x00; j < guessVal; j++ {
                new_index := byte_index + j
                if new_index == byte_index {
                	//fmt.Println("\t",copiedBlocks[block_index][new_index])
                    copiedBlocks[block_index][new_index] = copiedBlocks[block_index][new_index] ^ byte(guessVal) ^ byte(i)
                	//fmt.Println("\t*",copiedBlocks[block_index][new_index])
                } else {
                	//fmt.Println("\t",copiedBlocks[block_index][new_index])
                	copiedBlocks[block_index][new_index] = copiedBlocks[block_index][new_index] ^ byte(guessVal) ^ decrypted_block[new_index]
                	//fmt.Println("\t*",copiedBlocks[block_index][new_index])
                }
            }
            
            newCipherText := concatenateBlocks(copiedBlocks)
            err_write := ioutil.WriteFile(tempFile, newCipherText, 0644)
			if err_write!=nil {
				fmt.Println("ERROR: ", err_write)
			}

            result, err_cmd := exec.Command("./decrypt-test", "-i", tempFile).Output()
			if err_cmd!=nil {
				fmt.Println("ERROR: ", err_cmd)
				showUsage()
				os.Exit(1)
			}
			result_str := string(result)

			if result_str!="INVALID PADDING" {
				decrypted_block[byte_index] = byte(i)
				break
            }
        }
        guessVal += 1
    }
    
    return decrypted_block
}

// Decryption Function
func Decrypt(cipherText []byte, tempFile string) string {
	blockCount := len(cipherText) / aes.BlockSize
	plainText := make([]byte, (blockCount - 1) * aes.BlockSize)

	ctBlocks := divideBlock(cipherText, aes.BlockSize)
	ptBlocks := divideBlock(plainText, aes.BlockSize)
	fmt.Println("\nStarting Attack..\n")

	// Decrypting, starting from the second last (n)th block 
	// to get the last plaintext (n-1)th block
	for i:=blockCount-2 ; i>=0 ; i-- {
		fmt.Println(" Attacking Block:", i)
		decrypted_block := processBlocks(ctBlocks, i, tempFile)
		ptBlocks[i] = decrypted_block
		fmt.Println(" * Decrypted Block:", i+1)
	}
	fmt.Println("\n")
	plainText = stripMessage(concatenateBlocks(ptBlocks))

	return string(plainText)
}

func main() {

	if len(os.Args) < 2 {
		showUsage()
		os.Exit(1)
	}

	cipherTextFile := os.Args[2]

	cipherText, err_fileopen := ioutil.ReadFile(cipherTextFile)
	if (err_fileopen != nil) {
		fmt.Println("Error - Reading the file: " + cipherTextFile + "\n\n")
		os.Exit(1)
	}

	//fmt.Println("\nCipherText:\n", cipherText)

	//ctVar := cipherText

	AesBlockSize := 16
	blockCount := len(cipherText)/AesBlockSize

	// Info
	fmt.Println("\nNumber of blocks in CipherText:", blockCount, "\n")
	encrypted_blocks := make([][]byte, blockCount - 1) // first block for the IV

	for i:=0; i<blockCount; i++ {

		if(i == 0) {
			iv := cipherText[i:(i+1)*16]
			fmt.Println("IV: ", iv)
		} else {
			encrypted_blocks[i-1] = cipherText[i*16:(i+1)*16]
			//fmt.Println("Encryped Block ", i-1, ":", encrypted_blocks[i-1])
		}
	}

	tempFile := cipherTextFile + ".temp"
	result := Decrypt(cipherText, tempFile)
	fmt.Println(result)

}