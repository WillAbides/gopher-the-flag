package main

import (
	"fmt"

	gtf "github.com/willabides/gopher-the-flag"
)

func main() {
	for {
		fmt.Println("Enter password:")
		var password []byte
		_, err := fmt.Scanln(&password)
		if err != nil {
			fmt.Println(err)
			continue
		}
		flag, err := gtf.Flag(password)
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Println(flag)
	}
}
