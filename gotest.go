package main

import "fmt"

func main() {
	m := make(map[string]bool)
	m["1"] = true

	fmt.Println(m["1"], m["0"])
}
