// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Response struct {
	CurrentTime string
}

func main() {
	port := ":43111"
	listen := "localhost" + port
	assets := "webapp"
	http.Handle("/", http.FileServer(http.Dir(assets)))
	fmt.Printf("point browser to: %v\n", listen)
	fmt.Printf("serving from    : %v\n", assets)

	http.HandleFunc("/test", func(rw http.ResponseWriter, r *http.Request) {
		byteArray, err := json.Marshal(Response{
			CurrentTime: time.Now().Format(time.RFC3339),
		})
		if err != nil {
			fmt.Println(err)
		}
		rw.Write(byteArray)
	})

	if err := http.ListenAndServe(listen, nil); err != nil {
		log.Fatal(err)
	}
}
