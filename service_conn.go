package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

var PORT = "1812"
var GATE = "bad.lt.net"

func helpHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/help" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}

	fmt.Fprintf(w,"\nServer Port %s, Gateway %s\n", PORT, GATE)

	fmt.Fprintf(w,"jwt token is valid  : {\"code\":200}\n")
	fmt.Fprintf(w,"jwt token is invalid: {\"code\":401}\n")

	exa := "curl 'http://"+GATE+":1812/validate' -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJkZXZvcDAxQHBlZ2FzdXMwMUB1c2VyIiwiYXV0aCI6IlJPTEVfVEVOQU5UIiwiZXhwIjoxNjMwOTEzOTc5fQ.7XXsWUis1zh1EmLN6XPIOiglp6o_7k0aU8FR1DYQvz6fFg-s5eprUAco6aEScwNavye3u9r3VRSrnI_okEaxpQ'"
	fmt.Fprintf(w,"put jwt in reqest header to validate - Authorization \n\n")
	fmt.Fprintf(w,"%s\n", exa)
}

func jwtValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}

	jwt := r.Header.Get("Authorization")
	if  len(jwt) == 0 {
		http.Error(w, "\njwt token required", http.StatusBadRequest)
		return
	}

	req_url := "https://" + GATE + "/api/tenant/v1/users/current"

	req, err := http.NewRequest("GET", req_url, nil)
	if err != nil {
		log.Fatalln(err)
	}
	req.Header.Set("Authorization", jwt)

	tr := &http.Transport{ TLSClientConfig: &tls.Config{InsecureSkipVerify: true},	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	if strings.Contains(string(body), "username") {
		fmt.Fprintf(w,"{\"status\":200}")
	} else {
		fmt.Fprintf(w,"{\"status\":401}")
	}
}

func main() {
	if len(os.Args) == 2  {
		GATE = os.Args[1]
	}
	if len(os.Args) == 3  {
		PORT = os.Args[2]
	}

	http.HandleFunc("/help", helpHandler)
	http.HandleFunc("/validate", jwtValidateHandler)

	fmt.Printf("Server Port %s, Gateway %s\n", PORT, GATE)

	if err := http.ListenAndServe(":"+PORT, nil); err != nil {
		log.Fatal(err)
	}
}