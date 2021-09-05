package main

// https://blog.logrocket.com/creating-a-web-server-with-golang/

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
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

	fmt.Fprintf(w,"\njwt token is valid  : {\"code\":200}\n")
	fmt.Fprintf(w,"jwt token is invalid: {\"code\":401}\n\n")

	host := "CONN"
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		fmt.Printf("cannot find IP\n")
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				host = ipnet.IP.String()
			}
		}
	}

	exa := "curl 'http://" + host +":1812/validate' -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJkZXZvcDAxQHBlZ2FzdXMwMUB1c2VyIiwiYXV0aCI6IlJPTEVfVEVOQU5UIiwiZXhwIjoxNjMwOTEzOTc5fQ.7XXsWUis1zh1EmLN6XPIOiglp6o_7k0aU8FR1DYQvz6fFg-s5eprUAco6aEScwNavye3u9r3VRSrnI_okEaxpQ'"
	fmt.Fprintf(w,"put jwt in reqest header to validate - Authorization \n\n")
	fmt.Fprintf(w,"%s\n", exa)
}

func sendJWTreq(jwt string) string {
	req_url := "https://" + GATE + "/api/tenant/v1/users/current"

	req, err := http.NewRequest("GET", req_url, nil)
	if err != nil {
		log.Fatalln(err)
	}

	if ! strings.Contains(jwt, "Bearer ") {
		jwt = "Bearer " + jwt
	}
	req.Header.Set("Authorization", jwt)

	tr := &http.Transport{ TLSClientConfig: &tls.Config{InsecureSkipVerify: true},	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("%s\n%s\n%s\n", req_url, jwt, req.Header)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	return string(body)
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

	resp_body := sendJWTreq(jwt)

	if strings.Contains(resp_body, "username") {
		fmt.Fprintf(w,"{\"status\":200}")
	} else {
		fmt.Fprintf(w,"{\"status\":401}")
	}
}

func formHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}
	jwt := r.FormValue("jwt")

	resp_body := sendJWTreq(jwt)
	fmt.Fprintf(w, "%s\n", resp_body)
}

func main() {
	if len(os.Args) == 2  {
		GATE = os.Args[1]
	}
	if len(os.Args) == 3  {
		GATE = os.Args[1]
		PORT = os.Args[2]
	}

	fileServer := http.FileServer(http.Dir("./static"))

	http.Handle("/", fileServer)
	http.HandleFunc("/test", formHandler)
	http.HandleFunc("/help", helpHandler)
	http.HandleFunc("/validate", jwtValidateHandler)

	fmt.Printf("Server Port %s, Gateway %s\n", PORT, GATE)

	if err := http.ListenAndServe(":"+PORT, nil); err != nil {
		log.Fatal(err)
	}
}