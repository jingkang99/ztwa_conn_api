package main

// JK 090721
// SERVICE 1812 user.anfu.com 3 root Dev--p123 22

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var GATE = "bad.lt.net"
var PORT = "1812"
var ZUHU = "1"
var SSHU = "root"
var SSHW = "Dev00p123"
var SSHP = "22"

const SQLU = "select id,username,full_name,email,phone,login_date,login_jwt from user where is_enabled = 1 and activated = 1 and is_deleted = 0 and role='user' and tenant_id = "

type User struct {
	id			int64
	username	string
	full_name	string
	email		string
	phone		string
	login_date	string
	login_jwt	string
}

type ViaSSHDialer struct {
	client *ssh.Client
}

func (self *ViaSSHDialer) Dial(addr string) (net.Conn, error) {
	return self.client.Dial("tcp", addr)
}

func sshConnection(w http.ResponseWriter, r *http.Request) {
	dbUser := "root"           // DB username
	dbPass := ""               // DB Password
	dbHost := "localhost:3306" // DB Hostname/IP
	dbName := "tistargate"     // Database name

	var agentClient agent.Agent
	// Establish a connection to the local ssh-agent
	if conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		defer conn.Close()

		// Create a new instance of the ssh agent
		agentClient = agent.NewClient(conn)
	}

	// The client configuration with configuration option to use the ssh-agent
	sshConfig := &ssh.ClientConfig{
		User:            SSHU,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// When the agentClient connection succeeded, add them as AuthMethod
	if agentClient != nil {
		sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeysCallback(agentClient.Signers))
	}

	// When there's a non empty password add the password AuthMethod
	if SSHW != "" {
		sshConfig.Auth = append(sshConfig.Auth, ssh.PasswordCallback(func() (string, error) {
			return SSHW, nil
		}))
	}

	// Connect to the SSH Server
	sshcon, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", GATE, SSHP), sshConfig)
	if err != nil {
		fmt.Fprintf(w, "ssh conn err: %v", err)
		return
	}
	defer sshcon.Close()
	fmt.Printf("connected to the host %s %s\n", GATE, SSHP)

	// Now we register the ViaSSHDialer with the ssh connection as a parameter
	mysql.RegisterDial("mysql+tcp", (&ViaSSHDialer{sshcon}).Dial)

	// And now we can use our new driver with the regular mysql connection string tunneled through the SSH connection
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@mysql+tcp(%s)/%s", dbUser, dbPass, dbHost, dbName))
	if err != nil {
		fmt.Fprintf(w, "db ssh conn err: %v", err)
		return
	}
	fmt.Printf("connected to the db %s@%s\n", dbHost, dbName)

	rows, err := db.Query(SQLU + ZUHU)
	if err != nil {
		fmt.Fprintf(w, "data query err: %v", err)
		return
	}
	//fmt.Printf(SQLU + ZUHU + "\n")

	for rows.Next() {
		var user User
		err = rows.Scan(&user.id, &user.username, &user.full_name, &user.email, &user.phone, &user.login_date, &user.login_jwt)
		if err != nil {
			fmt.Printf("data row err: %v", err)
			return
		}
		fmt.Fprintf(w, "%d,%s,%s,%s,%s,%s,%s\n", user.id, user.username, user.full_name, user.email, user.phone, user.login_date, user.login_jwt)
	}
	rows.Close()
}

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
	fmt.Fprintf(w,"%s\n\n", exa)

	fmt.Fprintf(w,"Service Start:\n")
	fmt.Fprintf(w,"  %s GATEWAY_DOMAIN SERVICE_PORT TENANT_ID SSH_USER SSH_PASSWORD SSH_PORT\n", os.Args[0])
	fmt.Fprintf(w,"  example:\n  %s %s %s %s %s %s %s \n", os.Args[0], GATE, PORT, ZUHU, "USR", "PWD", SSHP)
}

func sendJWTreq(jwt string) string {
	req_url := "https://" + GATE + "/api/tenant/v1/users/current"

	req, err := http.NewRequest("GET", req_url, nil)
	if err != nil {
		log.Printf(err.Error())
		return "{}"
	}

	if ! strings.Contains(jwt, "Bearer ") {
		jwt = "Bearer " + jwt
	}
	req.Header.Set("Authorization", jwt)

	tr := &http.Transport{ TLSClientConfig: &tls.Config{InsecureSkipVerify: true},	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf(err.Error())
		return "{}"
	}

	fmt.Printf("%s\n%s\n%s\n", req_url, jwt, req.Header)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf(err.Error())
		return "{}"
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

func dataServices(w http.ResponseWriter, r *http.Request) {

	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/tistargate?charset=utf8")
	if err != nil {
		fmt.Fprintf(w, "data source err: %v", err)
		return
	}
	defer db.Close()

	rows, err := db.Query(SQLU + ZUHU)
	if err != nil {
		fmt.Fprintf(w, "data query err: %v", err)
		return
	}

	for rows.Next() {
		var user User
		err = rows.Scan(&user.id, &user.username, &user.full_name, &user.email, &user.phone, &user.login_date, &user.login_jwt)
		if err != nil {
			fmt.Printf("data row err: %v", err)
			return
		}
		fmt.Fprintf(w, "%d,%s,%s,%s,%s,%s,%s\n", user.id, user.username, user.full_name, user.email, user.phone, user.login_date, user.login_jwt)
	}
	rows.Close()
}

func main() {
	if len(os.Args) > 1 {
		GATE = os.Args[1]
	}
	if len(os.Args) > 2 {
		PORT = os.Args[2]
	}
	if len(os.Args) > 3 {
		ZUHU = os.Args[3]
	}
	if len(os.Args) > 4 {
		SSHU = os.Args[4]
	}
	if len(os.Args) > 5 {
		SSHW = os.Args[5]
	}
	if len(os.Args) > 6 {
		SSHP = os.Args[6]
	}

	fileServer := http.FileServer(http.Dir("./static"))

	http.Handle("/", fileServer)
	http.HandleFunc("/test", formHandler)
	http.HandleFunc("/help", helpHandler)
	http.HandleFunc("/validate", jwtValidateHandler)
	http.HandleFunc("/services", dataServices)
	http.HandleFunc("/remotecs", sshConnection)

	fmt.Printf("Server Port %s, Gateway %s\n", PORT, GATE)

	if err := http.ListenAndServe(":"+PORT, nil); err != nil {
		log.Fatal(err)
	}
}

// https://tutorialedge.net/golang/golang-mysql-tutorial/
// https://blog.logrocket.com/creating-a-web-server-with-golang/
// https://gist.github.com/vinzenz/d8e6834d9e25bbd422c14326f357cce0
