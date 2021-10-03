package main

// JK 090721
// SERVICE user.anfuyin--- 1812 1 root D---123 22

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"database/sql"
	"encoding/base32"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/schollz/websocket"
	"github.com/schollz/websocket/wsjson"
)

var GATE = "bad.lt.net"
var PORT = "1812"
var ZUHU = "1"
var SSHU = "root"
var SSHW = "Dev00p123"
var SSHP = "22"

// Compile templates on start of the application
var templates = template.Must(template.ParseFiles("static/upload.html"))

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
			//login_jwt null cause exception, continue
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

func connWebsocket(w http.ResponseWriter, r *http.Request) {

	t := time.Now().UTC()
	log.Printf("%v %v %v %s\n", r.RemoteAddr, r.Method, r.URL.Path, time.Since(t))

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusInternalError, "internal error")

	ctx, cancel := context.WithTimeout(r.Context(), time.Hour*120000)
	defer cancel()

	for {
		var v interface{}
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			break
		}
		log.Printf("received: %v", v)
		err = wsjson.Write(ctx, c, struct{ Message string }{
			"hello, browser",
		})
		if err != nil {
			break
		}
	}
	if websocket.CloseStatus(err) == websocket.StatusGoingAway {
		err = nil
	}
	c.Close(websocket.StatusNormalClosure, "")
	return
}

func perfTestBench(w http.ResponseWriter, r *http.Request) {
	// best performance
	fmt.Printf("_")
	fmt.Fprintf(w, "ok")
}

func oneTimePwdGen(w http.ResponseWriter, r *http.Request) {
	pwd, secondsRemaining := otpGen(GATE)
	html := "<head><meta http-equiv=\"refresh\" content=\"10\" /></head>"

	fmt.Fprintf(w,"%s\n", html)
	fmt.Fprintf(w,"<body>%06d &#8592; %d second(s) remaining</body>\n", pwd, secondsRemaining)
}

func sche_task(t time.Time ) {
	fmt.Println("task ", t)
}

func scheduleT(ticker *time.Ticker, done chan bool  ) {
	for {
		select {
		case <-done:
			return
		case t := <-ticker.C:
			sche_task(t)
		}
	}
}

func toBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	shifts := [8]uint16{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func toUint32(bytes []byte) uint32 {
	return (uint32(bytes[0]) << 24) + (uint32(bytes[1]) << 16) +
		(uint32(bytes[2]) << 8) + uint32(bytes[3])
}

func oneTimePassword(key []byte, value []byte) uint32 {
	// sign the value using HMAC-SHA1
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(value)
	hash := hmacSha1.Sum(nil)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	offset := hash[len(hash)-1] & 0x0F

	// get a 32-bit (4-byte) chunk from the hash starting at offset
	hashParts := hash[offset : offset+4]

	// ignore the most significant bit as per RFC 4226
	hashParts[0] = hashParts[0] & 0x7F

	number := toUint32(hashParts)

	// size to 6 digits
	// one million is the first number with 7 digits so the remainder
	// of the division will always return < 7 digits
	pwd := number % 1000000

	return pwd
}

// Display the named template
func display(w http.ResponseWriter, page string, data interface{}) {
	templates.ExecuteTemplate(w, page+".html", data)
}

func uploadFileHdl(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		display(w, "upload", nil)
	case "POST":
		uploadFile(w, r)
	}
}

func uploadFile(w http.ResponseWriter, r *http.Request) {
	// Maximum upload of 10 MB files
	r.ParseMultipartForm(10 << 20)

	// Get handler for filename, size and headers
	file, handler, err := r.FormFile("myFile")
	if err != nil {
		fmt.Println("Error Retrieving the File")
		fmt.Println(err)
		return
	}

	defer file.Close()
	fmt.Printf("Uploaded File: %+v\n", handler.Filename)
	fmt.Printf("File Size: %+v\n", handler.Size)
	fmt.Printf("MIME Header: %+v\n", handler.Header)

	// Create file
	dst, err := os.Create("temp/" + handler.Filename)
	defer dst.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy the uploaded file to the created file on the filesystem
	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Successfully Uploaded File\n")
}

// all []byte in this program are treated as Big Endian
// https://github.com/robbiev/two-factor-auth
func otpGen(input string) (uint32, int64) {
	input = strings.Replace(os.Args[1], " ", "", -1)
	input = strings.Replace(input, ".", "", -1)
	input = strings.ToUpper(input)

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// generate a one-time password using the time at 30-second intervals
	epochSeconds := time.Now().Unix()
	pwd := oneTimePassword(key, toBytes(epochSeconds/30))

	secondsRemaining := 30 - (epochSeconds % 30)
	fmt.Printf("%06d (%d second(s) remaining)\n", pwd, secondsRemaining)
	return pwd, secondsRemaining
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

	for i:= 3; i>=0; i-- {
		fmt.Printf("\033[2K\r%d", i)
		time.Sleep(1 * time.Second)
	}
	fmt.Println()

	/* // https://gobyexample.com/tickers
	ticker := time.NewTicker(5000 * time.Millisecond)
	done := make(chan bool)

	for {
		select {
		case <-done:
			return
		case t := <-ticker.C:
			sche_task(t)
		}
	}
	//scheduleT(ticker, done)  */

	fileWebRoot := http.FileServer(http.Dir("./static"))
	fileUploads := http.FileServer(http.Dir("./temp"))

	mux := http.NewServeMux()
	mux.Handle("/", fileWebRoot)
	mux.Handle("/files/",  http.StripPrefix("/files", fileUploads))

	mux.HandleFunc("/test", formHandler)
	mux.HandleFunc("/help", helpHandler)
	mux.HandleFunc("/perf", perfTestBench)
	mux.HandleFunc("/validate", jwtValidateHandler)
	mux.HandleFunc("/services", dataServices)
	mux.HandleFunc("/remotecs", sshConnection)
	mux.HandleFunc("/webscket", connWebsocket)
	mux.HandleFunc("/otpasswd", oneTimePwdGen)
	mux.HandleFunc("/myupload", uploadFileHdl)

	fmt.Printf("Server Port %s, Gateway %s\n", PORT, GATE)

	if err := http.ListenAndServe(":"+PORT, mux); err != nil {
		log.Fatal(err)
	}
}

// https://tutorialedge.net/golang/golang-mysql-tutorial/
// https://blog.logrocket.com/creating-a-web-server-with-golang/
// https://gist.github.com/vinzenz/d8e6834d9e25bbd422c14326f357cce0
// https://www.honeybadger.io/blog/go-web-services/
// https://schollz.com/blog/websockets-with-golang/

// "github.com/carlescere/scheduler"
// "github.com/go-co-op/gocron"

// https://gabrieltanner.org/blog/golang-file-uploading
// https://www.alexedwards.net/blog/serving-static-sites-with-go
