package websvr

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"gitee.com/cryptolab/crypto_cn/gmtls"
	"gitee.com/cryptolab/crypto_cn/x509"
)

var (
	pwd           = []byte("123456")
	sm2CaCertPath = "./certs/pki-sm2/ca.crt"
)

func loadCerts() ([]gmtls.Certificate, error) {
	pemdir := "./certs/pki-sm2"
	cerfiles := []string{"sign", "enc"}
	certs := make([]gmtls.Certificate, 0)
	for _, n := range cerfiles {
		certname := fmt.Sprintf("%s/issued/sm2-%s.crt", pemdir, n)
		certkey := fmt.Sprintf("%s/private/sm2-%s.key", pemdir, n)
		cer, err := gmtls.LoadX509KeyPairWithPassword(certname, certkey, pwd)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cer)
	}
	return certs, nil
}

func loadDemoCerts() ([]gmtls.Certificate, error) {
	pemdir := "./certs/demo"
	cerfiles := []string{"sign", "enc"}
	certs := make([]gmtls.Certificate, 0)
	for _, n := range cerfiles {
		certname := fmt.Sprintf("%s/ecc%ssite.pem", pemdir, n)
		certkey := fmt.Sprintf("%s/ecc%ssitekey.pem", pemdir, n)
		cer, err := gmtls.LoadX509KeyPair(certname, certkey)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cer)
	}
	return certs, nil
}

func loadAllCerts() ([]gmtls.Certificate, error) {
	pemdir := "./certs/pki-sm2"
	cerfiles := []string{"sign", "enc"}
	certs := make([]gmtls.Certificate, 0)
	for _, n := range cerfiles {
		certname := fmt.Sprintf("%s/issued/sm2-%s.crt", pemdir, n)
		certkey := fmt.Sprintf("%s/private/sm2-%s.key", pemdir, n)
		cer, err := gmtls.LoadX509KeyPairWithPassword(certname, certkey, pwd)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cer)
	}

	rsaPemdir := "./certs/pki-rsa"
	cerfiles = []string{"sign"}
	for _, n := range cerfiles {
		certname := fmt.Sprintf("%s/issued/rsa-%s.crt", rsaPemdir, n)
		certkey := fmt.Sprintf("%s/private/rsa-%s.key", rsaPemdir, n)
		cer, err := gmtls.LoadX509KeyPairWithPassword(certname, certkey, pwd)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cer)
	}

	return certs, nil
}

func ServerRun() {
	// config, err := LoadSm2Config(loadCerts)
	config, err := LoadAutoSwitchConfig(loadAllCerts)
	//config, err:=loadAutoSwitchConfigClientAuth()
	if err != nil {
		panic(err)
	}

	ln, err := gmtls.Listen("tcp4", ":50052", config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "hello\n")
	})
	fmt.Println(">> HTTP Over [GMSSL/TLS] running...")
	err = http.Serve(ln, nil)
	if err != nil {
		panic(err)
	}
}
func ClientRun() {
	var config = tls.Config{
		MaxVersion:         gmtls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp4", "127.0.0.1:50052", &config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	req := []byte("GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	conn.Write(req)

	buff := make([]byte, 1024)
	for {
		n, _ := conn.Read(buff)
		if n <= 0 {
			break
		} else {
			fmt.Printf("%s", buff[0:n])
		}
	}
	fmt.Println()
	end <- true
}
func gmClientRun() {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := os.ReadFile(sm2CaCertPath)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	// cert, err := gmtls.LoadX509KeyPair(sm2AuthCertPath, sm2AuthKeyPath)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	config := &gmtls.Config{
		GMSupport: &gmtls.GMSupport{},
		RootCAs:   certPool,
		// Certificates: []gmtls.Certificate{cert},
	}

	conn, err := gmtls.Dial("tcp4", "127.0.0.1:50052", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	req := []byte("GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	_, _ = conn.Write(req)
	buff := make([]byte, 1024)
	for {
		n, _ := conn.Read(buff)
		if n <= 0 {
			break
		} else {
			fmt.Printf("%s", buff[0:n])
		}
	}
	fmt.Println()
	end <- true
}

var end chan bool

func Test_tls(t *testing.T) {
	end = make(chan bool, 64)
	go ServerRun()
	time.Sleep(1000000)
	go ClientRun()
	<-end
	go gmClientRun()
	<-end
}

func Test_ServerRun(t *testing.T) {
	ServerRun()
}

func Test_gmClientRun(t *testing.T) {
	gmClientRun()
}
