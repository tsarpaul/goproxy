package main

import (
	"crypto/tls"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	crand "crypto/rand"
	"math/big"
	"math/rand"
	"log"
	"time"
	"net"
	"net/http"
	"net/http/httputil"
	"io/ioutil"
	"os"
	"path"
	"fmt"
)

func check(e error) {
    if e != nil {
	panic(e)
    }
}

type CertManager struct {
	CACertPath 	string
	CAKeyPath    	string
	CertKeyPath  	string
	CertBankPath	string
}

func readDERKey(path string) (*rsa.PrivateKey, error) {
	keyRaw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(keyRaw)
	return key, err
}

func readDERCert(path string) (*x509.Certificate, error){
	certRaw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certRaw)
	return cert, err
}

func (c *CertManager) tryLoadCert(subject string, certPath string) (*tls.Certificate, error) {
	if _, err := os.Stat(certPath); err == nil {
		certKey, err := readDERKey(c.CertKeyPath)
		if err != nil {
			return nil, err
		}

		certRaw, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, err
		}

		certificate := &tls.Certificate{
			Certificate: [][]byte{certRaw},
			PrivateKey: certKey,
		}
		return certificate, nil
	} else if !os.IsNotExist(err){  // Any other error than ErrNotExist
		return nil, err
	}
	return nil, nil
}

func (c *CertManager) genCertificate(subject string) (*tls.Certificate, error) {
	// Try finding existing certificate for the target
	certPath := path.Join(c.CertBankPath, subject)
	cert, err := c.tryLoadCert(subject, certPath)
	if err != nil || cert != nil {
		return cert, err
	}

	// Generate a new certificate
	serialNumber := big.NewInt(rand.Int63())
	unsignedCert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{CommonName: subject},
		NotBefore: time.Now(),
		NotAfter: time.Date(2029, time.January, 0, 0, 0, 0, 0, time.UTC),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	CACertificate, err := readDERCert(c.CACertPath)
	if err != nil {
		return nil, err
	}
	CAKey, err := readDERKey(c.CAKeyPath)
	if err != nil {
		return nil, err
	}
	certKey, err := readDERKey(c.CertKeyPath)
	if err != nil {
		return nil, err 
	}

	signedCertRaw, err := x509.CreateCertificate(crand.Reader, unsignedCert, CACertificate, certKey.Public(), CAKey)
	if err != nil {
		return nil, err
	}
	// Save Cert to disk for the next time
	if err = ioutil.WriteFile(certPath, signedCertRaw, 0644); err != nil {
		return nil, err
	}	
	signedCert := &tls.Certificate{
		Certificate: [][]byte{signedCertRaw},
		PrivateKey: certKey,
	}
	return signedCert, nil
}

func (c *CertManager) GetCertificate(clientHelloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	subject := clientHelloInfo.ServerName
	return c.genCertificate(subject)
}

type ProxyHandler struct {
	TLSConfig *tls.Config
	CertManager *CertManager
	// TODO: addr where to reroute traffic
}

func (*ProxyHandler) handleConnect(conn net.Conn, r *http.Request) error {
	fmt.Println("Received CONNECT from ", r.Host)
	_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	return err
}

func (p *ProxyHandler) establishTLS(raw net.Conn) (net.Conn, error) {
	p.TLSConfig.GetCertificate = p.CertManager.GetCertificate
	conn := tls.Server(raw, p.TLSConfig)
	err := conn.Handshake()
	if err != nil {
		conn.Close()
		panic(err)
	}
	return conn, err
}

type connListener struct {
	c net.Conn
}
func (l *connListener) Accept() (net.Conn, error){
	return l.c, nil
}
func (l *connListener) Close() error {
	return l.c.Close()
}
func (l *connListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

func createReverseProxy(https bool) *httputil.ReverseProxy {
	modifyResponse := func (r *http.Response) error {
		dump, err := httputil.DumpResponse(r, true)
		if err != nil {
			return err
		}
		fmt.Println(string(dump))
		return nil
	}
	directorBasic := func(r *http.Request) {	
		r.URL.Host = r.Host
		dump, err := httputil.DumpRequestOut(r, true)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(dump))
	}
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			if https == true{
				r.URL.Scheme = "https"
			} else {
				r.URL.Scheme = "http"
			}
			directorBasic(r)
		},
		Transport: &http.Transport{DialTLS: func(network, addr string) (net.Conn, error) {
			return tls.Dial("tcp", addr, nil)
		}},
		ModifyResponse: modifyResponse,
	}
	if https == false {
		// Cancel TLS transport
		rp.Transport = nil
	}
	return rp
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request){
	if r.Method == "CONNECT" {
		raw, _, err := w.(http.Hijacker).Hijack()
		check(err)

		err = p.handleConnect(raw, r)
		check(err)

		cconn, err := p.establishTLS(raw)
		check(err)

		rp := createReverseProxy(true)
		listener := &connListener{c: cconn}
		err = http.Serve(listener, rp)
		check(err)
	} else {
		rp := createReverseProxy(false)
		rp.ServeHTTP(w, r)
	}
}

func main() {
	cwd, err := os.Getwd()
	check(err)
	handler := &ProxyHandler{
		CertManager: &CertManager{
			CACertPath:	path.Join(cwd, "cacert.der"),
			CAKeyPath: 	path.Join(cwd, "cakey.der"),
			CertKeyPath:	path.Join(cwd, "signkey.der"),
			CertBankPath:	path.Join(cwd, "certs"),
		},
		TLSConfig: &tls.Config{},
	}
	fmt.Printf("Listening at 0.0.0.0:8080\n")
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", handler))
}
