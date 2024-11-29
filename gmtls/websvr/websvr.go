package websvr

import (
	"crypto/tls"
	x "crypto/x509"
	"errors"
	"os"

	"gitee.com/cryptolab/crypto_cn/gmtls"
	"gitee.com/cryptolab/crypto_cn/x509"
)

type loadCertsFunc func() ([]gmtls.Certificate, error)

func LoadSm2Config(loader loadCertsFunc) (*gmtls.Config, error) {
	if loader == nil {
		return nil, nil
	}
	certs, err := loader()
	if err != nil {
		return nil, err
	}
	return &gmtls.Config{
		GMSupport:    &gmtls.GMSupport{},
		Certificates: certs,
	}, nil
}

func LoadAutoSwitchConfig(loader loadCertsFunc) (*gmtls.Config, error) {
	if loader == nil {
		return nil, nil
	}
	certs, err := loader()
	if err != nil {
		return nil, err
	}
	if len(certs) != 3 {
		return nil, errors.New("certs number must be 3")
	}
	sigCert, encCert, rsaCert := certs[0], certs[1], certs[2]
	return gmtls.NewBasicAutoSwitchConfig(&sigCert, &encCert, &rsaCert)
}

// RSA配置
func LoadRsaConfigFromFile(rsaCertPath, rsaKeyPath string, pwd []byte) (*gmtls.Config, error) {
	cert, err := gmtls.LoadX509KeyPairWithPassword(rsaCertPath, rsaKeyPath, pwd)
	if err != nil {
		return nil, err
	}
	return &gmtls.Config{Certificates: []gmtls.Certificate{cert}}, nil
}

// SM2配置
func LoadSM2ConfigFromFile(
	sm2SignCertPath, sm2SignKeyPath string,
	sm2EncCertPath, sm2EncKeyPath string,
	pwd []byte,
) (*gmtls.Config, error) {
	sigCert, err := gmtls.LoadX509KeyPairWithPassword(sm2SignCertPath, sm2SignKeyPath, pwd)
	if err != nil {
		return nil, err
	}
	encCert, err := gmtls.LoadX509KeyPairWithPassword(sm2EncCertPath, sm2EncKeyPath, pwd)
	if err != nil {
		return nil, err
	}
	return &gmtls.Config{
		GMSupport:    &gmtls.GMSupport{},
		Certificates: []gmtls.Certificate{sigCert, encCert},
	}, nil
}

// 切换GMSSL/TSL
func LoadAutoSwitchConfigFromFile(
	rsaCertPath, rsaKeyPath string,
	sm2SignCertPath, sm2SignKeyPath string,
	sm2EncCertPath, sm2EncKeyPath string,
	pwd []byte,
) (*gmtls.Config, error) {
	rsaKeypair, err := gmtls.LoadX509KeyPairWithPassword(rsaCertPath, rsaKeyPath, pwd)
	if err != nil {
		return nil, err
	}
	sigCert, err := gmtls.LoadX509KeyPairWithPassword(sm2SignCertPath, sm2SignKeyPath, pwd)
	if err != nil {
		return nil, err
	}
	encCert, err := gmtls.LoadX509KeyPairWithPassword(sm2EncCertPath, sm2EncKeyPath, pwd)
	if err != nil {
		return nil, err

	}
	return gmtls.NewBasicAutoSwitchConfig(&sigCert, &encCert, &rsaKeypair)
}

// 要求客户端身份认证
func LoadAutoSwitchConfigClientAuthFromFile(
	rsaCertPath, rsaKeyPath string,
	sm2SignCertPath, sm2SignKeyPath string,
	sm2EncCertPath, sm2EncKeyPath string,
	pwd []byte,
) (*gmtls.Config, error) {
	config, err := LoadAutoSwitchConfigFromFile(
		rsaCertPath, rsaKeyPath,
		sm2SignCertPath, sm2SignKeyPath,
		sm2EncCertPath, sm2EncKeyPath,
		pwd,
	)
	if err != nil {
		return nil, err
	}
	// 设置需要客户端证书请求，标识需要进行客户端的身份认证
	config.ClientAuth = gmtls.RequireAndVerifyClientCert
	return config, nil
}

// 获取 客户端服务端双向身份认证 配置
func BothAuthConfig(sm2CaCertPath, sm2AuthCertPath, sm2AuthKeyPath string) (*gmtls.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := os.ReadFile(sm2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)
	authKeypair, err := gmtls.LoadX509KeyPair(sm2AuthCertPath, sm2AuthKeyPath)
	if err != nil {
		return nil, err
	}
	return &gmtls.Config{
		GMSupport:          &gmtls.GMSupport{},
		RootCAs:            certPool,
		Certificates:       []gmtls.Certificate{authKeypair},
		InsecureSkipVerify: false,
	}, nil

}

// 获取 单向身份认证（只认证服务端） 配置
func SingleSideAuthConfig(sm2CaCertPath string) (*gmtls.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := os.ReadFile(sm2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &gmtls.Config{
		GMSupport: &gmtls.GMSupport{},
		RootCAs:   certPool,
	}, nil
}

// 获取 客户端服务端双向身份认证 配置
func RsaBothAuthConfig(rsaCaCertPath, rsaAuthCertPath string, rsaAuthKeyPath string) (*tls.Config, error) {
	// 信任的根证书
	certPool := x.NewCertPool()
	cacert, err := os.ReadFile(rsaCaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)
	authKeypair, err := tls.LoadX509KeyPair(rsaAuthCertPath, rsaAuthKeyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MaxVersion:         tls.VersionTLS12,
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{authKeypair},
		InsecureSkipVerify: false,
	}, nil

}

// 获取 单向身份认证（只认证服务端） 配置
func RsaSingleSideAuthConfig(rsaCaCertPath string) (*tls.Config, error) {
	// 信任的根证书
	certPool := x.NewCertPool()
	cacert, err := os.ReadFile(rsaCaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &tls.Config{
		MaxVersion: tls.VersionTLS12,
		RootCAs:    certPool,
	}, nil
}
