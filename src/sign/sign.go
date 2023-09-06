package sign

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func gen_jwt(password string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "Authorization",
		"iss": "Jatelindo",
		"iat": time.Now().Unix(),
		"jti": "11123434",
	})

	tokenString, err := t.SignedString([]byte(password))

	if err != nil {
		return "Error", err
	}

	return tokenString, nil
}

func login_signature(apiKey, secret, tgl string) (string, error) {
	comstring := apiKey + ":" + secret + ":" + tgl
	res_sign1, err := RSA_sign(comstring)
	if err != nil {
		return "", err
	}
	signature := base64.StdEncoding.EncodeToString(res_sign1)

	return signature, nil
}

func balinqSignature(apiKey, secret, tgl, body string) (string, error) {
	// Balance Inquiry Signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{"customerId":"088294291652","channelId":"1"}`
	// [hashing : 63ea4efb-aa7b-4066-b83b-6ddc12619002:15716987-4f0d-4afd-b886-3c2e06daa77a:2023-07-14T04:32:12.700+07:00:{"customerId":"Member Test","channelId":"1"}]
	//            63ea4efb-aa7b-4066-b83b-6ddc12619002:15716987-4f0d-4afd-b886-3c2e06daa77a:2023-07-14T01:21:50.388+07:00:{"customerId": "Member Test", "channelId": "1"}
	comstring := apiKey + ":" + secret + ":" + tgl + ":" + body
	fmt.Print(comstring)
	res_sign1, err := RSA_sign(comstring)
	if err != nil {
		return "", err
	}
	signature := base64.StdEncoding.EncodeToString(res_sign1)
	return signature, nil
}

func gettrxdatetime() string {
	currentTime := time.Now().UTC()
	result1 := currentTime.Format("2006-01-02T15:04:05-07:00")
	return result1
}

func RSA_sign(data string) ([]byte, error) {
	var cert = []byte(`-----BEGIN CERTIFICATE-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDQUEKGMPhvEH98AdgG2aX9MFWn
YgzqGMUnt46hUVlp8WmYRUPCOb8sRFNmCzUzwPMqrkbGTg+vbvs6q9fhOt1O32CNLj0LcQ4dKOLMFCDPNr2l9hsqme1P
wnBZLhDuLt8LHtfClKC3DpRUJKKvYng/kwe8WtXQ8ueKfqLuLAqQ6Spz82EEt88SgMVNAdTZnOfPXP6oqRVZuy3+/LSB
KZMn86wBW902Gq7vBf36aHpGBxfsM3TcBTJC8kz3N+c99fQKWR+KDqWhEhzgcQMijgb3uHPMTqGzmT6IT643l+aUDcDM
+EzOasojXUEj06ZnoaMh17qCuox5ej6MrZXgTCoRAgMBAAECggEBAJepd2V/jcA+wLImHYOPPlxBrnq41jIxaojqCPvF
4FVTn89uzlA//sFZ1WY7zrYpSmDOlVSXTLArGtmydu/SDYH4+7CN83+7Bc2REN4H4YM7lYOY1FqFytMA+w7SjRz8HwNX
pzpRP1lHUhKYwaDzDh0rDLzDXVxNHOomHLVOdzrcVb5jg5PF/SMysOsCiKyiyiMn05Qxblbb39osBZRYJMMcw1/SA3WL
1kktVy60X3sxo7ilZODBmuig3/TrKKz+brxfqZWRmdKVhMZuDhUW9SgxGXbC2TePS5AqLV593Cl3a1aiSz1Mph/FdqT7
zOzOYU7NldebgsOWZJItVjtxqeECgYEA+6CeqItMrPQ14ofmVCZw3O+2FXcZl9TKcX9FNQmwp242qZZ7K4ihKRIg0XGS
ef3lFaAdXA/3+9pZUSHTCH0/dIUE+gYSYA5AnxH7ulHlRB9KZnzLSq3hpXPBy0t1rx5t1TEYH/JELndPcKIMWkGGBI1z
rf/rt3qV0Ngt/qpBbm0CgYEA0+70m1Vzq4Gw5qqxDo1cOr4/cUdsjzDoapILmxBXja0A7noWFSnV3xJYql8/GzqH+hu0
7w3hmuu/iR/hQC+TVdw71MsZ/PKiqqDkPHKA2kkfDh27aw3eo/8HsSZ4J49x3DtNXtskiklH7d/MM6tKBJmRo8YdHtk4
v68O+IXTE7UCgYEArz63IPUbKp1OZf11+YdoNUcxjhOLnIXTlGYqAf1ErecBZOzrzW7zptH8T0IE3Ldp87y2leZ9NEdm
yy1+dzwblIAL7kGKTKHAecihg6sDvIT6YRRq1RDyxTMwdfCQ/qx3m/H8NkuZFq97gRsq9TULLGKDfVxugzN54aCdr+5N
caUCgYEAhm3R1h2zyxvue8HVoSdlUxWN5Gqrn4AkTETq+6a4AnO0XZAvJaltsZtPhnH382uDCNA+SkwByGS1D2ObWz1S
NWoGwYk6qMm3CIgZfYYb2Vn8StXtJZCcomWIGYQPPvir/kfXYc2bNeQZrfcA7d0+jABk8v8dRY3/gwaldlpccukCgYEA
hMVb7p6CAVbwjUxqrmzSkhLJUy5zHGAi0mg5bLL/b6Ht215M2JQFpdFf+xwL/FXGacX4GCaHqAgOjVtwYt35/H8EZFx5
zO0VezEpJtgFv1+/eM2eBnHPcOcKMgFprZo56hmEXa4T/I6eZGaXyI49fbTOu5G8zblMEj0iCHeHDzc=
-----END CERTIFICATE-----`)

	block, _ := pem.Decode(cert)
	parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	key := parseResult.(*rsa.PrivateKey)

	if block == nil {
		return nil, errors.New("failed to decode pem block containing public key")
	}

	message := []byte(data)
	// SIGNATURE_ALGORITHM = "MD5withRSA"
	// hashed := md5.Sum(message)
	// SIGNATURE_ALGORITHM = "SHA1withRSA"
	hashed := sha1.Sum(message)
	// SIGNATURE_ALGORITHM = "SHA256withRSA"
	// hashed := sha256.Sum256(message)
	signature, _ := rsa.SignPKCS1v15(nil, key, crypto.SHA256, hashed[:])

	return signature, nil
}

func sign() {
	apiKey := "14674d2a-d782-11ed-a512-d0946603ce55"
	secret := "f307b55e9877c966599598d0b4a2625f"
	tgl := gettrxdatetime()

	// Login Signature
	comstring := apiKey + ":" + secret + ":" + tgl
	// payment channel signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{}`
	// Binding signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{"channelId":"1","customerId":"088294291652","description":"qatest's member 1234567812","notifUrl":"https://inauds.jatelindo.co.id/V1/jpa/pias/notify","callbackUrl":"https://mdl.fello.id/Api/Wallet/V1/Payment/Purchase/Confirm/Notif"}`
	// Unbinding signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{"customerId":"085813367572","channelId":"1"}`
	// Purchase signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{"channelId":"1","customerId":"Qatest-1234567812","description":"qatest's member 1234567812","amount":"1000","traceNumber":"202302210000126","notifUrl":"https://mdl.fello.id/Api/Wallet/V1/Payment/Purchase/Confirm/Notif","callbackUrl":"https://inauds.jatelindo.co.id/V1/jpa/pias/callback"}`
	// Direct Debit Signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{"customerId":"productive","channelId":"1","traceNumber":"20230522","amount":"3005"}`
	// Authorize signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{"channelId":"1","customerId":"08562233959","amount":"700","traceNumber":"202302210000042","notifUrl":"https://view-sandbox.fello.id/topup/direct-debit/register/notif","callbackUrl":"https://mdl.fello.id/Api/Wallet/V1/Payment/Purchase/Confirm/Notif"}`
	// Capture Signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{"ticketId":"27012023194523-08ecc97f-1142-4320-af97-f83ac322481d-18670","customerId":"08562233959","channelId":"1"}`
	// Reversal Signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{"traceNumber":"202301250000033","customerId":"NwFNMzg0NDdmMWQ0Zjk4ZWU2MDhiNzk5","channelId": "1"}`
	// Balance Inquiry Signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{"customerId":"088294291652","channelId":"1"}`
	// Transaction Status Signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{"traceNumber":"20230522"}`
	// Transaction History Signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{"customerId":"productive","channelId":"1","fromDate":"2023-05-21T00:00:00+07:00","toDate":"2023-05-22T23:59:59+07:00","currentPage":"0","pageSize":"175"}`
	// Payment Request Signature
	// comstring := apiKey + ":" + secret + ":" + tgl + ":" + `{"amount":"10000","traceNumber":"202301250000136","channelId":"0","description":"Description of Payment","notifUrl":"https://view-sandbox.fello.id/topup/direct-debit/register/notif","callbackUrl":"https://mdl.fello.id/Api/Wallet/V1/Payment/Purchase/Confirm/Notif"}`

	// data := "phone=15811352072&timestamp=1612496512540&device=Android"

	res_sign1, err := RSA_sign(comstring)
	if err != nil {
		fmt.Print(err)
		return
	}

	signature := base64.StdEncoding.EncodeToString(res_sign1)
	fmt.Print(signature)
}
