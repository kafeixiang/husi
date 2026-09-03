package libcore

import (
	"github.com/enfein/mieru/v3/apis/trafficpattern"
)

func DecodeMieruTrafficPattern(encoded string) (string, error) {
	jsonBytes, err := trafficpattern.DecodeBase64JSON(encoded)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

func EncodeMieruTrafficPattern(jsonText string) (string, error) {
	return trafficpattern.EncodeJSONBase64(jsonText)
}
