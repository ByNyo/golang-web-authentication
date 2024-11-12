package utils

import "github.com/google/uuid"

func GenerateUUID() (string, error) {
	uid, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	return uid.String(), nil
}
