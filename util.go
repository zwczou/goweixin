package goweixin

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
func RandString(n int) string {
	b := make([]byte, n)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// 将map[interface{}]interface{}跟结构体转换为map[string]string
func ToData(raw interface{}, t string) (data map[string]string) {
	data = make(map[string]string)
	if raw == nil {
		return data
	}
	if val, ok := raw.(map[string]string); ok {
		return val
	}
	val := reflect.Indirect(reflect.ValueOf(raw))
	if val.Kind() == reflect.Struct {
		typeOfT := val.Type()
		for i := 0; i < val.NumField(); i++ {
			keyField := typeOfT.Field(i)
			valField := val.Field(i)
			if !valField.IsValid() {
				continue
			}
			tags := keyField.Tag.Get(t)
			tag := strings.Split(tags, ",")[0]
			if tag == "-" {
				continue
			}
			if tag == "" {
				tag = keyField.Name
			}

			if strings.Contains(tags, "omitempty") {
				switch valField.Kind() {
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint32, reflect.Uint64:
					if valField.Int() == 0 {
						continue
					}
				case reflect.Float32, reflect.Float64:
					if valField.Float() == 0 {
						continue
					}
				case reflect.Bool:
					if !valField.Bool() {
						continue
					}
				case reflect.String:
					if valField.String() == "" {
						continue
					}
				case reflect.Interface:
					if valField.Interface() == nil {
						continue
					}
				case reflect.Ptr:
					if valField.IsNil() {
						continue
					}
				case reflect.Struct:
					if valField.NumField() == 0 {
						continue
					}
				}
			}
			if valField.Interface() == nil || (valField.Kind() == reflect.Struct && valField.NumField() == 0) {
				data[tag] = ""
			} else {
				data[tag] = fmt.Sprint(valField.Interface())
			}
		}
	} else if val.Kind() == reflect.Map {
		for _, key := range val.MapKeys() {
			value := val.MapIndex(key).Interface()
			if value == nil {
				data[fmt.Sprint(key.Interface())] = ""
			} else {
				data[fmt.Sprint(key.Interface())] = fmt.Sprint(value)
			}
		}
	}
	return
}
