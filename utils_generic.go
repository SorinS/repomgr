package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"regexp"
	"sort"
	"unsafe"
)

func ConvertToString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return string(v)
	case []byte:
		return string(v)
	case CanConvertToString:
		return v.String()
	default:
		return "*** NotStringConvertible ***"
	}
}

// IsNativeEndianLittle - returns true if little endian - from gokrb5/keytab/keytab.go
func IsNativeEndianLittle() bool {
	var x = 0x012345678
	var p = unsafe.Pointer(&x)
	var bp = (*[4]byte)(p)

	var endian bool
	if 0x01 == bp[0] {
		endian = false
	} else if (0x78 & 0xff) == (bp[0] & 0xff) {
		endian = true
	} else {
		// Default to big endian
		endian = false
	}
	return endian
}

func SetIfEmpty[T comparable](t *T, v T) {
	var zero T
	if *t == zero {
		*t = v
	}
}

func SliceContains[T comparable](s []T, toFind T) bool {
	for _, el := range s {
		if el == toFind {
			return true
		}
	}
	return false
}

func MakeID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func IsValidUUID(uuid string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")
	return r.MatchString(uuid)
}

func CheckNotEmpty[T comparable](values []T) error {
	var zero T
	for _, value := range values {
		if value == zero {
			return fmt.Errorf("value not expected to be empty: %s", ConvertToString(value))
		}
	}
	return nil
}

func ExecTemplate(fun template.FuncMap, tmpl string) (string, error) {
	buf := new(bytes.Buffer)
	tpl, err := template.New("template").Funcs(fun).Parse(tmpl)
	if err != nil {
		return "", err
	}
	err = tpl.Execute(buf, nil)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func DoIfNotNil(val interface{}, action func(interface{})) {
	if val != nil {
		action(val)
	}
}

func ValOrDefault[T comparable](val T, defaultVal T) T {
	var zero T
	if val != zero {
		return val
	}
	return defaultVal
}

func CopyMap[K comparable, V any](original map[K]V, copier ...func(V) V) map[K]V {
	if original == nil {
		return nil
	}

	copyOfMap := make(map[K]V)

	for key, value := range original {
		if len(copier) > 0 {
			copyOfMap[key] = copier[0](value)
		} else {
			copyOfMap[key] = value
		}
	}

	return copyOfMap
}

func CopySlice[T any](original []T, copier ...func(T) T) []T {
	if original == nil {
		return nil
	}

	var copyOfList = make([]T, len(original), len(original))

	for i := 0; i < len(original); i++ {
		if len(copier) > 0 {
			copyOfList[i] = copier[0](original[i])
		} else {
			copyOfList[i] = original[i]
		}

	}

	return copyOfList
}

func CopyPointer[T any](original *T, copier ...func(T) T) *T {
	if original == nil {
		return nil
	}

	var copyOfValue T
	if len(copier) > 0 {
		copyOfValue = copier[0](*original)
	} else {
		copyOfValue = *original
	}

	return &copyOfValue
}

func IndexOf[T comparable](s []T, x T) (int, error) {
	for i, v := range s {
		if v == x {
			return i, nil
		}
	}
	return 0, errors.New("not found")
}

// Map turns a []T1 to a []T2 using a mapping function.
func Map[T1, T2 any](s []T1, f func(T1) T2) []T2 {
	r := make([]T2, len(s))
	for i, v := range s {
		r[i] = f(v)
	}
	return r
}

// Filter filters values from a slice using a filter function.
// It returns a new slice with only the elements of s for which f returned true.
func Filter[T any](s []T, f func(T) bool) []T {
	var r []T
	for _, v := range s {
		if f(v) {
			r = append(r, v)
		}
	}
	return r
}

// Merge - receives slices of type T and merges them into a single slice of type T.
func Merge[T any](slices ...[]T) (mergedSlice []T) {
	for _, slice := range slices {
		mergedSlice = append(mergedSlice, slice...)
	}
	return mergedSlice
}

// Includes - given a slice of type T and a value of type T,
// determines whether the value is contained by the slice.
func Includes[T comparable](slice []T, value T) bool {
	for _, el := range slice {
		if el == value {
			return true
		}
	}
	return false
}

// Reduce reduces a []T1 to a single value using a reduction function.
func ReduceFunc[T1, T2 any](s []T1, initializer T2, f func(T2, T1) T2) T2 {
	r := initializer
	for _, v := range s {
		r = f(r, v)
	}
	return r
}

// // Sort - sorts given a slice of any orderable type T
// The constraints.Ordered constraint in the Sort() function guarantees that
// the function can sort values of any type supporting the operators <, <=, >=, >.
func Sort[T Ordered](s []T) {
	sort.Slice(s, func(i, j int) bool {
		return s[i] < s[j]
	})
}

func Last[T any](s []T) T {
	return s[len(s)-1]
}
