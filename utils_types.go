package main

type KeyValue[K comparable, V any] struct {
	Key   K
	Value V
}

type Ordered interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64 |
		~string
}

type ConvertibleToString interface {
	~[]byte | ~string
}

type CanConvertToString interface {
	String() string
}

type Int interface {
	~int | int8 | int16 | int32
}
