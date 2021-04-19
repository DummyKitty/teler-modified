package libinjection

/*
#cgo LDFLAGS: -linjection
#include "libinjection.h"
#include "libinjection_sqli.h"
#include "libinjection_xss.h"
*/
import "C"
import (
	"unsafe"
)

func IsSQLi(statement string) (bool, string) {
	var out [8]C.char
	pointer := (*C.char)(unsafe.Pointer(&out[0]))
	if found := C.libinjection_sqli(C.CString(statement), C.size_t(len(statement)), pointer); found == 1 {
		//output := C.GoBytes(unsafe.Pointer(&out[0]), 8)
		return true, "检测到SQL注入特征"
	}
	return false, ""
}

func IsXSS(input string) (bool,string) {
	if found := C.libinjection_xss(C.CString(input), C.size_t(len(input))); found == 1 {
		return true,"检测到XSS特征"
	}
	return false,""
}
