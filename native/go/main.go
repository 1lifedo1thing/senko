package main

/*
#include <stdint.h>
#include <string.h>
*/
import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/senko"
)

var nativeState struct {
	sync.Mutex
	instance *core.Instance
}

func nativeError(text string, out *C.char, cap C.int) C.int {
	if out == nil || cap <= 0 {
		return -1
	}
	bytes := []byte(text)
	limit := int(cap) - 1
	if len(bytes) > limit {
		bytes = bytes[:limit]
	}
	if len(bytes) > 0 {
		C.memcpy(unsafe.Pointer(out), unsafe.Pointer(&bytes[0]), C.size_t(len(bytes)))
	}
	*(*C.char)(unsafe.Add(unsafe.Pointer(out), len(bytes))) = 0
	return -1
}

//export SenkoNativeStart
func SenkoNativeStart(config *C.char, configLen C.int, tunFD C.int,
	errorOut *C.char, errorCap C.int) C.int {
	if config == nil || configLen <= 0 || tunFD < 0 {
		return nativeError("native core received an invalid configuration or utun fd",
			errorOut, errorCap)
	}

	bytes := C.GoBytes(unsafe.Pointer(config), configLen)
	nativeState.Lock()
	defer nativeState.Unlock()
	if nativeState.instance != nil {
		return nativeError("native core is already running", errorOut, errorCap)
	}

	if err := os.Setenv("XRAY_TUN_FD", strconv.Itoa(int(tunFD))); err != nil {
		return nativeError("could not publish the Network Extension utun fd: "+err.Error(),
			errorOut, errorCap)
	}
	instance, err := core.StartInstance("json", bytes)
	_ = os.Unsetenv("XRAY_TUN_FD")
	if err != nil {
		return nativeError("native core failed to start: "+err.Error(), errorOut, errorCap)
	}
	nativeState.instance = instance
	return 0
}

//export SenkoNativeStop
func SenkoNativeStop(errorOut *C.char, errorCap C.int) C.int {
	nativeState.Lock()
	defer nativeState.Unlock()
	if nativeState.instance == nil {
		return 0
	}
	instance := nativeState.instance
	nativeState.instance = nil
	if err := instance.Close(); err != nil {
		return nativeError("native core failed to stop: "+err.Error(), errorOut, errorCap)
	}
	return 0
}

//export SenkoNativeIsRunning
func SenkoNativeIsRunning() C.int {
	nativeState.Lock()
	running := nativeState.instance != nil
	nativeState.Unlock()
	if running {
		return 1
	}
	return 0
}

// SenkoNativeRunFile is senko-core's `run -c <path>` for senkod on jailbroken
// ios 12+: the tunnel descriptor arrives in XRAY_TUN_FD, and SIGTERM or SIGINT
// stops the core. the extension binary carries it so the package ships one go
// core instead of two copies of the same xray build
//
//export SenkoNativeRunFile
func SenkoNativeRunFile(path *C.char) C.int {
	if path == nil {
		fmt.Fprintln(os.Stderr, "Failed to start: no config path")
		return 23
	}
	bytes, err := os.ReadFile(C.GoString(path))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to start:", err)
		return 23
	}
	// subscribed before the core starts, so a stop sent while it comes up is kept
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	instance, err := core.StartInstance("json", bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to start:", err)
		return 23
	}
	runtime.GC()
	debug.FreeOSMemory()
	<-stop
	if err := instance.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to stop:", err)
		return 1
	}
	return 0
}

func main() {}
