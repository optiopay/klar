package utils

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
)

var Trace bool

func DumpRequest(r *http.Request) {
	if !Trace {
		return
	}
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't dump HTTP request %s\n", err.Error())
	} else {
		fmt.Fprintf(os.Stderr, "----> HTTP REQUEST:\n%s\n", string(dump[:]))
	}
}

func DumpResponse(r *http.Response) {
	if !Trace {
		return
	}
	dump, err := httputil.DumpResponse(r, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't dump HTTP reqsponse %s\n", err.Error())
	} else {
		fmt.Fprintf(os.Stderr, "<---- HTTP RESPONSE:\n%s\n", string(dump[:]))
	}
}
