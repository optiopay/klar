package utils

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
)

func DumpRequest(r *http.Request) {
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't dump HTTP request %s\n", err.Error())
	} else {
		fmt.Fprintf(os.Stderr, "request_dump: %s\n", string(dump[:]))
	}
}

func DumpResponse(r *http.Response) {
	dump, err := httputil.DumpResponse(r, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't dump HTTP reqsponse %s\n", err.Error())
	} else {
		fmt.Fprintf(os.Stderr, "response_dump: %s\n", string(dump[:]))
	}
}
