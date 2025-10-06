package service

import "net/http"

type DummyHTTP struct {
	runner *Runner
}

func (d DummyHTTP) Start(w http.ResponseWriter, r *http.Request) {

}
