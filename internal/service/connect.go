package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"connectrpc.com/connect"
)

// jsonCodec lets Connect serve plain Go structs as application/json; the
// registry API is JSON-only and needs no protobuf codegen of its own.
type jsonCodec struct{}

func (jsonCodec) Name() string { return "json" }

func (jsonCodec) Marshal(v any) ([]byte, error)   { return json.Marshal(v) }
func (jsonCodec) Unmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// toConnectError maps domain errors to Connect status codes.
func toConnectError(err error) error {
	switch {
	case errors.Is(err, ErrVersionConflict):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, ErrValidation), errors.Is(err, ErrCompile):
		return connect.NewError(connect.CodeInvalidArgument, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// unary adapts a plain Go method to a Connect unary handler.
func unary[Req, Resp any](procedure string, fn func(context.Context, *Req) (*Resp, error)) (string, http.Handler) {
	h := connect.NewUnaryHandler(procedure,
		func(ctx context.Context, r *connect.Request[Req]) (*connect.Response[Resp], error) {
			resp, err := fn(ctx, r.Msg)
			if err != nil {
				return nil, toConnectError(err)
			}
			return connect.NewResponse(resp), nil
		},
		connect.WithCodec(jsonCodec{}),
	)
	return procedure, h
}

// NewHandler mounts the registry API on a mux.
func NewHandler(svc *Service) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(unary("/registry.v1.Registry/Publish", svc.Publish))
	mux.Handle(unary("/registry.v1.Registry/Check", svc.Check))
	mux.Handle(unary("/registry.v1.Registry/GetVersion", svc.GetVersion))
	mux.Handle(unary("/registry.v1.Registry/DeclareConsumer", svc.DeclareConsumer))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}
