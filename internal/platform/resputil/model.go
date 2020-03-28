package resputil

import (
	"github.com/go-chi/render"
	// "github.com/go-chi/common"
	"net/http"
)

// ErrorResp is the json error response format
type ErrResp struct {
	// these ones are for internal consumption
	InternalError  error `json:"-"`
	InternalStatus int   `json:"-"`

	// these ones are for external / public.
	// Status int `json:"status, omitempty"`
	ErrCode int    `json:"code, omitempty"`
	ErrText string `json:"err, omitempty"`
}

func (e *ErrResp) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.InternalStatus)
	return nil
}

func RenderErr(err error, errStatus int) render.Renderer {
	return &ErrResp{
		InternalError:  err,
		InternalStatus: errStatus,
		ErrCode:        errStatus,
		ErrText:        err.Error(),
	}
}
