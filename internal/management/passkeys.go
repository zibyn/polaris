package management

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"

	"github.com/zibyn/polaris/internal/passkey"
)

type listPasskeysOutput struct {
	Body struct {
		Passkeys []passkey.Passkey `json:"passkeys" nullable:"false" doc:"Oldest first"`
	}
}

func (s *Service) listPasskeys(ctx context.Context, in *struct {
	Sub string `path:"sub"`
}) (*listPasskeysOutput, error) {
	if err := s.ensureUser(ctx, in.Sub); err != nil {
		return nil, err
	}
	list, err := s.passkeys.List(ctx, in.Sub)
	if err != nil {
		return nil, err
	}
	out := &listPasskeysOutput{}
	out.Body.Passkeys = list
	return out, nil
}

// removePasskey is for a User who lost the device a Passkey lives on; the
// audit's by names the admin, which is what tells it from the User's own
// delete.
func (s *Service) removePasskey(ctx context.Context, in *struct {
	Sub string `path:"sub"`
	ID  string `path:"id"`
}) (*struct{}, error) {
	if err := s.mayManage(ctx, in.Sub); err != nil {
		return nil, err
	}
	err := s.passkeys.Remove(ctx, in.Sub, in.ID, callerSub(ctx))
	if errors.Is(err, passkey.ErrGone) {
		return nil, huma.Error404NotFound("no such Passkey")
	}
	return nil, err
}
