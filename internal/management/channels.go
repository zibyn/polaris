package management

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/mail"
	"regexp"

	"github.com/danielgtaylor/huma/v2"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
)

type listChannelsOutput struct {
	Body struct {
		Plugins  []channel.Plugin   `json:"plugins" nullable:"false"`
		Channels []channel.Settings `json:"channels" nullable:"false" doc:"At most one per Identifier kind"`
	}
}

func (s *Service) listChannels(ctx context.Context, _ *struct{}) (*listChannelsOutput, error) {
	out := &listChannelsOutput{}
	var err error
	out.Body.Plugins = channel.Plugins()
	out.Body.Channels, err = s.channels.List(ctx)
	return out, err
}

type kindPath struct {
	Kind string `path:"kind" enum:"phone,email"`
}

type putChannelInput struct {
	Kind string `path:"kind" enum:"phone,email"`
	Body struct {
		Plugin string            `json:"plugin"`
		Config map[string]string `json:"config" doc:"By field key; an empty secret field keeps the stored value"`
	}
}

func (s *Service) putChannel(ctx context.Context, in *putChannelInput) (*struct{}, error) {
	return nil, invalid(s.channels.Put(ctx, in.Kind, in.Body.Plugin, in.Body.Config, callerSub(ctx)))
}

func (s *Service) deleteChannel(ctx context.Context, in *kindPath) (*struct{}, error) {
	return nil, s.channels.Delete(ctx, in.Kind, callerSub(ctx))
}

type testChannelInput struct {
	Kind string `path:"kind" enum:"phone,email"`
	Body struct {
		To string `json:"to" doc:"E.164 phone number or email address"`
	}
}

type testChannelOutput struct {
	Body struct {
		Code string `json:"code" doc:"The code sent, to compare with the one received"`
	}
}

var e164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

func (s *Service) testChannel(ctx context.Context, in *testChannelInput) (*testChannelOutput, error) {
	if in.Kind == "phone" && !e164.MatchString(in.Body.To) {
		return nil, huma.Error422UnprocessableEntity("手机号须为国际格式,如 +8613800001111")
	}
	if a, err := mail.ParseAddress(in.Body.To); in.Kind == "email" && (err != nil || a.Address != in.Body.To) {
		return nil, huma.Error422UnprocessableEntity("邮箱格式不对")
	}
	ch, err := s.channels.Channel(ctx, in.Kind)
	if errors.Is(err, channel.ErrNotConfigured) {
		return nil, huma.Error404NotFound("还没有配置这类 Channel")
	} else if err != nil {
		return nil, err
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return nil, err
	}
	out := &testChannelOutput{}
	out.Body.Code = fmt.Sprintf("%06d", n)
	if err := ch.Send(ctx, in.Body.To, out.Body.Code); err != nil {
		return nil, huma.Error502BadGateway("发送失败:" + err.Error())
	}
	// Nothing in PG changed, so there is no transaction to share; the
	// recipient stays out of the log.
	detail, _ := json.Marshal(map[string]string{"kind": in.Kind, "by": callerSub(ctx)})
	return out, s.q.Audit(ctx, sqlc.AuditParams{Event: "channel.tested", Detail: detail})
}

// invalid turns an error safe to show the admin into a 422.
func invalid(err error) error {
	if msg, ok := errors.AsType[identity.Invalid](err); ok {
		return huma.Error422UnprocessableEntity(string(msg))
	}
	return err
}
