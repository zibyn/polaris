package management

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"

	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/provider"
)

type ProviderInfo struct {
	provider.Settings
	CallbackURL string `json:"callbackUrl" doc:"Where the Provider sends the browser back to; register it upstream"`
}

type listProvidersOutput struct {
	Body struct {
		Types     []provider.Type `json:"types" nullable:"false"`
		Providers []ProviderInfo  `json:"providers" nullable:"false" doc:"Oldest first, the login page's order"`
	}
}

func (s *Service) listProviders(ctx context.Context, _ *struct{}) (*listProvidersOutput, error) {
	list, err := s.providers.List(ctx)
	if err != nil {
		return nil, err
	}
	out := &listProvidersOutput{}
	out.Body.Types = provider.Types()
	out.Body.Providers = []ProviderInfo{}
	for _, p := range list {
		out.Body.Providers = append(out.Body.Providers, ProviderInfo{Settings: p, CallbackURL: provider.CallbackURL(s.issuer, p.ID)})
	}
	return out, nil
}

type ProviderSettings struct {
	Name   string            `json:"name" doc:"Shown on the login page: 使用 {name} 登录"`
	Config map[string]string `json:"config" doc:"By field key; an empty secret field keeps the stored value"`
}

type createProviderInput struct {
	Body struct {
		ID   string `json:"id" doc:"Provider ID: a slug in the callback URL, never changed"`
		Type string `json:"type" doc:"A Provider type's key"`
		ProviderSettings
	}
}

func (s *Service) createProvider(ctx context.Context, in *createProviderInput) (*struct{}, error) {
	b := in.Body
	return nil, providerErr(s.providers.Create(ctx, b.ID, b.Type, b.Name, b.Config, callerSub(ctx)))
}

type providerPath struct {
	ID string `path:"id"`
}

func (s *Service) updateProvider(ctx context.Context, in *struct {
	ID   string `path:"id"`
	Body ProviderSettings
}) (*struct{}, error) {
	return nil, providerErr(s.providers.Update(ctx, in.ID, in.Body.Name, in.Body.Config, callerSub(ctx)))
}

func (s *Service) enableProvider(ctx context.Context, in *providerPath) (*struct{}, error) {
	return nil, providerErr(s.providers.SetEnabled(ctx, in.ID, true, callerSub(ctx)))
}

func (s *Service) disableProvider(ctx context.Context, in *providerPath) (*struct{}, error) {
	return nil, providerErr(s.providers.SetEnabled(ctx, in.ID, false, callerSub(ctx)))
}

func (s *Service) deleteProvider(ctx context.Context, in *providerPath) (*struct{}, error) {
	return nil, providerErr(s.providers.Delete(ctx, in.ID, callerSub(ctx)))
}

type listExternalIdentitiesOutput struct {
	Body struct {
		ExternalIdentities []provider.ExternalIdentity `json:"externalIdentities" nullable:"false"`
	}
}

func (s *Service) listExternalIdentities(ctx context.Context, in *subPath) (*listExternalIdentitiesOutput, error) {
	list, err := s.providers.ExternalIdentities(ctx, in.Sub)
	out := &listExternalIdentitiesOutput{}
	out.Body.ExternalIdentities = list
	return out, err
}

// unbindExternalIdentity is for a User who lost their account upstream
// (an Apple ID, say); the admin checked who they are offline.
func (s *Service) unbindExternalIdentity(ctx context.Context, in *struct {
	Sub      string `path:"sub"`
	Provider string `path:"provider"`
}) (*struct{}, error) {
	if err := s.mayManage(ctx, in.Sub); err != nil {
		return nil, err
	}
	err := s.providers.Unbind(ctx, in.Sub, in.Provider, callerSub(ctx))
	switch {
	case errors.Is(err, identity.ErrNotBound):
		return nil, huma.Error404NotFound("该用户没有绑定这个 Provider")
	case errors.Is(err, identity.ErrLastLoginPath):
		return nil, huma.Error409Conflict(err.Error())
	}
	return nil, err
}

func providerErr(err error) error {
	switch {
	case errors.Is(err, provider.ErrNotFound):
		return huma.Error404NotFound("no such Provider")
	case errors.Is(err, provider.ErrExists):
		return huma.Error409Conflict("这个 Provider ID 已被使用")
	case errors.Is(err, provider.ErrBound):
		return huma.Error409Conflict("还有用户绑定了这个 Provider,只能停用,不能删除")
	}
	return invalid(err)
}
