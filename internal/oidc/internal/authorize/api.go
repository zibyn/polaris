package authorize

import (
	"net/http"
	"slices"

	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if slices.ContainsFunc(config.GrantTypes, func(gt goidc.GrantType) bool {
		return gt == goidc.GrantAuthorizationCode || gt == goidc.GrantImplicit
	}) {
		router.Handle("GET "+config.EndpointPrefix+config.AuthorizationEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handler), middlewares...))
		router.Handle("POST "+config.EndpointPrefix+config.AuthorizationEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handler), middlewares...))

		router.Handle("POST "+config.EndpointPrefix+config.AuthorizationEndpoint+"/{callback}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...))
		router.Handle("GET "+config.EndpointPrefix+config.AuthorizationEndpoint+"/{callback}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...))
		router.Handle("POST "+config.EndpointPrefix+config.AuthorizationEndpoint+"/{callback}/{callback_path...}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...))
		router.Handle("GET "+config.EndpointPrefix+config.AuthorizationEndpoint+"/{callback}/{callback_path...}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...))
	}

}

func handler(ctx oidc.Context) {
	var req request
	if ctx.Request.Method == http.MethodPost {
		if mediaType := ctx.MediaType(); mediaType != "" && mediaType != "application/x-www-form-urlencoded" {
			ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid content type").WithStatusCode(http.StatusUnsupportedMediaType))
			return
		}
		req = newFormRequest(ctx.Request)
	} else {
		req = newRequest(ctx.Request)
	}

	err := initAuth(ctx, req)
	if err != nil {
		if err := ctx.RenderError(err); err != nil {
			ctx.WriteError(err)
		}
		return
	}
}

func handlerCallback(ctx oidc.Context) {
	callbackID := ctx.Request.PathValue("callback")
	err := continueAuth(ctx, callbackID)
	if err == nil {
		return
	}

	if err := ctx.RenderError(err); err != nil {
		ctx.WriteError(err)
	}
}
