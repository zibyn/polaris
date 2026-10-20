package authorize

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
	"github.com/zibyn/polaris/internal/oidc/internal/strutil"
)

func redirectError(ctx oidc.Context, err error, c *goidc.Client) error {
	var redirectErr redirectionError
	if !errors.As(err, &redirectErr) {
		return err
	}

	ctx.HandleError(err)

	redirectParams := response{
		errorCode:        redirectErr.Code(),
		errorDescription: redirectErr.Description(),
		state:            redirectErr.State,
		errorURI:         ctx.ErrorURI,
	}
	return redirectResponse(
		ctx,
		c,
		redirectErr.AuthorizationParameters,
		redirectParams,
	)
}

func redirectResponse(ctx oidc.Context, c *goidc.Client, params goidc.AuthorizationParameters, redirectParams response) error {
	if ctx.IssuerRespParamEnabled {
		redirectParams.issuer = ctx.Issuer()
	}

	// [OAuth 2.0 Multiple Response Type Encoding Practices §5] Find the response mode based on the response type.
	responseMode := func() goidc.ResponseMode {
		if params.ResponseMode == "" {
			if params.ResponseType.IsImplicit() {
				return goidc.ResponseModeFragment
			}
			return goidc.ResponseModeQuery
		}
		return params.ResponseMode
	}()
	redirectParamsMap := redirectParams.parameters()
	switch responseMode {
	case goidc.ResponseModeFragment:
		redirectURL := strutil.URLWithFragmentParams(params.RedirectURI, redirectParamsMap)
		ctx.Redirect(redirectURL)
	case goidc.ResponseModeFormPost:
		redirectParamsMap["redirect_uri"] = params.RedirectURI
		if err := ctx.WriteHTML(formPostResponseTemplate, redirectParamsMap); err != nil {
			return fmt.Errorf("could not render the html for the form_post response mode: %w", err)
		}
	case goidc.ResponseModeJSON:
		if err := ctx.Write(redirectParamsMap, http.StatusOK); err != nil {
			return fmt.Errorf("could not write the json response: %w", err)
		}
	default:
		redirectURL := strutil.URLWithQueryParams(params.RedirectURI, redirectParamsMap)
		ctx.Redirect(redirectURL)
	}

	return nil
}
