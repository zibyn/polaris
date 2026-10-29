package login

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidcstore"
	"github.com/zibyn/polaris/internal/passkey"
	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/twofactor"
)

// ChallengePath is the direct auth API's authorization challenge endpoint
// (OAuth 2.0 for First-Party Applications, draft -04; ADR 0002).
const ChallengePath = "/v1/auth/challenge"

// Error codes of the draft beyond RFC 6749's.
const (
	errInvalidSession            = "invalid_session"
	errInsufficientAuthorization = "insufficient_authorization"
	// RFC 6749's: a Provider turned the client token down.
	errInvalidGrant = "invalid_grant"
	// Ours: the Application requires a Role on its default API, and the User
	// holds none (docs/spec/rbac.md). Only ever added to, like next.
	errApplicationAccessDenied = "application_access_denied"
)

// Values of next (ADR 0010): only ever added to, never renamed or removed.
const (
	nextCode     = "code"     // enter the code just sent
	nextPhone    = "phone"    // bind a phone number first
	nextTOTP     = "totp"     // enter a TOTP code or a 恢复码
	nextPassword = "password" // set your own password first: the account is 待激活
)

// challengeState is what an auth_session carries between requests.
type challengeState struct {
	Params goidc.AuthorizationParameters `json:"params"`
	// Identifier the last code went to.
	Identifier string `json:"identifier,omitempty"`
	// Set once the User has passed the first factor but must pass 两步验证
	// or bind a phone number.
	Pending *pendingLogin `json:"pending,omitempty"`
	// The challenge of a Passkey sign-in begun in this auth_session, which
	// the assertion submitted on it must answer (ADR 0014). Spent with the
	// auth_session: a refused assertion ends it.
	PasskeyChallenge string `json:"passkey_challenge,omitempty"`
}

type pendingLogin struct {
	Sub      string   `json:"sub"`
	AuthTime int64    `json:"auth_time"`
	AMR      []string `json:"amr"`
	// TOTP: waiting for a TOTP code or a 恢复码, with Failures mistakes so far.
	TOTP     bool `json:"totp,omitempty"`
	Failures int  `json:"failures,omitempty"`
	// Password: 待激活, waiting for the User to replace the initial password
	// an admin set. Nothing else happens until they do (ADR 0016).
	Password bool `json:"password,omitempty"`
}

// challengeError is a draft error response; AuthSession lets the App go on.
type challengeError struct {
	status      int
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	AuthSession string `json:"auth_session,omitempty"`
	// Next names the step an insufficient_authorization asks for (ADR 0010).
	Next string `json:"next,omitempty"`
}

func (e *challengeError) Error() string { return e.Code + ": " + e.Description }

// answer is what one challenge request yields: the authorization code that
// ends the sign-in, or, for passkey=begin, assertion options and the
// auth_session the assertion is submitted on (ADR 0014).
type answer struct {
	code  string
	token string
	// options is set instead of a code to begin a sign-in.
	options json.RawMessage
}

// challenge is the direct auth API: an App signs a User in with a code or a
// password and gets an authorization code for /token. One request sends a
// code (identifier) and answers insufficient_authorization with an
// auth_session; the next enters it (auth_session + code). A password
// (username + password) takes one request. A Passkey takes two: passkey=begin
// answers 200 with assertion options and an auth_session, and passkey then
// submits the assertion (ADR 0014).
func (s *Service) challenge(w http.ResponseWriter, r *http.Request) {
	out, err := s.runChallenge(w, r)
	var ce *challengeError
	switch {
	case err == nil:
		if out.options != nil {
			writeJSON(w, http.StatusOK, map[string]any{"auth_session": out.token, "options": out.options})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"authorization_code": out.code})
		return
	case errors.As(err, &ce):
	default:
		var oe goidc.Error
		if errors.As(err, &oe) {
			ce = &challengeError{status: oe.StatusCode(), Code: string(oe.Code), Description: oe.Description}
			break
		}
		slog.Error("authorization challenge", "err", err)
		ce = &challengeError{status: http.StatusInternalServerError, Code: "server_error"}
	}
	writeJSON(w, ce.status, ce)
}

func (s *Service) runChallenge(w http.ResponseWriter, r *http.Request) (answer, error) {
	ctx := r.Context()
	// Every request carries the version of the terms the User agreed to in
	// the App; with no terms set up, any version will do, none included.
	version := r.PostFormValue("terms_version")
	terms, err := s.q.Terms(ctx)
	if err != nil {
		return answer{}, err
	}
	if terms.TermsVersion != "" && version != terms.TermsVersion {
		return answer{}, invalid("terms_version is not the current one: " + terms.TermsVersion)
	}
	// A new sign-in sets the parameters; later requests carry them in the
	// auth_session.
	token := r.PostFormValue("auth_session")
	var st challengeState
	if token != "" {
		row, err := s.q.ChallengeSession(ctx, hash(token))
		if errors.Is(err, pgx.ErrNoRows) {
			return answer{}, &challengeError{status: http.StatusBadRequest, Code: errInvalidSession, Description: "auth_session is invalid or expired"}
		} else if err != nil {
			return answer{}, err
		}
		if err := json.Unmarshal(row.Data, &st); err != nil {
			return answer{}, err
		}
		if r.PostFormValue("client_id") != "" && r.PostFormValue("client_id") != row.ClientID {
			return answer{}, &challengeError{status: http.StatusBadRequest, Code: errInvalidSession, Description: "auth_session belongs to another client"}
		}
		// The draft lets the App leave client_id out of later requests.
		r.Form.Set("client_id", row.ClientID)
		r.PostForm.Set("client_id", row.ClientID)
	} else {
		if r.PostFormValue("response_type") != string(goidc.ResponseTypeCode) {
			return answer{}, invalid("response_type must be code")
		}
		st.Params = goidc.AuthorizationParameters{
			ResponseType:        goidc.ResponseTypeCode,
			Scopes:              r.PostFormValue("scope"),
			CodeChallenge:       r.PostFormValue("code_challenge"),
			CodeChallengeMethod: goidc.CodeChallengeMethod(r.PostFormValue("code_challenge_method")),
		}
	}
	c, err := s.op.ChallengeClient(w, r, st.Params)
	if err != nil {
		return answer{}, err
	}

	// save keeps st in the auth_session.
	save := func() error {
		if token == "" {
			token = newAuthSession()
		}
		data, err := json.Marshal(st)
		if err != nil {
			return err
		}
		return s.q.SaveChallengeSession(ctx, sqlc.SaveChallengeSessionParams{Hash: hash(token), ClientID: c.ID, Data: data})
	}
	// next keeps the sign-in going: the App must take another step.
	next := func(step, description string) (answer, error) {
		if err := save(); err != nil {
			return answer{}, err
		}
		return answer{}, &challengeError{status: http.StatusForbidden, Code: errInsufficientAuthorization, Description: description, AuthSession: token, Next: step}
	}
	// signedIn ends the sign-in with an authorization code, unless sub must
	// pass 两步验证, agree to the terms or bind a phone number first, in that
	// order.
	signedIn := func(sub string, authTime time.Time, amr []string) (answer, error) {
		what, err := s.nextStep(ctx, sub, amr, false)
		if err != nil {
			return answer{}, err
		}
		if what == stepConsent {
			// The App sent the current terms_version with this request, so
			// consent is recorded here rather than asked for as another step;
			// then whatever is left (a phone number) is asked for.
			if terms.TermsVersion != "" {
				if err := s.q.RecordConsent(ctx, sqlc.RecordConsentParams{UserID: sub, Version: version, ClientID: c.ID}); err != nil {
					return answer{}, err
				}
			}
			if what, err = s.nextStep(ctx, sub, amr, false); err != nil {
				return answer{}, err
			}
		}
		switch what {
		case stepSetPassword:
			// 待激活 comes before everything else (ADR 0016): the only evidence
			// so far is that the User knows a password someone else chose, and
			// letting that carry on through 两步验证, the terms and a phone
			// number would build the session on it.
			st.Pending, st.Identifier = &pendingLogin{Sub: sub, AuthTime: authTime.Unix(), AMR: amr, Password: true}, ""
			return next(nextPassword, "set your own password: send password")
		case stepTOTP:
			st.Pending, st.Identifier = &pendingLogin{Sub: sub, AuthTime: authTime.Unix(), AMR: amr, TOTP: true}, ""
			return next(nextTOTP, "两步验证 is on: send totp or recovery_code")
		case stepPhone:
			st.Pending, st.Identifier = &pendingLogin{Sub: sub, AuthTime: authTime.Unix(), AMR: amr}, ""
			return next(nextPhone, "a phone number must be bound: send a code to one")
		}
		if ok, err := s.mayUse(ctx, c.ID, sub); err != nil {
			return answer{}, err
		} else if !ok {
			return answer{}, &challengeError{status: http.StatusForbidden, Code: errApplicationAccessDenied, Description: errNoRole}
		}
		// Spent before the code exists: one auth_session, one code.
		if token != "" {
			if err := s.q.DeleteChallengeSession(ctx, hash(token)); err != nil {
				return answer{}, err
			}
		}
		ip, ua := oidcstore.Device(deviceContext(r))
		sess, err := s.q.CreateSession(ctx, sqlc.CreateSessionParams{
			ClientID: c.ID, UserID: sub, AuthTime: pgtype.Timestamptz{Time: authTime, Valid: true}, Amr: amr,
			Ip: ip, UserAgent: ua,
		})
		if errors.Is(err, pgx.ErrNoRows) { // disabled since authenticating
			return answer{}, &challengeError{status: http.StatusBadRequest, Code: string(goidc.ErrorCodeAccessDenied), Description: identity.ErrDisabled.Error()}
		} else if err != nil {
			return answer{}, err
		}
		if err := s.ids.LoginSucceeded(ctx, attempt(r, c.ID), sub, amr); err != nil {
			return answer{}, err
		}
		code, err := s.op.IssueAuthCode(ctx, c, sub, st.Params, map[string]any{
			oidcstore.SessionKey: sess.ID, storeAuthTime: authTime.Unix(), storeAMR: amr,
		})
		return answer{code: code}, err
	}
	// mistake reports what the User got wrong; the auth_session, if any,
	// stays usable.
	mistake := func(err error) (answer, error) {
		var bad identity.Invalid
		if !errors.As(err, &bad) {
			return answer{}, err
		}
		return answer{}, &challengeError{status: http.StatusBadRequest, Code: string(goidc.ErrorCodeInvalidRequest), Description: bad.Error(), AuthSession: token}
	}

	switch {
	case st.Pending != nil && st.Pending.Password:
		// 强制改密: the one step a 待激活 User may take, and the only one
		// open. It writes the password down a path of its own rather than
		// the account center's, which demands a recent reauthentication and
		// so is closed to a User with 两步验证 on (ADR 0016).
		p := st.Pending
		// 注销 is the other thing open to them. They have no token to delete
		// an account with — no token of any kind — so the sign-in they are
		// stuck in is where they do it, with delete=true.
		if r.PostFormValue("delete") != "" {
			if err := s.deletePending(ctx, p.Sub); err != nil {
				return answer{}, err
			}
			// The auth_session goes with the account it belonged to, as a
			// refused assertion's does: nothing is left to continue (ADR 0016).
			if token != "" {
				if err := s.q.DeleteChallengeSession(ctx, hash(token)); err != nil {
					return answer{}, err
				}
			}
			return answer{}, &challengeError{status: http.StatusBadRequest, Code: string(goidc.ErrorCodeAccessDenied), Description: "账号已注销,请重新登录"}
		}
		if secret := r.PostFormValue("password"); secret == "" {
			return mistake(identity.Invalid("请先设置自己的密码"))
		} else if err := s.ids.SetPasswordIfPending(ctx, p.Sub, secret); err != nil {
			// The account is no longer 待激活: it was activated, or deleted
			// meanwhile. Nothing was written; the App starts over as a new
			// User rather than reading a message about a state it cannot fix.
			if errors.Is(err, identity.ErrNotPending) {
				return answer{}, &challengeError{status: http.StatusBadRequest, Code: errInvalidSession, Description: "the account is not 待激活 any more: start over"}
			}
			return mistake(err)
		}
		return signedIn(p.Sub, time.Unix(p.AuthTime, 0), p.AMR)

	case st.Pending != nil && st.Pending.TOTP: // nothing else before TOTP
		p := st.Pending
		totp, recoveryCode := r.PostFormValue("totp"), r.PostFormValue("recovery_code")
		if totp == "" && recoveryCode == "" {
			return mistake(identity.Invalid("两步验证 is on: send totp or recovery_code"))
		}
		err := s.twoFactor.Check(ctx, clientIP(r), p.Sub, totp, recoveryCode)
		err = s.ids.LoginFailed(ctx, attempt(r, c.ID), p.Sub, secondFactor(recoveryCode), err)
		switch {
		case err == nil:
			return signedIn(p.Sub, time.Unix(p.AuthTime, 0), withMFA(p.AMR))
		case errors.Is(err, twofactor.ErrOff): // turned off meanwhile: nothing to enter
			return signedIn(p.Sub, time.Unix(p.AuthTime, 0), p.AMR)
		case wrongSecondFactor(err):
			if p.Failures++; p.Failures >= totpTries {
				if err := s.q.DeleteChallengeSession(ctx, hash(token)); err != nil {
					return answer{}, err
				}
				return answer{}, &challengeError{status: http.StatusBadRequest, Code: errInvalidSession, Description: "too many wrong codes: sign in again"}
			}
			if err := save(); err != nil {
				return answer{}, err
			}
		}
		return mistake(err)

	case r.PostFormValue("passkey") == "begin":
		if st.Pending != nil {
			return answer{}, invalid("a phone number must be bound")
		}
		// No PoW: begin sends no code and checks no credential, so a PoW
		// would protect nothing; the per-IP budget bounds it instead
		// (ADR 0014).
		if err := s.ids.Start(ctx, clientIP(r)); err != nil {
			return mistake(err)
		}
		options, challenge, err := s.passkeys.LoginOptions(ctx)
		if err != nil {
			return mistake(err)
		}
		st.PasskeyChallenge = challenge
		if err := save(); err != nil {
			return answer{}, err
		}
		return answer{token: token, options: options}, nil

	case r.PostFormValue("passkey") != "":
		if st.Pending != nil {
			return answer{}, invalid("a phone number must be bound")
		}
		if st.PasskeyChallenge == "" {
			return answer{}, invalid("no Passkey sign-in was begun in this auth_session")
		}
		in, err := s.passkeys.SignIn(ctx, st.PasskeyChallenge, []byte(r.PostFormValue("passkey")))
		if err != nil {
			var bad identity.Invalid
			if !errors.As(err, &bad) {
				return answer{}, err
			}
			// A refused assertion ends the auth_session: the App starts over
			// rather than turning the same challenge over (ADR 0014).
			if token != "" {
				if err := s.q.DeleteChallengeSession(ctx, hash(token)); err != nil {
					return answer{}, err
				}
			}
			return answer{}, invalid(bad.Error())
		}
		// The amr says mfa, which signedIn reads as 两步验证 passed.
		return signedIn(in.Sub, time.Now(), passkey.AMR(in.BackupEligible))

	case r.PostFormValue("code") != "":
		if st.Identifier == "" {
			return answer{}, invalid("no code was sent in this auth_session")
		}
		if err := s.ids.FromIP(ctx, clientIP(r), func() error { return s.codes.Check(ctx, st.Identifier, r.PostFormValue("code")) }); err != nil {
			var pending string
			if st.Pending != nil {
				pending = st.Pending.Sub
			}
			return mistake(s.codeFailed(ctx, attempt(r, c.ID), pending, st.Identifier, err))
		}
		kind, value, _ := identity.ParseIdentifier(st.Identifier)
		if p := st.Pending; p != nil {
			if err := s.ids.AddIdentifier(ctx, p.Sub, kind, value); err != nil {
				return mistake(err)
			}
			return signedIn(p.Sub, time.Unix(p.AuthTime, 0), p.AMR)
		}
		sub, err := s.ids.SignIn(ctx, kind, value)
		if err != nil {
			return mistake(err)
		}
		return signedIn(sub, time.Now(), []string{string(codeAMR(kind))})

	case r.PostFormValue("identifier") != "":
		kind, value, err := identity.ParseIdentifier(r.PostFormValue("identifier"))
		if err == nil && st.Pending != nil && kind != "phone" {
			err = identity.ErrPhone
		}
		if err == nil {
			err = s.pow.Verify(ctx, r.PostFormValue("altcha"))
		}
		if err == nil {
			err = s.codes.Send(ctx, kind, value, clientIP(r))
		}
		if err != nil {
			return mistake(err)
		}
		st.Identifier = value
		return next(nextCode, "code sent: enter it")

	case r.PostFormValue("provider") != "":
		if st.Pending != nil {
			return answer{}, invalid("a phone number must be bound")
		}
		sub, err := s.providers.SignInWithClientToken(ctx, r.PostFormValue("provider"), r.PostFormValue("authorization_code"))
		switch {
		case errors.Is(err, provider.ErrNotFound):
			return answer{}, invalid("provider is not one an App can sign in with")
		case errors.Is(err, provider.ErrLogin):
			slog.Info("client token login", "provider", r.PostFormValue("provider"), "err", err)
			return answer{}, &challengeError{status: http.StatusBadRequest, Code: errInvalidGrant, Description: "the Provider turned authorization_code down: sign in with it again"}
		case err != nil:
			return mistake(err)
		}
		return signedIn(sub, time.Now(), []string{amrFed})

	case r.PostFormValue("username") != "":
		if st.Pending != nil {
			return answer{}, invalid("a phone number must be bound")
		}
		if err := s.pow.Verify(ctx, r.PostFormValue("altcha")); err != nil {
			return mistake(err)
		}
		var sub string
		a := attempt(r, c.ID)
		if err := s.ids.FromIP(ctx, clientIP(r), func() (err error) {
			sub, err = s.ids.CheckPassword(ctx, a, r.PostFormValue("username"), r.PostFormValue("password"))
			return err
		}); err != nil {
			return mistake(s.ids.LoginFailed(ctx, a, sub, "password", err))
		}
		return signedIn(sub, time.Now(), []string{string(goidc.AMRPassword)})
	}
	return answer{}, invalid("send identifier, code, username and password, provider and authorization_code, or passkey")
}

// terms tells Apps what their consent checkbox links to and which version
// to send.
func (s *Service) terms(w http.ResponseWriter, r *http.Request) {
	t, err := s.q.Terms(r.Context())
	if err != nil {
		slog.Error("terms", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"terms_url": t.TermsUrl, "privacy_url": t.PrivacyUrl, "version": t.TermsVersion})
}

// deletePending deletes the account of a 待激活 User at their own request: the
// same deletion as 注销, minus the browser Session a 待激活 User cannot have.
func (s *Service) deletePending(ctx context.Context, sub string) error {
	err := s.providers.DeleteUser(ctx, sub, s.ids.Delete)
	if errors.Is(err, identity.ErrLastOwner) {
		return invalid(identity.ErrLastOwner.Error())
	}
	return err
}

func invalid(description string) error {
	return &challengeError{status: http.StatusBadRequest, Code: string(goidc.ErrorCodeInvalidRequest), Description: description}
}

// newAuthSession makes an auth_session value: 256 random bits, as the draft
// recommends.
func newAuthSession() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
