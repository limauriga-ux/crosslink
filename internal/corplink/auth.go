package corplink

import (
	"context"
	"fmt"
	"time"
)

// SendCode sends a verification code to email or phone.
// codeType: "email" or "phone"
func (c *Client) SendCode(ctx context.Context, codeType, account string) error {
	type req struct {
		ForgetPassword bool   `json:"forget_password"`
		CodeType       string `json:"code_type"`
		UserName       string `json:"user_name"`
	}
	var resp apiResp[any]
	if err := c.post(ctx, c.apiURL("/api/login/code/send"), req{
		CodeType: codeType,
		UserName: account,
	}, &resp); err != nil {
		return err
	}
	if resp.Code != 0 {
		return fmt.Errorf("send code: %s", resp.Message)
	}
	return nil
}

// VerifyCode submits a verification code and completes login.
func (c *Client) VerifyCode(ctx context.Context, codeType, account, code string) error {
	type req struct {
		ForgetPassword bool   `json:"forget_password"`
		CodeType       string `json:"code_type"`
		UserName       string `json:"user_name"`
		Code           string `json:"code"`
	}
	var resp apiResp[any]
	if err := c.post(ctx, c.apiURL("/api/login/code/verify"), req{
		CodeType: codeType,
		UserName: account,
		Code:     code,
	}, &resp); err != nil {
		return err
	}
	if resp.Code != 0 {
		return fmt.Errorf("verify code: %s", resp.Message)
	}
	return nil
}

// QRCodeResult holds data for QR code login flow.
type QRCodeResult struct {
	LoginURL string
	Token    string
}

// GetQRCode fetches a Lark/OIDC OAuth login URL and polling token.
func (c *Client) GetQRCode(ctx context.Context) (*QRCodeResult, error) {
	// data is an array of TPS items; find the first (lark) entry.
	type tpsItem struct {
		AliasKey string `json:"alias_key"`
		LoginURL string `json:"login_url"`
		Token    string `json:"token"`
	}
	var result apiResp[[]tpsItem]
	if err := c.get(ctx, c.apiURL("/api/tpslogin/link"), &result); err != nil {
		return nil, err
	}
	if result.Code != 0 {
		return nil, fmt.Errorf("get qr code: %s", result.Message)
	}
	if len(result.Data) == 0 {
		return nil, fmt.Errorf("get qr code: no TPS items returned")
	}
	item := result.Data[0]
	return &QRCodeResult{LoginURL: item.LoginURL, Token: item.Token}, nil
}

// PollQRLogin polls until QR code is scanned and login is complete.
func (c *Client) PollQRLogin(ctx context.Context, token string) error {
	type req struct {
		Token string `json:"token"`
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("QR login timed out after 3 minutes")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
		var resp apiResp[any]
		if err := c.post(ctx, c.apiURL("/api/tpslogin/token/check"), req{Token: token}, &resp); err != nil {
			continue
		}
		if resp.Code == 0 {
			return nil
		}
		if resp.Code == 101 {
			continue // not yet scanned
		}
		return fmt.Errorf("qr login error: %s", resp.Message)
	}
}

// Logout logs out the current session and clears all local credentials.
// The remote request is best effort: local credential removal must still
// happen when the server is unreachable or the session already expired.
func (c *Client) Logout(ctx context.Context) {
	c.session.mu.Lock()
	server := c.session.Server
	c.session.mu.Unlock()
	if server != "" {
		var resp apiResp[any]
		c.get(ctx, c.apiURL("/api/logout")+"&logout_all=false", &resp) //nolint:errcheck
	}
	c.session.mu.Lock()
	c.session.clearCredentialsLocked()
	c.session.mu.Unlock()
	// The previous HTTP client still references the pre-logout cookie jar;
	// rebind it so stored authentication cookies cannot be resent.
	c.rebindJar()
}
