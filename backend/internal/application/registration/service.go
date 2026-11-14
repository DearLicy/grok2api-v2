package registration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

type accountService interface {
	List(ctx context.Context, page, pageSize int, search string, filter accountapp.ListFilter) ([]accountapp.View, int64, error)
	ImportWebCredentialsWithObserver(ctx context.Context, data []byte, observer accountapp.ImportedAccountObserver) (accountapp.ImportResult, error)
	ImportCredentialDocumentsWithProgress(ctx context.Context, documents [][]byte, observer accountapp.ImportedAccountObserver, progress accountapp.BatchProgressObserver) (accountapp.ImportResult, error)
	ImportConsoleCredentialsWithObserver(ctx context.Context, data []byte, observer accountapp.ImportedAccountObserver) (accountapp.ImportResult, error)
	ConvertWebAccountsToBuildWithProgress(ctx context.Context, ids []uint64, observer accountapp.ImportedAccountObserver, progress accountapp.BatchProgressObserver) (accountapp.BuildConversionResult, error)
	SyncAccountIdentity(ctx context.Context, id uint64) error
}

// Service bridges the isolated registration worker to the existing Web, Build
// and Console credential import pipelines.
type Service struct {
	accounts accountService
}

type BuildTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
}

type IngestInput struct {
	Email    string      `json:"email"`
	Password string      `json:"password"`
	SSO      string      `json:"sso"`
	Build    BuildTokens `json:"build"`
	Source   string      `json:"source"`
}

type IngestResult struct {
	WebOk             bool              `json:"webOk"`
	BuildOk           bool              `json:"buildOk"`
	BuildNeedsBrowser bool              `json:"buildNeedsBrowser,omitempty"`
	ConsoleOk         bool              `json:"consoleOk"`
	AccountIDs        map[string]uint64 `json:"accountIds"`
	Warnings          []string          `json:"warnings,omitempty"`
	Errors            []string          `json:"errors,omitempty"`
}

type ExistsResult struct {
	Exists     bool     `json:"exists"`
	Providers  []string `json:"providers,omitempty"`
	AccountIDs []uint64 `json:"accountIds,omitempty"`
}

func NewService(accounts *accountapp.Service) *Service {
	return &Service{accounts: accounts}
}

func newService(accounts accountService) *Service {
	return &Service{accounts: accounts}
}

func (s *Service) Exists(ctx context.Context, email string) (ExistsResult, error) {
	email = strings.TrimSpace(email)
	if !validEmail(email) {
		return ExistsResult{}, errors.New("邮箱格式无效")
	}
	if s == nil || s.accounts == nil {
		return ExistsResult{}, errors.New("账号服务未初始化")
	}
	values, _, err := s.accounts.List(ctx, 1, 50, email, accountapp.ListFilter{})
	if err != nil {
		return ExistsResult{}, err
	}
	result := ExistsResult{}
	seenProviders := make(map[string]struct{})
	for _, value := range values {
		if !strings.EqualFold(strings.TrimSpace(value.Credential.Email), email) {
			continue
		}
		result.Exists = true
		result.AccountIDs = append(result.AccountIDs, value.Credential.ID)
		providerValue := string(value.Credential.Provider)
		if _, exists := seenProviders[providerValue]; !exists {
			seenProviders[providerValue] = struct{}{}
			result.Providers = append(result.Providers, providerValue)
		}
	}
	return result, nil
}

func (s *Service) Ingest(ctx context.Context, input IngestInput) (IngestResult, error) {
	input.Email = strings.TrimSpace(input.Email)
	input.SSO = strings.TrimSpace(strings.TrimPrefix(input.SSO, "sso="))
	if !validEmail(input.Email) {
		return IngestResult{}, errors.New("入库账号缺少有效邮箱")
	}
	if input.SSO == "" {
		return IngestResult{}, errors.New("入库账号缺少 SSO")
	}
	if s == nil || s.accounts == nil {
		return IngestResult{}, errors.New("账号服务未初始化")
	}
	result := IngestResult{AccountIDs: make(map[string]uint64)}

	webDocument, err := marshalImportDocument("grok_web", []map[string]any{{
		"name":      input.Email,
		"email":     input.Email,
		"sso_token": input.SSO,
	}})
	if err != nil {
		return result, err
	}
	webImport, webErr := s.accounts.ImportWebCredentialsWithObserver(ctx, webDocument, nil)
	if webErr == nil && len(webImport.AccountIDs) > 0 {
		result.WebOk = true
		result.AccountIDs[string(accountdomain.ProviderWeb)] = webImport.AccountIDs[0]
		s.syncIdentityBestEffort(ctx, webImport.AccountIDs[0], "Web", &result)
	} else {
		result.Errors = append(result.Errors, importError("Web", webErr, len(webImport.AccountIDs)))
	}

	if strings.TrimSpace(input.Build.AccessToken) != "" || strings.TrimSpace(input.Build.RefreshToken) != "" {
		buildEntry := map[string]any{
			"provider":      string(accountdomain.ProviderBuild),
			"name":          input.Email,
			"email":         input.Email,
			"access_token":  strings.TrimSpace(input.Build.AccessToken),
			"refresh_token": strings.TrimSpace(input.Build.RefreshToken),
			"id_token":      strings.TrimSpace(input.Build.IDToken),
			"token_type":    firstNonEmpty(input.Build.TokenType, "Bearer"),
			"expires_in":    input.Build.ExpiresIn,
		}
		buildDocument, marshalErr := marshalImportDocument(string(accountdomain.ProviderBuild), []map[string]any{buildEntry})
		if marshalErr != nil {
			result.Errors = append(result.Errors, "Build: "+marshalErr.Error())
		} else {
			buildImport, buildErr := s.accounts.ImportCredentialDocumentsWithProgress(ctx, [][]byte{buildDocument}, nil, nil)
			if buildErr == nil && len(buildImport.AccountIDs) > 0 {
				result.BuildOk = true
				result.AccountIDs[string(accountdomain.ProviderBuild)] = buildImport.AccountIDs[0]
			} else {
				result.Errors = append(result.Errors, importError("Build", buildErr, len(buildImport.AccountIDs)))
			}
		}
	} else if webID := result.AccountIDs[string(accountdomain.ProviderWeb)]; webID != 0 {
		conversion, conversionErr := s.accounts.ConvertWebAccountsToBuildWithProgress(
			ctx,
			[]uint64{webID},
			nil,
			nil,
		)
		switch {
		case conversionErr == nil && len(conversion.BuildAccountIDs) > 0:
			result.BuildOk = true
			result.AccountIDs[string(accountdomain.ProviderBuild)] = conversion.BuildAccountIDs[0]
		case errors.Is(conversionErr, provider.ErrBrowserVerificationRequired):
			result.BuildNeedsBrowser = true
			result.Errors = append(result.Errors, "Build: xAI 要求浏览器校验后才能完成授权")
		case conversionErr != nil:
			result.Errors = append(result.Errors, "Build: "+conversionErr.Error())
		default:
			result.Errors = append(result.Errors, importError("Build", nil, len(conversion.BuildAccountIDs)))
		}
	} else {
		result.Errors = append(result.Errors, "Build: Web SSO 未成功导入，无法转换")
	}

	consoleDocument, err := marshalImportDocument(string(accountdomain.ProviderConsole), []map[string]any{{
		"name":      input.Email,
		"email":     input.Email,
		"sso_token": input.SSO,
	}})
	if err != nil {
		result.Errors = append(result.Errors, "Console: "+err.Error())
	} else {
		consoleImport, consoleErr := s.accounts.ImportConsoleCredentialsWithObserver(ctx, consoleDocument, nil)
		if consoleErr == nil && len(consoleImport.AccountIDs) > 0 {
			result.ConsoleOk = true
			result.AccountIDs[string(accountdomain.ProviderConsole)] = consoleImport.AccountIDs[0]
			s.syncIdentityBestEffort(ctx, consoleImport.AccountIDs[0], "Console", &result)
		} else {
			result.Errors = append(result.Errors, importError("Console", consoleErr, len(consoleImport.AccountIDs)))
		}
	}

	// Re-run the Web identity sync after Build and Console exist so trusted
	// provider links are reconciled against the complete set of credentials.
	if webID := result.AccountIDs[string(accountdomain.ProviderWeb)]; webID != 0 {
		s.syncIdentityBestEffort(ctx, webID, "Web identity", &result)
	}
	return result, nil
}

func (s *Service) syncIdentityBestEffort(ctx context.Context, id uint64, label string, result *IngestResult) {
	syncCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := s.accounts.SyncAccountIdentity(syncCtx, id); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("%s身份同步未完成: %s", label, err))
	}
}

func importError(providerName string, err error, imported int) string {
	if err != nil {
		return providerName + ": " + err.Error()
	}
	if imported == 0 {
		return providerName + ": 导入流水线没有返回账号"
	}
	return ""
}

func marshalImportDocument(providerName string, accounts []map[string]any) ([]byte, error) {
	document := map[string]any{
		"provider": providerName,
		"accounts": accounts,
	}
	data, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("编码 %s 入库数据: %w", providerName, err)
	}
	return data, nil
}

func validEmail(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 3 || len(value) > 320 {
		return false
	}
	at := strings.LastIndexByte(value, '@')
	return at > 0 && at < len(value)-1 && !strings.ContainsAny(value, "\r\n\x00")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
