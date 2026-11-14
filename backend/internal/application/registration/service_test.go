package registration

import (
	"context"
	"errors"
	"testing"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

type registrationAccountStub struct {
	webID            uint64
	buildID          uint64
	consoleID        uint64
	conversionErr    error
	conversionCalls  int
	buildImportCalls int
	listResults      []accountapp.View
	listErr          error
	listCalls        int
}

func (s *registrationAccountStub) List(context.Context, int, int, string, accountapp.ListFilter) ([]accountapp.View, int64, error) {
	s.listCalls++
	return s.listResults, int64(len(s.listResults)), s.listErr
}

func (s *registrationAccountStub) ImportWebCredentialsWithObserver(context.Context, []byte, accountapp.ImportedAccountObserver) (accountapp.ImportResult, error) {
	return accountapp.ImportResult{AccountIDs: []uint64{s.webID}}, nil
}

func (s *registrationAccountStub) ImportCredentialDocumentsWithProgress(context.Context, [][]byte, accountapp.ImportedAccountObserver, accountapp.BatchProgressObserver) (accountapp.ImportResult, error) {
	s.buildImportCalls++
	return accountapp.ImportResult{AccountIDs: []uint64{s.buildID}}, nil
}

func (s *registrationAccountStub) ImportConsoleCredentialsWithObserver(context.Context, []byte, accountapp.ImportedAccountObserver) (accountapp.ImportResult, error) {
	return accountapp.ImportResult{AccountIDs: []uint64{s.consoleID}}, nil
}

func (s *registrationAccountStub) ConvertWebAccountsToBuildWithProgress(context.Context, []uint64, accountapp.ImportedAccountObserver, accountapp.BatchProgressObserver) (accountapp.BuildConversionResult, error) {
	s.conversionCalls++
	if s.conversionErr != nil {
		return accountapp.BuildConversionResult{}, s.conversionErr
	}
	return accountapp.BuildConversionResult{BuildAccountIDs: []uint64{s.buildID}}, nil
}

func (s *registrationAccountStub) SyncAccountIdentity(context.Context, uint64) error {
	return nil
}

func TestIngestUsesPureHTTPBuildConversion(t *testing.T) {
	accounts := &registrationAccountStub{webID: 11, buildID: 22, consoleID: 33}
	service := newService(accounts)

	result, err := service.Ingest(context.Background(), IngestInput{
		Email: "person@example.com",
		SSO:   "sso-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.WebOk || !result.BuildOk || !result.ConsoleOk {
		t.Fatalf("unexpected ingest result: %#v", result)
	}
	if accounts.buildImportCalls != 0 {
		t.Fatalf("Build token import called without browser tokens: %d", accounts.buildImportCalls)
	}
	if accounts.conversionCalls != 1 {
		t.Fatalf("conversion calls = %d, want 1", accounts.conversionCalls)
	}
	if result.AccountIDs[string(accountdomain.ProviderBuild)] != 22 {
		t.Fatalf("build account id = %d", result.AccountIDs[string(accountdomain.ProviderBuild)])
	}
}

func TestIngestReportsConditionalBrowserFallback(t *testing.T) {
	accounts := &registrationAccountStub{
		webID:         11,
		consoleID:     33,
		conversionErr: provider.ErrBrowserVerificationRequired,
	}
	service := newService(accounts)

	result, err := service.Ingest(context.Background(), IngestInput{
		Email: "person@example.com",
		SSO:   "sso-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.WebOk || !result.ConsoleOk {
		t.Fatalf("Web/Console should remain successful: %#v", result)
	}
	if result.BuildOk || !result.BuildNeedsBrowser {
		t.Fatalf("expected conditional browser fallback: %#v", result)
	}
	if len(result.Errors) == 0 {
		t.Fatal("expected a Build warning")
	}
}

func TestIngestExplicitBuildTokensSkipConversion(t *testing.T) {
	accounts := &registrationAccountStub{webID: 11, buildID: 22, consoleID: 33}
	service := newService(accounts)

	result, err := service.Ingest(context.Background(), IngestInput{
		Email: "person@example.com",
		SSO:   "sso-token",
		Build: BuildTokens{AccessToken: "access", RefreshToken: "refresh"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.BuildOk || accounts.conversionCalls != 0 || accounts.buildImportCalls != 1 {
		t.Fatalf("unexpected Build path: result=%#v conversion=%d imports=%d", result, accounts.conversionCalls, accounts.buildImportCalls)
	}
}

func TestIngestKeepsWebAndConsoleWhenBuildConversionFails(t *testing.T) {
	accounts := &registrationAccountStub{
		webID:         11,
		consoleID:     33,
		conversionErr: errors.New("temporary upstream failure"),
	}
	service := newService(accounts)

	result, err := service.Ingest(context.Background(), IngestInput{
		Email: "person@example.com",
		SSO:   "sso-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.WebOk || !result.ConsoleOk || result.BuildOk || result.BuildNeedsBrowser {
		t.Fatalf("unexpected partial result: %#v", result)
	}
}

func TestExistsMatchesOnlyExactEmailAndDeduplicatesProviders(t *testing.T) {
	accounts := &registrationAccountStub{
		listResults: []accountapp.View{
			{Credential: accountdomain.Credential{ID: 11, Provider: accountdomain.ProviderWeb, Email: "Person@Example.com"}},
			{Credential: accountdomain.Credential{ID: 22, Provider: accountdomain.ProviderBuild, Email: "person@example.com"}},
			{Credential: accountdomain.Credential{ID: 33, Provider: accountdomain.ProviderConsole, Email: " PERSON@EXAMPLE.COM "}},
			{Credential: accountdomain.Credential{ID: 44, Provider: accountdomain.ProviderWeb, Email: "person@example.com"}},
			{Credential: accountdomain.Credential{ID: 55, Provider: accountdomain.ProviderWeb, Email: "person@example.com.extra"}},
		},
	}
	service := newService(accounts)

	result, err := service.Exists(context.Background(), "person@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Exists {
		t.Fatal("expected account to exist")
	}
	if accounts.listCalls != 1 {
		t.Fatalf("List calls = %d, want 1", accounts.listCalls)
	}
	if len(result.Providers) != 3 {
		t.Fatalf("providers = %#v", result.Providers)
	}
	for index, providerValue := range []string{"grok_web", "grok_build", "grok_console"} {
		if result.Providers[index] != providerValue {
			t.Fatalf("providers = %#v, want index %d = %s", result.Providers, index, providerValue)
		}
	}
	if len(result.AccountIDs) != 4 || result.AccountIDs[3] != 44 {
		t.Fatalf("account ids = %#v", result.AccountIDs)
	}
}

func TestExistsRejectsInvalidEmailBeforeQueryingAccounts(t *testing.T) {
	accounts := &registrationAccountStub{}
	service := newService(accounts)

	if _, err := service.Exists(context.Background(), "not-an-email"); err == nil {
		t.Fatal("expected invalid email error")
	}
	if accounts.listCalls != 0 {
		t.Fatalf("List calls = %d, want 0", accounts.listCalls)
	}
}
