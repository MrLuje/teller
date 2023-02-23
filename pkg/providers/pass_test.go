package providers

import (
	"errors"
	"testing"

	"github.com/alecthomas/assert"
	"github.com/golang/mock/gomock"

	"github.com/spectralops/teller/pkg/core"
	"github.com/spectralops/teller/pkg/providers/mock_providers"
)

func TestPass(t *testing.T) {
	ctrl := gomock.NewController(t)
	// Assert that Bar() is invoked.
	defer ctrl.Finish()
	client := mock_providers.NewMockPassClient(ctrl)
	path := "settings/prod/billing-svc"
	pathmap := "settings/prod/billing-svc/all"
	out := map[string]string{
		"settings/prod/billing-svc/MG_KEY":    "shazam",
		"settings/prod/billing-svc/SMTP_PASS": "mailman",
	}
	client.EXPECT().Get(gomock.Eq(path), false).Return(out, nil).AnyTimes()
	client.EXPECT().Get(gomock.Eq(pathmap), true).Return(out, nil).AnyTimes()
	s := Pass{
		client: client,
		logger: GetTestLogger(),
	}
	AssertProvider(t, &s, true)
}

func TestPassFailures(t *testing.T) {
	ctrl := gomock.NewController(t)
	// Assert that Bar() is invoked.
	defer ctrl.Finish()
	client := mock_providers.NewMockPassClient(ctrl)
	client.EXPECT().Get(gomock.Any(), true).Return(nil, errors.New("error")).AnyTimes()
	s := Pass{
		client: client,
		logger: GetTestLogger(),
	}
	_, err := s.Get(core.KeyPath{Env: "MG_KEY", Path: "settings/{{stage}}/billing-svc"})
	assert.NotNil(t, err)
}
