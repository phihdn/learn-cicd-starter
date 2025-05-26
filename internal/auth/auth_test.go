package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}{
		{
			name:    "no auth header",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-api-key"},
			},
			want:    "test-api-key",
			wantErr: nil,
		},
		{
			name: "malformed header - no ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer test-api-key"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "malformed header - empty value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if err != nil && tt.wantErr != nil {
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if (err != nil) != (tt.wantErr != nil) {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetAPIKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
