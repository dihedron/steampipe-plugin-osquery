package osquery

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func TrimString(ctx context.Context, d *transform.TransformData) (interface{}, error) {
	if d.Value == nil {
		return "", nil
	}
	return strings.TrimSpace(d.Value.(string)), nil
}

func SafeInt(def int) func(context.Context, *transform.TransformData) (interface{}, error) {
	return func(ctx context.Context, d *transform.TransformData) (interface{}, error) {
		if d.Value == nil || d.Value.(string) == "" {
			return def, nil
		}
		return strconv.Atoi(d.Value.(string))
	}
}

func EpochToDate(ctx context.Context, d *transform.TransformData) (interface{}, error) {
	if d.Value == nil || d.Value.(string) == "" {
		return "", nil
	}
	if secs, err := strconv.Atoi(d.Value.(string)); err != nil {
		return "", err
	} else {
		return time.Unix(int64(secs), 0), nil
	}
}
