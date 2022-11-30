package osquery

import (
	"context"
	"fmt"
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
	var err error
	if d.Value == nil {
		return "", nil
	}
	switch t := d.Value.(type) {
	case string:
		if t == "" {
			return "", nil
		}
		if secs, err := strconv.Atoi(t); err != nil {
			return "", err
		} else {
			return time.Unix(int64(secs), 0), nil
		}
	case int:
		return time.Unix(int64(t), 0), nil
	case int32:
		return time.Unix(int64(t), 0), nil
	case int64:
		return time.Unix(int64(t), 0), nil
	default:
		err = fmt.Errorf("invalid type: %T", d.Value)
	}
	return nil, err
}
