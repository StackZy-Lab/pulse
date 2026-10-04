package probe

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// StatusMatcher decides whether an HTTP status code counts as a successful
// check. The zero value accepts every code below 400, which is what a plain
// "is this endpoint serving?" check wants.
type StatusMatcher struct {
	ranges []statusRange
}

type statusRange struct {
	lo, hi int
}

// DefaultStatusMatcher accepts 1xx, 2xx and 3xx responses.
func DefaultStatusMatcher() StatusMatcher { return StatusMatcher{} }

// ParseStatusMatcher parses a specification such as "200", "200,204" or a
// range like "200-299". Class shorthands such as "2xx" are accepted too.
// An empty specification returns the default matcher.
func ParseStatusMatcher(spec string) (StatusMatcher, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return StatusMatcher{}, nil
	}

	var matcher StatusMatcher
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return StatusMatcher{}, fmt.Errorf("empty status in %q", spec)
		}

		switch {
		case len(part) == 3 && strings.HasSuffix(strings.ToLower(part), "xx"):
			digit := part[0]
			if digit < '1' || digit > '5' {
				return StatusMatcher{}, fmt.Errorf("invalid status class %q", part)
			}
			lo := int(digit-'0') * 100
			matcher.ranges = append(matcher.ranges, statusRange{lo, lo + 99})
		case strings.Contains(part, "-"):
			lo, hi, err := parseStatusRange(part)
			if err != nil {
				return StatusMatcher{}, err
			}
			matcher.ranges = append(matcher.ranges, statusRange{lo, hi})
		default:
			code, err := parseStatusCode(part)
			if err != nil {
				return StatusMatcher{}, err
			}
			matcher.ranges = append(matcher.ranges, statusRange{code, code})
		}
	}

	sort.Slice(matcher.ranges, func(i, j int) bool {
		return matcher.ranges[i].lo < matcher.ranges[j].lo
	})
	return matcher, nil
}

func parseStatusRange(spec string) (int, int, error) {
	lo, hi, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, fmt.Errorf("invalid status range %q", spec)
	}
	low, err := parseStatusCode(strings.TrimSpace(lo))
	if err != nil {
		return 0, 0, err
	}
	high, err := parseStatusCode(strings.TrimSpace(hi))
	if err != nil {
		return 0, 0, err
	}
	if low > high {
		return 0, 0, fmt.Errorf("invalid status range %q: %d is greater than %d", spec, low, high)
	}
	return low, high, nil
}

func parseStatusCode(spec string) (int, error) {
	code, err := strconv.Atoi(strings.TrimSpace(spec))
	if err != nil || code < 100 || code > 599 {
		return 0, fmt.Errorf("invalid status code %q", spec)
	}
	return code, nil
}

// Match reports whether code is accepted.
func (m StatusMatcher) Match(code int) bool {
	if len(m.ranges) == 0 {
		return code >= 100 && code < 400
	}
	for _, r := range m.ranges {
		if code >= r.lo && code <= r.hi {
			return true
		}
	}
	return false
}

// String renders the matcher back into its specification form, for messages
// and help output.
func (m StatusMatcher) String() string {
	if len(m.ranges) == 0 {
		return "1xx-3xx"
	}
	parts := make([]string, 0, len(m.ranges))
	for _, r := range m.ranges {
		if r.lo == r.hi {
			parts = append(parts, strconv.Itoa(r.lo))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d-%d", r.lo, r.hi))
	}
	return strings.Join(parts, ",")
}
