package main

import (
	"os"
	"testing"
)

func TestParseIntOption(t *testing.T) {
	cases := []struct {
		value    string
		expected int
	}{
		{
			value:    "",
			expected: 0,
		},
		{
			value:    "0",
			expected: 0,
		},
		{
			value:    "10",
			expected: 10,
		},
		{
			value:    "x",
			expected: 0,
		},
	}
	for _, tc := range cases {
		os.Setenv(optionClairThreshold, tc.value)
		if got := parseIntOption(optionClairThreshold); got != tc.expected {
			t.Errorf("expected %d got %d", tc.expected, got)
		}
	}
}

func TestParseBoolOption(t *testing.T) {
	cases := []struct {
		value    string
		expected bool
	}{
		{
			value:    "",
			expected: false,
		},
		{
			value:    "x",
			expected: false,
		},
		{
			value:    "true",
			expected: true,
		},
		{
			value:    "false",
			expected: false,
		},
	}
	for _, tc := range cases {
		os.Setenv(optionDockerInsecure, tc.value)
		if got := parseBoolOption(optionDockerInsecure); got != tc.expected {
			t.Errorf("%q: expected %v got %v", tc.value, tc.expected, got)
		}
	}
}

func TestParseOutputPriority(t *testing.T) {
	cases := []struct {
		priority   string
		expected   string
		shouldFail bool
	}{
		{
			priority: priorities[1],
			expected: priorities[1],
		},
		{
			priority: "",
			expected: priorities[0],
		},
		{
			priority:   "xxx",
			shouldFail: true,
		},
	}

	for _, tc := range cases {
		os.Setenv(optionClairOutput, tc.priority)
		p, err := parseOutputPriority()
		if (err != nil) != tc.shouldFail {
			t.Fatalf("expected error: %v, got: %v", tc.expected, err)
		}
		if p != tc.expected {
			t.Fatalf("expected output priority %s, got %s", tc.expected, p)
		}
	}
}
