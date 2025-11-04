package model

// Leak are data returned by gitleaks module
type Leak struct {
	RuleID      string
	Description string
	File        string
	StartLine   int
}
