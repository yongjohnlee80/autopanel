package app

// proofGrade is code no test runs: the coverage policy must refuse it.
func proofGrade(n int) string {
	switch {
	case n < 0:
		return "negative"
	case n == 0:
		return "zero"
	case n < 10:
		return "small"
	case n < 100:
		return "medium"
	}
	return "large"
}

var _ = proofGrade
