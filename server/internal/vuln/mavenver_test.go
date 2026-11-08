package vuln

import "testing"

// Ordering cases taken from Maven's ComparableVersionTest plus versions common in advisories.
func TestCompareMavenOrdering(t *testing.T) {
	ascending := [][]string{
		{"1", "2"}, {"1.5", "2"}, {"1", "2.5"}, {"1.0", "1.1"}, {"1.1", "1.2"}, {"1.0.0", "1.1"}, {"1.1", "1.2.0"},
		{"1.0-alpha-1", "1.0"}, {"1.0-alpha-1", "1.0-alpha-2"}, {"1.0-alpha-1", "1.0-beta-1"},
		{"1.0-beta-1", "1.0-SNAPSHOT"}, {"1.0-SNAPSHOT", "1.0"}, {"1.0-alpha-1-SNAPSHOT", "1.0-alpha-1"},
		{"1.0", "1.0-1"}, {"1.0-1", "1.0-2"}, {"1.0.0", "1.0-1"}, {"2.0-1", "2.0.1"}, {"2.0.1-klm", "2.0.1-lmn"},
		{"2.0.1", "2.0.1-xyz"}, {"2.0.1", "2.0.1-123"}, {"2.0.1-xyz", "2.0.1-123"},
		{"1-alpha", "1-beta"}, {"1-beta", "1-milestone"}, {"1-milestone", "1-rc"}, {"1-rc", "1-snapshot"},
		{"1-snapshot", "1"}, {"1", "1-sp"}, {"1-sp", "1.1"},
		{"2.15.0-rc1", "2.15.0"}, {"2.14.1", "2.15.0"}, {"2.16.0", "2.17.1"}, {"5.3.9", "5.3.20"},
		{"1.2.3-a1", "1.2.3-b1"}, {"1.2.3.m1", "1.2.3.rc1"},
		{"9.4.43.v20210629", "9.4.44.v20210927"}, {"2.9.10.7", "2.9.10.8"}, {"2.13.4", "2.13.4.2"},
		{"3.0.0-M1", "3.0.0-RC1"}, {"1.0.0.RC1", "1.0.0.RELEASE"},
		{"10.1.33", "10.1.34"}, {"10.0.27", "10.1.0-M1"},
	}
	for _, p := range ascending {
		if c := CompareMaven(p[0], p[1]); c >= 0 {
			t.Errorf("CompareMaven(%q, %q) = %d, want < 0", p[0], p[1], c)
		}
		if c := CompareMaven(p[1], p[0]); c <= 0 {
			t.Errorf("CompareMaven(%q, %q) = %d, want > 0", p[1], p[0], c)
		}
	}
}

func TestCompareMavenEquality(t *testing.T) {
	equal := [][]string{
		{"1", "1.0"}, {"1", "1.0.0"}, {"1.0", "1.0.0"}, {"1", "1-0"}, {"1.0-alpha1", "1.0-ALPHA1"},
		{"1-ga", "1"}, {"1-final", "1"}, {"1.0.0.RELEASE", "1.0.0"}, {"1.0-cr1", "1.0-rc1"},
		{"1a1", "1-alpha-1"}, {"1.0-rc", "1-rc"}, {"007", "7"},
		{"99999999999999999999999", "99999999999999999999999.0"},
	}
	for _, p := range equal {
		if c := CompareMaven(p[0], p[1]); c != 0 {
			t.Errorf("CompareMaven(%q, %q) = %d, want 0", p[0], p[1], c)
		}
	}
}
