package stalwart

import (
	"strings"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// THE ZONE FILE — Stalwart answers what a domain needs in DNS as a zone file
// (x:Domain's dnsZoneFile), which this reads into provider.Records.

// parseZone reads the zone file Stalwart writes: one record per line, or a
// record whose data is split over lines inside parentheses (a long DKIM key).
func parseZone(text string) []provider.Record {
	var out []provider.Record
	var pending strings.Builder
	depth := 0
	flush := func(line string) {
		f := zoneFields(line)
		// name [ttl] [IN] type data...
		if len(f) < 3 {
			return
		}
		i := 1
		if isNumber(f[i]) {
			i++
		}
		if i < len(f) && strings.EqualFold(f[i], "IN") {
			i++
		}
		if i >= len(f)-1 {
			return
		}
		typ := strings.ToUpper(f[i])
		data := f[i+1:]
		r := provider.Record{Name: fqdn(f[0]), Type: typ}
		switch typ {
		case "TXT":
			r.Value = strings.Join(data, "")
		case "MX", "SRV", "CNAME":
			for j := range data {
				data[j] = strings.TrimSuffix(data[j], ".")
			}
			r.Value = strings.ToLower(strings.Join(data, " "))
		default:
			r.Value = strings.Join(data, " ")
		}
		out = append(out, r)
	}
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, ";"); i >= 0 && !strings.Contains(line[:i], `"`) {
			line = line[:i]
		}
		depth += strings.Count(line, "(") - strings.Count(line, ")")
		pending.WriteString(strings.NewReplacer("(", " ", ")", " ").Replace(line))
		pending.WriteString(" ")
		if depth <= 0 {
			flush(pending.String())
			pending.Reset()
			depth = 0
		}
	}
	return out
}

// zoneFields splits a zone line into fields, a quoted string being one field
// without its quotes.
func zoneFields(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote, have := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && inQuote && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
		case c == '"':
			inQuote = !inQuote
			have = true
			if !inQuote {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		case (c == ' ' || c == '\t') && !inQuote:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func fqdn(n string) string { return strings.ToLower(strings.TrimSuffix(n, ".")) }
