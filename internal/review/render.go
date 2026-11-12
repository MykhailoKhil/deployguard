// Package review turns a verified pull request event into a published GitHub
// Check Run: fetch the plan artifact, analyze it, and report the result.
package review

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/deployguard/deployguard/internal/domain"
	gh "github.com/deployguard/deployguard/internal/github"
)

const (
	maxRenderedFindings = 30
	maxFieldRunes       = 300
)

// Conclusion maps DeployGuard's recommendation onto a Check Run conclusion.
// REVIEW is neutral so it never blocks merging by itself; only BLOCK fails.
func Conclusion(recommendation domain.Recommendation) string {
	switch recommendation {
	case domain.RecommendationSafe:
		return "success"
	case domain.RecommendationBlock:
		return "failure"
	default:
		return "neutral"
	}
}

// Render builds the check run for one analysis. Every plan-derived string is
// untrusted (resource names come from the repository), so it is sanitized
// before it reaches GitHub's markdown renderer.
func Render(headSHA string, analysis domain.Analysis) gh.CheckRun {
	var b strings.Builder
	fmt.Fprintf(&b, "**Recommendation: %s** · Risk level %s · Score %d/100\n\n", analysis.Recommendation, analysis.Level, analysis.Score)
	b.WriteString(clean(analysis.Explanation, 2*maxFieldRunes) + "\n\n")
	fmt.Fprintf(&b, "| Cost | Reliability | Security | Changed resources | Critical resources |\n| --- | --- | --- | --- | --- |\n| %d | %d | %d | %d | %d |\n\n",
		analysis.Cost.Score, analysis.Reliability.Score, analysis.Security.Score, analysis.BlastRadius.ChangedResources, analysis.BlastRadius.CriticalResources)
	if analysis.Provenance.Checked {
		state := "not verified"
		if analysis.Provenance.Verified {
			state = "verified"
		}
		fmt.Fprintf(&b, "**Plan provenance: %s.** %s.\n\n", state, clean(analysis.Provenance.Detail, maxFieldRunes))
	}
	if len(analysis.Findings) == 0 {
		b.WriteString("No deterministic risk findings. Review the plan and its provenance before applying.\n")
	} else {
		b.WriteString("### Findings\n\n")
		for i, finding := range analysis.Findings {
			if i == maxRenderedFindings {
				fmt.Fprintf(&b, "\n…and %d more finding(s) not shown.\n", len(analysis.Findings)-maxRenderedFindings)
				break
			}
			fmt.Fprintf(&b, "- **%s** — %s", finding.Severity, clean(finding.Summary, maxFieldRunes))
			for _, resource := range finding.Resources {
				fmt.Fprintf(&b, " `%s`", code(resource))
			}
			fmt.Fprintf(&b, "  \n  Next step: %s\n", clean(finding.Remediation, maxFieldRunes))
		}
	}
	if analysis.AIExplanation != "" {
		b.WriteString("\n> **AI summary (generated, not authoritative)**\n")
		for _, line := range strings.Split(clean(analysis.AIExplanation, 2000), "\n") {
			b.WriteString("> " + line + "\n")
		}
	}
	b.WriteString("\n_Deterministic rules decide this verdict; they are not a comprehensive security or cost assessment. DeployGuard never applies infrastructure changes._\n")
	return gh.CheckRun{
		HeadSHA:    headSHA,
		Conclusion: Conclusion(analysis.Recommendation),
		Title:      fmt.Sprintf("%s — %s risk (score %d/100)", analysis.Recommendation, analysis.Level, analysis.Score),
		Summary:    b.String(),
	}
}

// Neutral builds a check run for when no verdict could be produced.
func Neutral(headSHA, title, detail string) gh.CheckRun {
	return gh.CheckRun{HeadSHA: headSHA, Conclusion: "neutral", Title: title, Summary: clean(detail, 1000) + "\n"}
}

// clean strips control characters, escapes markdown and HTML, defuses @mentions and automatic
// links, and bounds the length. Newlines survive; callers split on them.
func clean(value string, limit int) string {
	var b strings.Builder
	count := 0
	for _, r := range value {
		if count == limit {
			b.WriteString("…")
			break
		}
		switch {
		case r == '\n':
			b.WriteRune(r)
		case unicode.IsControl(r):
			b.WriteRune(' ')
		case strings.ContainsRune("\\`*_[]<>|#~&", r):
			b.WriteRune('\\')
			b.WriteRune(r)
		case r == '@':
			b.WriteString("@​") // zero-width space stops a mention
		default:
			b.WriteRune(r)
		}
		count++
	}
	return defuseLinks(b.String())
}

var (
	wwwPattern   = regexp.MustCompile(`(?i)www\.`)
	issueRefLink = regexp.MustCompile(`(?i)\bGH-\d`)
)

// defuseLinks stops GitHub from turning text into a clickable link or cross-reference, by putting an
// invisible zero-width space where the link syntax begins. The AI summary is influenced by plan data
// (resource names come from the repository), so without this it could make a bot comment carry a
// phishing link. Email addresses are already safe because "@" is defused in clean, and "[", "<" and
// "#" are escaped there.
func defuseLinks(text string) string {
	text = strings.ReplaceAll(text, "://", ":\u200b//") // http(s)://, ftp://, ...
	text = wwwPattern.ReplaceAllStringFunc(text, func(match string) string { return match[:3] + "\u200b." })
	return issueRefLink.ReplaceAllStringFunc(text, func(match string) string { return match[:2] + "\u200b" + match[2:] })
}

// code prepares text for an inline code span: no backticks, no newlines.
func code(value string) string {
	value = strings.NewReplacer("`", "'", "\n", " ", "\r", " ").Replace(value)
	if runes := []rune(value); len(runes) > maxFieldRunes {
		value = string(runes[:maxFieldRunes]) + "…"
	}
	return value
}

// RenderComment builds the markdown of the (opt-in) pull request comment from the same content as
// the Check Run, so the two never disagree. It names the commit, because the comment is edited in
// place and a reader must be able to tell which commit it describes.
func RenderComment(headSHA string, analysis domain.Analysis) string {
	return commentText(headSHA, Render(headSHA, analysis))
}

// RenderNeutralComment is the comment for a commit that has no verdict (see Neutral).
func RenderNeutralComment(run gh.CheckRun) string { return commentText(run.HeadSHA, run) }

func commentText(headSHA string, run gh.CheckRun) string {
	short := code(headSHA)
	if len(short) > 7 {
		short = short[:7]
	}
	return "### DeployGuard: " + run.Title + "\n\nCommit `" + short + "`\n\n" + run.Summary
}
