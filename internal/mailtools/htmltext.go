package mailtools

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Elements whose content is never shown as text.
var skipElems = map[atom.Atom]bool{
	atom.Script: true, atom.Style: true, atom.Head: true, atom.Template: true,
	atom.Noscript: true, atom.Title: true, atom.Svg: true, atom.Textarea: true,
	atom.Iframe: true, atom.Object: true, atom.Math: true,
}

// Elements that start and end on their own line.
var blockElems = map[atom.Atom]bool{
	atom.P: true, atom.Div: true, atom.Tr: true, atom.Table: true, atom.Blockquote: true,
	atom.Hr: true, atom.H1: true, atom.H2: true, atom.H3: true, atom.H4: true, atom.H5: true,
	atom.H6: true, atom.Ul: true, atom.Ol: true, atom.Pre: true, atom.Section: true,
	atom.Article: true, atom.Header: true, atom.Footer: true, atom.Address: true, atom.Dl: true,
	atom.Dt: true, atom.Dd: true, atom.Form: true, atom.Fieldset: true, atom.Main: true,
	atom.Nav: true, atom.Aside: true, atom.Figure: true, atom.Figcaption: true, atom.Center: true,
}

// reHiddenStyle matches (after lowercasing and removing whitespace) inline
// styles that hide an element. Best effort; it is meant to catch the usual
// tricks for invisible text in emails.
var reHiddenStyle = regexp.MustCompile(`(?:^|;)(?:` +
	`display:none|visibility:(?:hidden|collapse)|color:transparent|` +
	`(?:opacity|font-size|(?:max-)?(?:width|height)|line-height):0(?:\.0*)?(?:[a-z%]+)?(?:;|!|$))`)

func hidingDeclarations(decls string) bool {
	return reHiddenStyle.MatchString(strings.ToLower(strings.Join(strings.Fields(decls), "")))
}

// hideRules are the simple selectors that a document's <style> blocks hide.
type hideRules struct {
	tags, classes, ids map[string]bool
}

var (
	reCSSComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reSelTag     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]*$`)
	reSelClass   = regexp.MustCompile(`^\.(-?[_a-zA-Z][_a-zA-Z0-9-]*)$`)
	reSelID      = regexp.MustCompile(`^#([_a-zA-Z0-9-]+)$`)
)

// addStyleSheet applies a best-effort reading of css: top-level rules whose
// selector list consists only of simple selectors (tag, .class, #id) and
// whose declarations hide content (same properties as inline styles) are
// recorded. Complex selectors and at-rules (including @media, whose rules
// only apply conditionally) are ignored.
func (h *hideRules) addStyleSheet(css string) {
	css = reCSSComment.ReplaceAllString(css, " ")
	for {
		open := strings.IndexByte(css, '{')
		if open < 0 {
			return
		}
		prelude := css[:open]
		if k := strings.LastIndexAny(prelude, ";}"); k >= 0 {
			prelude = prelude[k+1:] // skip statements like @import ...;
		}
		prelude = strings.TrimSpace(prelude)
		// Find the matching closing brace (blocks may nest in at-rules).
		depth, end := 0, len(css)
		for i := open; i < len(css); i++ {
			if css[i] == '{' {
				depth++
			} else if css[i] == '}' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		body := css[open+1 : end]
		if end < len(css) {
			css = css[end+1:]
		} else {
			css = ""
		}
		if strings.HasPrefix(prelude, "@") || !hidingDeclarations(body) {
			continue
		}
		var tags, classes, ids []string
		simple := true
		for _, sel := range strings.Split(prelude, ",") {
			sel = strings.TrimSpace(sel)
			switch {
			case reSelTag.MatchString(sel):
				tags = append(tags, strings.ToLower(sel))
			case reSelClass.MatchString(sel):
				classes = append(classes, sel[1:])
			case reSelID.MatchString(sel):
				ids = append(ids, sel[1:])
			default:
				simple = false
			}
		}
		if !simple {
			continue // ignore the whole rule if any selector is complex
		}
		for _, t := range tags {
			h.tags[t] = true
		}
		for _, c := range classes {
			h.classes[c] = true
		}
		for _, id := range ids {
			h.ids[id] = true
		}
	}
}

func collectHideRules(doc *html.Node) *hideRules {
	h := &hideRules{tags: map[string]bool{}, classes: map[string]bool{}, ids: map[string]bool{}}
	for n := range doc.Descendants() {
		if n.Type == html.ElementNode && n.DataAtom == atom.Style {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.TextNode {
					h.addStyleSheet(c.Data)
				}
			}
		}
	}
	return h
}

func hiddenElement(n *html.Node, h *hideRules) bool {
	if h.tags[n.Data] {
		return true
	}
	for _, a := range n.Attr {
		switch a.Key {
		case "class":
			for _, c := range strings.Fields(a.Val) {
				if h.classes[c] {
					return true
				}
			}
		case "id":
			if h.ids[a.Val] {
				return true
			}
		case "hidden":
			return true
		case "aria-hidden":
			if strings.EqualFold(strings.TrimSpace(a.Val), "true") {
				return true
			}
		case "style":
			if hidingDeclarations(a.Val) {
				return true
			}
		}
	}
	return false
}

var (
	reBlankLines = regexp.MustCompile(`\n{3,}`)
	reSpaces     = regexp.MustCompile(`[ \t\x{00a0}]+`)
)

const htmlUnconvertible = "[HTML body could not be converted to text]"

// htmlToText converts HTML to plain text with the HTML5 parser, which copes
// with truncated or unclosed markup like a browser would. Only visible text
// nodes are kept (entities are decoded once, by the parser); scripts, styles,
// embedded documents and hidden elements are dropped; links are reduced to
// their text. Nothing is ever resolved or fetched.
func htmlToText(src string) string {
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		// The parser gives up on pathological input (e.g. nesting deeper
		// than 512 elements). Show nothing rather than raw markup.
		return htmlUnconvertible
	}
	rules := collectHideRules(doc)
	var b strings.Builder
	pre := 0
	enter := func(n *html.Node) {
		switch n.Type {
		case html.TextNode:
			if pre > 0 {
				b.WriteString(n.Data)
			} else {
				b.WriteString(reSpaces.ReplaceAllString(strings.ReplaceAll(n.Data, "\n", " "), " "))
			}
		case html.ElementNode:
			switch {
			case n.DataAtom == atom.Br:
				b.WriteString("\n")
			case n.DataAtom == atom.Li:
				b.WriteString("\n- ")
			case n.DataAtom == atom.Td || n.DataAtom == atom.Th:
				b.WriteString(" ")
			case blockElems[n.DataAtom]:
				b.WriteString("\n")
			}
			if n.DataAtom == atom.Pre {
				pre++
			}
		}
	}
	leave := func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		if blockElems[n.DataAtom] {
			b.WriteString("\n")
		}
		if n.DataAtom == atom.Pre {
			pre--
		}
	}

	// Iterative pre-order walk: deeply nested markup cannot exhaust the stack.
	n := doc
	for n != nil {
		skip := n.Type == html.ElementNode && (skipElems[n.DataAtom] || hiddenElement(n, rules))
		if !skip {
			enter(n)
			if n.FirstChild != nil {
				n = n.FirstChild
				continue
			}
		}
		for n != nil {
			if !skip {
				leave(n)
			}
			skip = false
			if n == doc {
				n = nil
				break
			}
			if n.NextSibling != nil {
				n = n.NextSibling
				break
			}
			n = n.Parent
		}
	}

	lines := strings.Split(b.String(), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(reSpaces.ReplaceAllString(l, " "))
	}
	return strings.TrimSpace(reBlankLines.ReplaceAllString(strings.Join(lines, "\n"), "\n\n"))
}
