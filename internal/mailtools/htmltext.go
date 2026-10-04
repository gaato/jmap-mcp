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

func hiddenElement(n *html.Node) bool {
	for _, a := range n.Attr {
		switch a.Key {
		case "hidden":
			return true
		case "aria-hidden":
			if strings.EqualFold(strings.TrimSpace(a.Val), "true") {
				return true
			}
		case "style":
			if reHiddenStyle.MatchString(strings.ToLower(strings.Join(strings.Fields(a.Val), ""))) {
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
		skip := n.Type == html.ElementNode && (skipElems[n.DataAtom] || hiddenElement(n))
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
