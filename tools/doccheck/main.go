// Command doccheck fails when a function or method has no doc comment, or a
// package has no package comment. Test files and generated files are skipped.
//
//	go run ./tools/doccheck ./...
//
// Each argument is a directory; a trailing "/..." includes everything below
// it, skipping testdata, vendor and hidden directories.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// main runs doccheck on the command-line arguments and exits non-zero when
// anything is missing a comment.
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run checks the directories named by args, prints one line per problem to
// stdout and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		args = []string{"."}
	}
	var dirs []string
	for _, arg := range args {
		found, err := expand(arg)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "doccheck:", err)
			return 2
		}
		dirs = append(dirs, found...)
	}
	var problems []string
	for _, dir := range dirs {
		p, err := checkDir(dir)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "doccheck:", err)
			return 2
		}
		problems = append(problems, p...)
	}
	for _, p := range problems {
		_, _ = fmt.Fprintln(stdout, p)
	}
	if len(problems) > 0 {
		_, _ = fmt.Fprintf(stdout, "%d missing doc comments\n", len(problems))
		return 1
	}
	return 0
}

// expand turns a directory argument into the list of directories it names.
func expand(arg string) ([]string, error) {
	root, recursive := strings.CutSuffix(arg, "/...")
	if root == "" || root == "..." {
		root, recursive = ".", true
	}
	// Walk through an fs.FS so the argument only ever names the tree to
	// check, never a path joined from it.
	fsys := os.DirFS(root)
	info, err := fs.Stat(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	if !recursive {
		return []string{root}, nil
	}
	var dirs []string
	err = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if path != "." && skipDir(d.Name()) {
			return fs.SkipDir
		}
		dirs = append(dirs, filepath.Join(root, filepath.FromSlash(path)))
		return nil
	})
	return dirs, err
}

// skipDir reports whether a directory is ignored by the go tool.
func skipDir(name string) bool {
	return name == "testdata" || name == "vendor" ||
		strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// checkDir parses the non-test Go files in dir and returns a problem for
// each undocumented function and for a package with no package comment.
func checkDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var problems []string
	hasPkgDoc := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		if ast.IsGenerated(f) {
			continue
		}
		pkg := f.Name.Name
		hasPkgDoc[pkg] = hasPkgDoc[pkg] || f.Doc != nil
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && fd.Doc == nil {
				problems = append(problems, fmt.Sprintf("%s: %s has no doc comment", fset.Position(fd.Pos()), funcName(fd)))
			}
		}
	}
	pkgs := make([]string, 0, len(hasPkgDoc))
	for pkg := range hasPkgDoc {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)
	for _, pkg := range pkgs {
		if !hasPkgDoc[pkg] {
			problems = append(problems, fmt.Sprintf("%s: package %s has no package comment", dir, pkg))
		}
	}
	return problems, nil
}

// funcName returns a function's name, qualified by its receiver type for
// methods.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if idx, ok := t.(*ast.IndexExpr); ok {
		t = idx.X
	}
	if idx, ok := t.(*ast.IndexListExpr); ok {
		t = idx.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}
