// Package kallsyms loads and parses the kernel symbol table
// so that other modules can attach kprobe to functions.
package kallsyms

import (
	"bytes"
	"regexp"
	"strconv"
)

var regexpSymbolItem = regexp.MustCompilePOSIX(
	`^([0-9a-f]+) ([A-Za-z0-9]) ([^ \t]+)(\t\[([^]]+)\])?$`)

func init() {
	regexpSymbolItem.Longest()
}

type symbol struct {
	addr uint64
	typ  byte
}

// SymbolTable is the parsed symbol table from kernel.
type SymbolTable struct {
	table map[string][]symbol
}

// Lookup looks up the symbol in a module.
func (t *SymbolTable) Lookup(name, types string) uint64 {
	syms := t.table[name]
	for i := len(syms); i > 0; i-- {
		if bytes.IndexAny([]byte{syms[i-1].typ}, types) >= 0 {
			return syms[i-1].addr
		}
	}
	return 0
}

// Parse the kallsyms data and return the parsed symbol table.
func Parse(
	kallsyms []byte, interestedModules map[string]struct{},
) map[string]*SymbolTable {
	result := make(map[string]*SymbolTable)
	for len(kallsyms) > 0 {
		index := bytes.Index(kallsyms, []byte("\n"))
		current := kallsyms
		if index < 0 {
			kallsyms = nil
		} else {
			current = kallsyms[0:index]
			kallsyms = kallsyms[index+1:]
		}
		// 0: the whole string
		// 1: symbol address
		// 2: symbol type
		// 3: symbol name
		// 4: string with module string
		// 5: module containing symbol
		matches := regexpSymbolItem.FindSubmatch(current)
		if len(matches) == 0 {
			continue
		}
		module := string(matches[5])
		if interestedModules != nil {
			if _, ok := interestedModules[module]; !ok {
				continue
			}
		}
		addr, _ := strconv.ParseUint(string(matches[1]), 16, 64)
		typ := matches[2][0]
		name := string(matches[3])
		table := result[module]
		if table == nil {
			table = &SymbolTable{
				table: make(map[string][]symbol),
			}
			result[module] = table
		}
		table.table[name] = append(table.table[name], symbol{
			addr: uint64(addr),
			typ:  typ,
		})
	}
	return result
}
