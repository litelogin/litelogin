package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"
)

// Output formats.
const (
	OutputTable = "table"
	OutputJSON  = "json"
)

type field struct {
	name      string
	value     reflect.Value
	omitEmpty bool
}

// jsonFields returns a struct's fields under their JSON names, in
// declaration order.
func jsonFields(v reflect.Value) []field {
	for v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	var fields []field
	t := v.Type()
	for i := range t.NumField() {
		sf := t.Field(i)
		tag := sf.Tag.Get("json")
		if !sf.IsExported() || tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" {
			name = sf.Name
		}
		fields = append(fields, field{name: name, value: v.Field(i), omitEmpty: strings.Contains(opts, "omitempty")})
	}
	return fields
}

func formatValue(v reflect.Value) string {
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Slice:
		parts := make([]string, v.Len())
		for i := range parts {
			parts[i] = formatValue(v.Index(i))
		}
		return strings.Join(parts, ", ")
	case reflect.Map:
		keys := make([]string, 0, v.Len())
		for _, k := range v.MapKeys() {
			keys = append(keys, fmt.Sprint(k.Interface()))
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = k + "=" + formatValue(v.MapIndex(reflect.ValueOf(k)))
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprint(v.Interface())
	}
}

// printObject prints one resource: JSON, or a two-column table of its
// fields.
func printObject(w io.Writer, format string, v any) error {
	if format == OutputJSON {
		return printJSON(w, v)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, f := range jsonFields(reflect.ValueOf(v)) {
		if f.omitEmpty && f.value.IsZero() {
			continue
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\n", f.name, formatValue(f.value))
	}
	return tw.Flush()
}

// printList prints a list of resources: JSON, or a table with the given
// columns (JSON field names).
func printList[T any](w io.Writer, format string, items []T, nextCursor string, columns ...string) error {
	if format == OutputJSON {
		return printJSON(w, struct {
			Items      []T    `json:"items"`
			NextCursor string `json:"next_cursor,omitempty"`
		}{items, nextCursor})
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, strings.ToUpper(strings.Join(columns, "\t")))
	for _, item := range items {
		byName := map[string]string{}
		for _, f := range jsonFields(reflect.ValueOf(item)) {
			byName[f.name] = formatValue(f.value)
		}
		row := make([]string, len(columns))
		for i, c := range columns {
			row[i] = byName[c]
		}
		_, _ = fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if nextCursor != "" {
		_, _ = fmt.Fprintf(w, "\nMore results: --cursor %s\n", nextCursor)
	}
	return nil
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
