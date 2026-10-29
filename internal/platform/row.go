// ==========================================
// ALFYCHAT - LIGNES SQL AU FORMAT mysql2
// Les routes renvoient souvent des lignes brutes (SELECT *) : on garde l'ordre
// des colonnes et la sérialisation de mysql2 pour que le JSON reste identique.
// ==========================================

package platform

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Row est un objet JSON ordonné : une ligne SQL ou un corps de réponse.
type Row = *Object

type Object struct {
	keys []string
	vals map[string]any
}

// O construit un objet ordonné : O("a", 1, "b", 2).
func O(kv ...any) *Object {
	o := &Object{vals: make(map[string]any, len(kv)/2)}
	for i := 0; i+1 < len(kv); i += 2 {
		o.Set(kv[i].(string), kv[i+1])
	}
	return o
}

// Set ajoute ou remplace une clé en gardant sa position d'origine.
func (o *Object) Set(k string, v any) *Object {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *Object) Get(k string) any { return o.vals[k] }

func (o *Object) Has(k string) bool {
	_, ok := o.vals[k]
	return ok
}

func (o *Object) Delete(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, key := range o.keys {
		if key == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *Object) Keys() []string { return o.keys }

// Str renvoie la valeur en chaîne ("" si absente ou NULL).
func (o *Object) Str(k string) string {
	switch v := o.vals[k].(type) {
	case string:
		return v
	case nil:
		return ""
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// Int renvoie la valeur numérique (0 si absente).
func (o *Object) Int(k string) int64 {
	switch v := o.vals[k].(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	case bool:
		if v {
			return 1
		}
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}

// Bool applique la vérité JS sur la valeur (1/0, true/false, chaîne non vide).
func (o *Object) Bool(k string) bool { return Truthy(o.vals[k]) }

// IsNull vaut vrai si la clé est absente ou NULL.
func (o *Object) IsNull(k string) bool { return o.vals[k] == nil }

// Clone copie l'objet (équivalent de { ...row }).
func (o *Object) Clone() *Object {
	c := &Object{keys: append([]string(nil), o.keys...), vals: make(map[string]any, len(o.vals))}
	for k, v := range o.vals {
		c.vals[k] = v
	}
	return c
}

func (o *Object) MarshalJSON() ([]byte, error) {
	if o == nil {
		return []byte("null"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true
	for _, k := range o.keys {
		// JSON.stringify omet les propriétés valant undefined.
		if o.vals[k] == Undefined {
			continue
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		kb, _ := marshalNoEscape(k)
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := marshalNoEscape(o.vals[k])
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func (o *Object) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return &json.UnmarshalTypeError{Value: "non-object", Type: nil}
	}
	o.vals = map[string]any{}
	o.keys = nil
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		o.Set(kt.(string), decodeOrdered(raw))
	}
	return nil
}

// decodeOrdered décode une valeur JSON en gardant l'ordre des clés des objets.
func decodeOrdered(raw json.RawMessage) any {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case '{':
		o := &Object{}
		if err := o.UnmarshalJSON(trimmed); err != nil {
			return nil
		}
		return o
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil
		}
		out := make([]any, len(items))
		for i, it := range items {
			out[i] = decodeOrdered(it)
		}
		return out
	default:
		var v any
		_ = json.Unmarshal(trimmed, &v)
		return v
	}
}

// ParseJSON décode du JSON en valeurs ordonnées (*Object, []any, string, float64…).
func ParseJSON(b []byte) (any, error) {
	if !json.Valid(b) {
		return nil, &json.SyntaxError{}
	}
	return decodeOrdered(b), nil
}

// JSDate formate une date comme Date.prototype.toJSON().
func JSDate(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// ScanRows lit toutes les lignes avec les conversions de mysql2 :
// entiers → nombres, DECIMAL → chaîne, dates → ISO UTC, JSON → objet,
// binaires → { type: "Buffer", data: [...] }.
func ScanRows(rows *sql.Rows) ([]Row, error) {
	types, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	cols := make([]string, len(types))
	kinds := make([]string, len(types))
	for i, t := range types {
		cols[i] = t.Name()
		kinds[i] = strings.ToUpper(t.DatabaseTypeName())
	}

	out := []Row{}
	for rows.Next() {
		raw := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := &Object{keys: make([]string, 0, len(cols)), vals: make(map[string]any, len(cols))}
		for i, c := range cols {
			row.Set(c, convertColumn(kinds[i], raw[i]))
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func convertColumn(kind string, v any) any {
	if v == nil {
		return nil
	}
	if t, ok := v.(time.Time); ok {
		return JSDate(t)
	}
	b, isBytes := v.([]byte)
	switch kind {
	case "TINYINT", "SMALLINT", "MEDIUMINT", "INT", "INTEGER", "BIGINT", "YEAR",
		"UNSIGNED TINYINT", "UNSIGNED SMALLINT", "UNSIGNED MEDIUMINT", "UNSIGNED INT", "UNSIGNED BIGINT":
		if isBytes {
			n, err := strconv.ParseInt(string(b), 10, 64)
			if err != nil {
				return string(b)
			}
			return n
		}
		switch n := v.(type) {
		case int64:
			return n
		case uint64:
			return int64(n)
		}
		return v
	case "FLOAT", "DOUBLE":
		if isBytes {
			f, err := strconv.ParseFloat(string(b), 64)
			if err != nil {
				return string(b)
			}
			return f
		}
		switch f := v.(type) {
		case float32:
			return float64(f)
		case float64:
			return f
		}
		return v
	case "DECIMAL":
		if isBytes {
			return string(b)
		}
		return v
	case "JSON":
		if isBytes {
			parsed, err := ParseJSON(b)
			if err != nil {
				return string(b)
			}
			return parsed
		}
		return v
	case "DATETIME", "TIMESTAMP", "DATE":
		if isBytes {
			s := string(b)
			if strings.HasPrefix(s, "0000-00-00") {
				return nil
			}
			for _, layout := range []string{"2006-01-02 15:04:05.999999", "2006-01-02"} {
				if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
					return JSDate(t)
				}
			}
			return s
		}
		return v
	case "BLOB", "TINYBLOB", "MEDIUMBLOB", "LONGBLOB", "BINARY", "VARBINARY", "BIT", "GEOMETRY":
		if isBytes {
			data := make([]int, len(b))
			for i, c := range b {
				data[i] = int(c)
			}
			return O("type", "Buffer", "data", data)
		}
		return v
	default:
		if isBytes {
			return string(b)
		}
		return v
	}
}
