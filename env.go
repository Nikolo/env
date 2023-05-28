package env

import (
	"encoding"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// nolint: gochecknoglobals
var (
	defaultBuiltInParsers = map[reflect.Kind]ParserFunc{
		reflect.Bool: func(v string) (interface{}, error) {
			return strconv.ParseBool(v)
		},
		reflect.String: func(v string) (interface{}, error) {
			return v, nil
		},
		reflect.Int: func(v string) (interface{}, error) {
			i, err := strconv.ParseInt(v, 10, 32)
			return int(i), err
		},
		reflect.Int16: func(v string) (interface{}, error) {
			i, err := strconv.ParseInt(v, 10, 16)
			return int16(i), err
		},
		reflect.Int32: func(v string) (interface{}, error) {
			i, err := strconv.ParseInt(v, 10, 32)
			return int32(i), err
		},
		reflect.Int64: func(v string) (interface{}, error) {
			return strconv.ParseInt(v, 10, 64)
		},
		reflect.Int8: func(v string) (interface{}, error) {
			i, err := strconv.ParseInt(v, 10, 8)
			return int8(i), err
		},
		reflect.Uint: func(v string) (interface{}, error) {
			i, err := strconv.ParseUint(v, 10, 32)
			return uint(i), err
		},
		reflect.Uint16: func(v string) (interface{}, error) {
			i, err := strconv.ParseUint(v, 10, 16)
			return uint16(i), err
		},
		reflect.Uint32: func(v string) (interface{}, error) {
			i, err := strconv.ParseUint(v, 10, 32)
			return uint32(i), err
		},
		reflect.Uint64: func(v string) (interface{}, error) {
			i, err := strconv.ParseUint(v, 10, 64)
			return i, err
		},
		reflect.Uint8: func(v string) (interface{}, error) {
			i, err := strconv.ParseUint(v, 10, 8)
			return uint8(i), err
		},
		reflect.Float64: func(v string) (interface{}, error) {
			return strconv.ParseFloat(v, 64)
		},
		reflect.Float32: func(v string) (interface{}, error) {
			f, err := strconv.ParseFloat(v, 32)
			return float32(f), err
		},
	}
	defaultBuiltInFormaters = map[reflect.Kind]FormatFunc{
		reflect.Bool: func(i reflect.Value) (string, error) {
			b := i.Bool()

			return strconv.FormatBool(b), nil
		},
		reflect.String: func(i reflect.Value) (string, error) {
			s := i.String()

			return s, nil
		},
		reflect.Int: func(i reflect.Value) (string, error) {
			ii := i.Int()

			return strconv.FormatInt(int64(ii), 10), nil
		},
		reflect.Int16: func(i reflect.Value) (string, error) {
			ii := i.Int()

			return strconv.FormatInt(int64(ii), 10), nil
		},
		reflect.Int32: func(i reflect.Value) (string, error) {
			ii := i.Int()

			return strconv.FormatInt(int64(ii), 10), nil
		},
		reflect.Int64: func(i reflect.Value) (string, error) {
			ii := i.Int()

			return strconv.FormatInt(int64(ii), 10), nil
		},
		reflect.Int8: func(i reflect.Value) (string, error) {
			ii := i.Int()

			return strconv.FormatInt(int64(ii), 10), nil
		},
		reflect.Uint16: func(i reflect.Value) (string, error) {
			ii := i.Uint()

			return strconv.FormatUint(uint64(ii), 10), nil
		},
		reflect.Uint32: func(i reflect.Value) (string, error) {
			ii := i.Uint()

			return strconv.FormatUint(uint64(ii), 10), nil
		},
		reflect.Uint64: func(i reflect.Value) (string, error) {
			ii := i.Uint()

			return strconv.FormatUint(uint64(ii), 10), nil
		},
		reflect.Uint8: func(i reflect.Value) (string, error) {
			ii := i.Uint()

			return strconv.FormatUint(uint64(ii), 10), nil
		},
		reflect.Uint: func(i reflect.Value) (string, error) {
			ii := i.Uint()

			return strconv.FormatUint(uint64(ii), 10), nil
		},
		reflect.Float64: func(i reflect.Value) (string, error) {
			f := i.Float()

			return strconv.FormatFloat(float64(f), 'f', -1, 64), nil
		},
		reflect.Float32: func(i reflect.Value) (string, error) {
			f := i.Float()

			return strconv.FormatFloat(float64(f), 'f', -1, 32), nil
		},
	}
	DefaultCollector Collector = &EmptyCollector{}
)

func defaultTypeParsers() map[reflect.Type]ParserFunc {
	return map[reflect.Type]ParserFunc{
		reflect.TypeOf(url.URL{}): func(v string) (interface{}, error) {
			u, err := url.Parse(v)
			if err != nil {
				return nil, newParseValueError("unable to parse URL", err)
			}
			return *u, nil
		},
		reflect.TypeOf(time.Nanosecond): func(v string) (interface{}, error) {
			s, err := time.ParseDuration(v)
			if err != nil {
				return nil, newParseValueError("unable to parse duration", err)
			}
			return s, err
		},
	}
}

func defaultTypeFormaters() map[reflect.Type]FormatFunc {
	var dt time.Duration

	return map[reflect.Type]FormatFunc{
		reflect.TypeOf(url.URL{}): func(i reflect.Value) (string, error) {
			u, ok := i.Interface().(url.URL)
			if !ok {
				return "", fmt.Errorf("can't format not `url` (%+v) object as url", i)
			}

			return u.String(), nil
		},
		reflect.TypeOf(dt): func(i reflect.Value) (string, error) {
			u, ok := i.Interface().(time.Duration)
			if !ok {
				return "", fmt.Errorf("can't format not `duration` (%+v) object as duration", i)
			}

			return u.String(), nil
		},
	}
}

// ParserFunc defines the signature of a function that can be used within `CustomParsers`.
type ParserFunc func(v string) (interface{}, error)

// UnmarshalFunc defines the signature of a function that can be used within `CustomParsers`.
type FormatFunc func(i reflect.Value) (string, error)

// OnSetFn is a hook that can be run when a value is set.
type OnSetFn func(tag string, value interface{}, isDefault bool)

// Options for the parser.
type Options struct {
	// Environment keys and values that will be accessible for the service.
	Environment map[string]string

	// TagName specifies another tagname to use rather than the default env.
	TagName string

	// RequiredIfNoDef automatically sets all env as required if they do not
	// declare 'envDefault'.
	RequiredIfNoDef bool

	// OnSet allows to run a function when a value is set.
	OnSet OnSetFn

	// Prefix define a prefix for each key.
	Prefix string

	// UseFieldNameByDefault defines whether or not env should use the field
	// name by default if the `env` key is missing.
	UseFieldNameByDefault bool

	// Custom parse functions for different types.
	FuncMap map[reflect.Type]ParserFunc

	// Custom formater functions for different types.
	FormatMap map[reflect.Type]FormatFunc

	// Container for collect all processed env fields
	Collector Collector
}

type Collector interface {
	AddCodeValue(key string, isPtr bool, val string)
	Set(key string, envF EnvField)
}

type EnvField struct {
	File, Required, Unset, NotEmpty, Expand, DefaultExist, IsPtr bool
	Default, EnvValue, CodeValue, Separator                      string
}

type EmptyCollector struct{}

func (e *EmptyCollector) Set(key string, envF EnvField)                   {}
func (e *EmptyCollector) AddCodeValue(key string, isPtr bool, val string) {}

func NewSimpleCollector() *SimpleCollector {
	return &SimpleCollector{
		Map: map[string]*EnvField{},
	}
}

type SimpleCollector struct {
	Map map[string]*EnvField
	sync.Mutex
}

func (c *SimpleCollector) AddCodeValue(key string, isPtr bool, val string) {
	c.Lock()
	defer c.Unlock()

	cm, ex := c.Map[key]
	if !ex {
		panic("can't add codeValue for unexistings env: " + key)
	}

	cm.CodeValue = val
	cm.IsPtr = isPtr
}

func (c *SimpleCollector) Set(key string, envF EnvField) {
	c.Lock()
	defer c.Unlock()

	if _, ex := c.Map[key]; ex {
		panic("env already exists: " + key)
	}

	c.Map[key] = &envF
}

func defaultOptions() Options {
	return Options{
		TagName:     "env",
		Environment: toMap(os.Environ()),
		FuncMap:     defaultTypeParsers(),
		FormatMap:   defaultTypeFormaters(),
		Collector:   DefaultCollector,
	}
}

func customOptions(opt Options) Options {
	defOpts := defaultOptions()
	if opt.TagName == "" {
		opt.TagName = defOpts.TagName
	}
	if opt.Environment == nil {
		opt.Environment = defOpts.Environment
	}
	if opt.FuncMap == nil {
		opt.FuncMap = map[reflect.Type]ParserFunc{}
	}
	if opt.FormatMap == nil {
		opt.FormatMap = map[reflect.Type]FormatFunc{}
	}
	if opt.Collector == nil {
		opt.Collector = defOpts.Collector
	}
	for k, v := range defOpts.FuncMap {
		opt.FuncMap[k] = v
	}
	return opt
}

func optionsWithEnvPrefix(field reflect.StructField, opts Options) Options {
	return Options{
		Environment:           opts.Environment,
		TagName:               opts.TagName,
		RequiredIfNoDef:       opts.RequiredIfNoDef,
		OnSet:                 opts.OnSet,
		Prefix:                opts.Prefix + field.Tag.Get("envPrefix"),
		UseFieldNameByDefault: opts.UseFieldNameByDefault,
		FuncMap:               opts.FuncMap,
		Collector:             opts.Collector,
	}
}

// Parse parses a struct containing `env` tags and loads its values from
// environment variables.
func Parse(v interface{}) error {
	return parseInternal(v, defaultOptions())
}

// Parse parses a struct containing `env` tags and loads its values from
// environment variables.
func ParseWithOptions(v interface{}, opts Options) error {
	return parseInternal(v, customOptions(opts))
}

func parseInternal(v interface{}, opts Options) error {
	ptrRef := reflect.ValueOf(v)
	if ptrRef.Kind() != reflect.Ptr {
		return newAggregateError(NotStructPtrError{})
	}
	ref := ptrRef.Elem()
	if ref.Kind() != reflect.Struct {
		return newAggregateError(NotStructPtrError{})
	}
	return doParse(ref, opts)
}

func doParse(ref reflect.Value, opts Options) error {
	refType := ref.Type()

	var agrErr AggregateError

	for i := 0; i < refType.NumField(); i++ {
		refField := ref.Field(i)
		refTypeField := refType.Field(i)

		if err := doParseField(refField, refTypeField, opts); err != nil {
			if val, ok := err.(AggregateError); ok {
				agrErr.Errors = append(agrErr.Errors, val.Errors...)
			} else {
				agrErr.Errors = append(agrErr.Errors, err)
			}
		}
	}

	if len(agrErr.Errors) == 0 {
		return nil
	}

	return agrErr
}

func doParseField(refField reflect.Value, refTypeField reflect.StructField, opts Options) error {
	if !refField.CanSet() {
		return nil
	}
	if reflect.Ptr == refField.Kind() && !refField.IsNil() {
		return parseInternal(refField.Interface(), optionsWithEnvPrefix(refTypeField, opts))
	}
	if reflect.Struct == refField.Kind() && refField.CanAddr() && refField.Type().Name() == "" {
		return parseInternal(refField.Addr().Interface(), optionsWithEnvPrefix(refTypeField, opts))
	}

	key, value, err := get(refTypeField, opts)
	if err != nil {
		return err
	}

	eVal, isPtr, err := makeEnv(refField, refTypeField, refTypeField.Type, opts.FormatMap)
	if err != nil {
		return err
	}

	opts.Collector.AddCodeValue(key, isPtr, eVal)

	if value != "" {
		return set(refField, refTypeField, value, opts.FuncMap)
	}

	if reflect.Struct == refField.Kind() {
		return doParse(refField, optionsWithEnvPrefix(refTypeField, opts))
	}

	return nil
}

const underscore rune = '_'

func toEnvName(input string) string {
	var output []rune
	for i, c := range input {
		if i > 0 && output[i-1] != underscore && c != underscore && unicode.ToUpper(c) == c {
			output = append(output, underscore)
		}
		output = append(output, unicode.ToUpper(c))
	}
	return string(output)
}

func get(field reflect.StructField, opts Options) (k, val string, err error) {
	var exists bool
	var isDefault bool
	var loadFile bool
	var unset bool
	var notEmpty bool

	required := opts.RequiredIfNoDef
	ownKey, tags := parseKeyForOption(field.Tag.Get(opts.TagName))
	if ownKey == "" && opts.UseFieldNameByDefault {
		ownKey = toEnvName(field.Name)
	}

	prefix := opts.Prefix
	key := prefix + ownKey

	envF := EnvField{}

	for _, tag := range tags {
		switch tag {
		case "":
			continue
		case "file":
			envF.File = true
			loadFile = true
		case "required":
			envF.Required = true
			required = true
		case "unset":
			envF.Unset = true
			unset = true
		case "notEmpty":
			envF.NotEmpty = true
			notEmpty = true
		default:
			return "", "", newNoSupportedTagOptionError(tag)
		}
	}

	expand := strings.EqualFold(field.Tag.Get("envExpand"), "true")
	envF.Expand = expand
	defaultValue, defExists := field.Tag.Lookup("envDefault")
	envF.Default = defaultValue
	envF.DefaultExist = defExists
	val, exists, isDefault = getOr(key, defaultValue, defExists, opts.Environment)

	envF.Separator = getFieldSeparator(field)

	if expand {
		val = os.ExpandEnv(val)
	}

	if unset {
		defer os.Unsetenv(key)
	}

	if required && !exists && len(ownKey) > 0 {
		opts.Collector.Set(key, envF)

		return "", "", newEnvVarIsNotSet(key)
	}

	if notEmpty && val == "" {
		opts.Collector.Set(key, envF)

		return "", "", newEmptyEnvVarError(key)
	}

	if loadFile && val != "" {
		filename := val
		val, err = getFromFile(filename)
		if err != nil {
			return "", "", newLoadFileContentError(filename, key, err)
		}
	}

	envF.EnvValue = val
	envF.Separator = getFieldSeparator(field)

	opts.Collector.Set(key, envF)

	if opts.OnSet != nil {
		opts.OnSet(key, val, isDefault)
	}

	return key, val, err
}

// split the env tag's key into the expected key and desired option, if any.
func parseKeyForOption(key string) (string, []string) {
	opts := strings.Split(key, ",")
	return opts[0], opts[1:]
}

func getFromFile(filename string) (value string, err error) {
	b, err := os.ReadFile(filename)
	return string(b), err
}

func getOr(key, defaultValue string, defExists bool, envs map[string]string) (string, bool, bool) {
	value, exists := envs[key]
	switch {
	case (!exists || key == "") && defExists:
		return defaultValue, true, true
	case exists && value == "" && defExists:
		return defaultValue, true, true
	case !exists:
		return "", false, false
	}

	return value, true, false
}

func makeEnv(field reflect.Value, sf reflect.StructField, typee reflect.Type, funcMap map[reflect.Type]FormatFunc) (string, bool, error) {
	isPtr := false

	if tm := asTextMarshaler(field); tm != nil {
		b, err := tm.MarshalText()
		return string(b), typee.Kind() == reflect.Ptr, err
	}

	if typee.Kind() == reflect.Ptr {
		isPtr = true
		typee = typee.Elem()
		field = field.Elem()
	}

	formatFunc, ok := funcMap[typee]
	if ok {
		val, err := formatFunc(field)
		if err != nil {
			return "", isPtr, newParseError(sf, err)
		}

		return val, isPtr, nil
	}

	formatFunc, ok = defaultBuiltInFormaters[typee.Kind()]
	if ok {
		val, err := formatFunc(field)
		if err != nil {
			return "", isPtr, newParseError(sf, err)
		}

		return val, isPtr, nil
	}

	switch field.Kind() {
	case reflect.Slice:
		if typee.Elem().Kind() == reflect.Ptr {
			isPtr = true
		}

		v, e := sliceToString(field, sf, funcMap)

		return v, isPtr, e
	case reflect.Map:
		if typee.Elem().Kind() == reflect.Ptr {
			isPtr = true
		}

		v, e := mapToString(field, sf, funcMap)

		return v, isPtr, e
	}

	return fmt.Sprintf("can't makeEnv %s (%+v)", typee, field), isPtr, nil
}

func set(field reflect.Value, sf reflect.StructField, value string, funcMap map[reflect.Type]ParserFunc) error {
	if tm := asTextUnmarshaler(field); tm != nil {
		if err := tm.UnmarshalText([]byte(value)); err != nil {
			return newParseError(sf, err)
		}
		return nil
	}

	typee := sf.Type
	fieldee := field
	if typee.Kind() == reflect.Ptr {
		typee = typee.Elem()
		fieldee = field.Elem()
	}

	parserFunc, ok := funcMap[typee]
	if ok {
		val, err := parserFunc(value)
		if err != nil {
			return newParseError(sf, err)
		}

		fieldee.Set(reflect.ValueOf(val))
		return nil
	}

	parserFunc, ok = defaultBuiltInParsers[typee.Kind()]
	if ok {
		val, err := parserFunc(value)
		if err != nil {
			return newParseError(sf, err)
		}

		fieldee.Set(reflect.ValueOf(val).Convert(typee))
		return nil
	}

	switch field.Kind() {
	case reflect.Slice:
		return handleSlice(field, value, sf, funcMap)
	case reflect.Map:
		return handleMap(field, value, sf, funcMap)
	}

	return newNoParserError(sf)
}

func getFieldSeparator(sf reflect.StructField) string {
	separator := sf.Tag.Get("envSeparator")
	if separator == "" {
		separator = ","
	}

	return separator
}

func sliceToString(field reflect.Value, sf reflect.StructField, funcMap map[reflect.Type]FormatFunc) (string, error) {
	envStrs := []string{}

	for i := 0; i < field.Len(); i++ {
		newStr, _, err := makeEnv(field.Index(i), sf, field.Index(i).Type(), funcMap)
		if err != nil {
			return "", fmt.Errorf("can't process slice %w", err)
		}

		envStrs = append(envStrs, newStr)
	}

	separator := getFieldSeparator(sf)

	return strings.Join(envStrs, separator), nil
}

func handleSlice(field reflect.Value, value string, sf reflect.StructField, funcMap map[reflect.Type]ParserFunc) error {
	separator := getFieldSeparator(sf)
	parts := strings.Split(value, separator)

	typee := sf.Type.Elem()
	if typee.Kind() == reflect.Ptr {
		typee = typee.Elem()
	}

	if _, ok := reflect.New(typee).Interface().(encoding.TextUnmarshaler); ok {
		return parseTextUnmarshalers(field, parts, sf)
	}

	parserFunc, ok := funcMap[typee]
	if !ok {
		parserFunc, ok = defaultBuiltInParsers[typee.Kind()]
		if !ok {
			return newNoParserError(sf)
		}
	}

	result := reflect.MakeSlice(sf.Type, 0, len(parts))
	for _, part := range parts {
		r, err := parserFunc(part)
		if err != nil {
			return newParseError(sf, err)
		}
		v := reflect.ValueOf(r).Convert(typee)
		if sf.Type.Elem().Kind() == reflect.Ptr {
			v = reflect.New(typee)
			v.Elem().Set(reflect.ValueOf(r).Convert(typee))
		}
		result = reflect.Append(result, v)
	}
	field.Set(result)
	return nil
}

func mapToString(field reflect.Value, sf reflect.StructField, funcMap map[reflect.Type]FormatFunc) (string, error) {
	envStrs := []string{}

	for _, k := range field.MapKeys() {
		newStrKey, _, err := makeEnv(k, sf, k.Type(), funcMap)
		if err != nil {
			return "", err
		}

		newStrVal, _, err := makeEnv(field.MapIndex(k), sf, field.MapIndex(k).Type(), funcMap)
		if err != nil {
			return "", err
		}

		envStrs = append(envStrs, newStrKey+":"+newStrVal)
	}

	separator := getFieldSeparator(sf)

	return strings.Join(envStrs, separator), nil
}

func handleMap(field reflect.Value, value string, sf reflect.StructField, funcMap map[reflect.Type]ParserFunc) error {
	keyType := sf.Type.Key()
	keyParserFunc, ok := funcMap[keyType]
	if !ok {
		keyParserFunc, ok = defaultBuiltInParsers[keyType.Kind()]
		if !ok {
			return newNoParserError(sf)
		}
	}

	elemType := sf.Type.Elem()
	elemParserFunc, ok := funcMap[elemType]
	if !ok {
		elemParserFunc, ok = defaultBuiltInParsers[elemType.Kind()]
		if !ok {
			return newNoParserError(sf)
		}
	}

	separator := getFieldSeparator(sf)

	result := reflect.MakeMap(sf.Type)
	for _, part := range strings.Split(value, separator) {
		pairs := strings.Split(part, ":")
		if len(pairs) != 2 {
			return newParseError(sf, fmt.Errorf(`%q should be in "key:value" format`, part))
		}

		key, err := keyParserFunc(pairs[0])
		if err != nil {
			return newParseError(sf, err)
		}

		elem, err := elemParserFunc(pairs[1])
		if err != nil {
			return newParseError(sf, err)
		}

		result.SetMapIndex(reflect.ValueOf(key).Convert(keyType), reflect.ValueOf(elem).Convert(elemType))
	}

	field.Set(result)
	return nil
}

func asTextUnmarshaler(field reflect.Value) encoding.TextUnmarshaler {
	if reflect.Ptr == field.Kind() {
		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}
	} else if field.CanAddr() {
		field = field.Addr()
	}

	tm, ok := field.Interface().(encoding.TextUnmarshaler)
	if !ok {
		return nil
	}
	return tm
}

func asTextMarshaler(field reflect.Value) encoding.TextMarshaler {
	if reflect.Ptr == field.Kind() {
		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}
	} else if field.CanAddr() {
		field = field.Addr()
	}

	tm, ok := field.Interface().(encoding.TextMarshaler)
	if !ok {
		return nil
	}
	return tm
}

func parseTextUnmarshalers(field reflect.Value, data []string, sf reflect.StructField) error {
	s := len(data)
	elemType := field.Type().Elem()
	slice := reflect.MakeSlice(reflect.SliceOf(elemType), s, s)
	for i, v := range data {
		sv := slice.Index(i)
		kind := sv.Kind()
		if kind == reflect.Ptr {
			sv = reflect.New(elemType.Elem())
		} else {
			sv = sv.Addr()
		}
		tm := sv.Interface().(encoding.TextUnmarshaler)
		if err := tm.UnmarshalText([]byte(v)); err != nil {
			return newParseError(sf, err)
		}
		if kind == reflect.Ptr {
			slice.Index(i).Set(sv)
		}
	}

	field.Set(slice)

	return nil
}
