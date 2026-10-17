package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/lib/oauthutil"
	"golang.org/x/oauth2"
)

const (
	enrollDone byte = iota
	enrollBrowser
	enrollWaiting
	enrollQuestion
	enrollReview
)

type enrollmentMap struct {
	mu               sync.Mutex
	values, defaults map[string]string
	provider         string
	faulted          bool
}

func (m *enrollmentMap) Get(key string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.values[key]
	if !ok {
		value, ok = m.defaults[key]
	}
	return value, ok
}
func (m *enrollmentMap) Set(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !slices.Contains(strings.Fields(optionAllow[m.provider]), key) || len(value) > 16384 || strings.ContainsRune(value, 0) {
		m.faulted = true
		return
	}
	m.values[key] = value
}
func (m *enrollmentMap) snapshot() (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.faulted {
		return nil, errEnrollment
	}
	return maps.Clone(m.values), nil
}

var _ configmap.Mapper = (*enrollmentMap)(nil)

type enrollment struct {
	ctx              context.Context
	cancel           context.CancelFunc
	path             string
	profile          CloudProfile
	mapper           *enrollmentMap
	configure        func(context.Context, string, configmap.Mapper, fs.ConfigIn) (*fs.ConfigOut, error)
	startGrant       func(context.Context, *oauth2.Config) (*browserGrant, error)
	state            string
	question         *fs.Option
	grant            *browserGrant
	review, finished bool
	reviewText       string
	validateResult   func(CloudProfile) error
	save             func(context.Context, CloudProfile) error
	onClose          func()
}

func validateEnrollment(p CloudProfile) error {
	if p.Version != 1 || !namespacePattern.MatchString(p.Namespace) || p.Namespace == strings.Repeat("0", 32) ||
		(p.Provider.Provider != "drive" && p.Provider.Provider != "onedrive") || p.Provider.CACertFile != "" {
		return errEnrollment
	}
	allowed := "client_id client_secret"
	if p.Provider.Provider == "drive" {
		allowed += " scope"
		if p.Provider.Options["client_id"] == "" || p.Provider.Options["client_secret"] == "" ||
			(p.Provider.Options["scope"] != "drive.file" && p.Provider.Options["scope"] != "drive") {
			return errEnrollment
		}
	} else {
		allowed += " region"
	}
	for key := range p.Provider.Options {
		if !slices.Contains(strings.Fields(allowed), key) {
			return errEnrollment
		}
	}
	if p.Provider.Options["client_secret"] != "" && p.Provider.Options["client_id"] == "" {
		return errEnrollment
	}
	test := p.Provider
	test.Options = maps.Clone(test.Options)
	if test.Options == nil {
		test.Options = make(map[string]string)
	}
	test.Options["token"] = "pending OAuth"
	if test.Provider == "onedrive" {
		test.Options["drive_id"], test.Options["drive_type"] = "pending", "personal"
	}
	return ValidateProviderConfig(test)
}

func beginEnrollment(ctx context.Context, path, namespace string, data []byte) (*enrollment, []byte, error) {
	var request ProfileSetup
	if len(data) == 0 || len(data) > profileLimit {
		return nil, nil, errEnrollment
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return nil, nil, errEnrollment
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || request.WebDAVPassword != "" || request.Profile.Namespace != namespace {
		return nil, nil, errEnrollment
	}
	p := request.Profile
	if err := validateEnrollment(p); err != nil {
		return nil, nil, errEnrollment
	}
	// An interrupted earlier creation (exact marker, no profile) stays recoverable.
	if err := profileCreatable(path, namespace); err != nil {
		return nil, nil, errEnrollment
	}
	if err := pinCoordinator(ctx, &p); err != nil {
		return nil, nil, errEnrollment
	}
	e, err := newEnrollment(ctx, path, p)
	if err != nil {
		return nil, nil, err
	}
	reply, err := e.advance("")
	if err != nil {
		e.close()
		return nil, nil, errEnrollment
	}
	return e, reply, nil
}

func newEnrollment(parent context.Context, path string, p CloudProfile) (*enrollment, error) {
	life, cancel := context.WithTimeout(parent, 10*time.Minute)
	ctx, ci := fs.AddConfig(life)
	ci.InsecureSkipVerify, ci.Dump, ci.NoConsole = false, 0, true
	ci.ConnectTimeout, ci.Timeout = fs.Duration(5*time.Second), fs.Duration(20*time.Second)
	ci.LowLevelRetries, ci.Retries, ci.Checkers, ci.Transfers = 1, 1, 1, 1
	ci.PasswordCommand, ci.Headers, ci.UploadHeaders, ci.DownloadHeaders = nil, nil, nil, nil
	ci.ClientCert, ci.ClientKey, ci.ClientPass, ci.HTTPProxy = "", "", "", ""
	ci.CaCert = nil
	registry, err := fs.Find(p.Provider.Provider)
	if err != nil || (registry.Config == nil && p.Provider.Provider != "webdav") {
		cancel()
		return nil, errEnrollment
	}
	mapper := &enrollmentMap{values: maps.Clone(p.Provider.Options), defaults: make(map[string]string), provider: p.Provider.Provider}
	if mapper.values == nil {
		mapper.values = make(map[string]string)
	}
	for _, option := range registry.Options {
		mapper.defaults[option.Name] = option.String()
	}
	return &enrollment{ctx: ctx, cancel: cancel, path: path, profile: p, mapper: mapper, configure: registry.Config,
		startGrant: func(ctx context.Context, config *oauth2.Config) (*browserGrant, error) {
			return beginBrowserGrant(ctx, config, oauthHTTPClient(ctx))
		}}, nil
}

func appendEnrollmentString(data []byte, value string) ([]byte, error) {
	if !utf8.ValidString(value) || len(value) > 8192 || strings.ContainsRune(value, 0) || len(data)+4+len(value) > profileLimit {
		return nil, errEnrollment
	}
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(value)))
	data = append(data, length[:]...)
	return append(data, value...), nil
}
func encodeEnrollmentQuestion(kind byte, option *fs.Option) ([]byte, error) {
	if option == nil || len(option.Examples) > 128 {
		return nil, errEnrollment
	}
	result := []byte{kind}
	var err error
	for _, value := range []string{option.Name, option.Help, option.String()} {
		result, err = appendEnrollmentString(result, value)
		if err != nil {
			return nil, err
		}
	}
	flags := byte(0)
	if option.Required {
		flags |= 1
	}
	if option.Exclusive {
		flags |= 2
	}
	if option.IsPassword {
		flags |= 4
	}
	result = append(result, flags, byte(len(option.Examples)), byte(len(option.Examples)>>8))
	for _, example := range option.Examples {
		for _, value := range []string{example.Value, example.Help} {
			result, err = appendEnrollmentString(result, value)
			if err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

func (e *enrollment) advance(answer string) ([]byte, error) {
	if e.ctx.Err() != nil || e.finished || e.grant != nil || !utf8.ValidString(answer) || len(answer) > 8192 || strings.ContainsRune(answer, 0) {
		return nil, errEnrollment
	}
	if e.review {
		if answer != "save" {
			return nil, errEnrollment
		}
		options, err := e.mapper.snapshot()
		if err != nil {
			return nil, err
		}
		e.profile.Provider.Options = options
		if err := e.ctx.Err(); err != nil {
			return nil, errEnrollment
		}
		var saveErr error
		if e.save != nil {
			saveErr = e.save(e.ctx, e.profile)
		} else {
			saveErr = CreateProfile(e.path, e.profile)
		}
		if saveErr != nil {
			return nil, errEnrollment
		}
		e.finished = true
		return []byte{enrollDone}, nil
	}
	if e.question != nil {
		if e.question.Required && answer == "" {
			return nil, errEnrollment
		}
		if e.question.Exclusive {
			match := false
			for _, example := range e.question.Examples {
				if example.Value == answer {
					match = true
					break
				}
			}
			if !match {
				return nil, errEnrollment
			}
		}
		e.question = nil
	} else if answer != "" {
		return nil, errEnrollment
	}
	in := fs.ConfigIn{State: e.state, Result: answer}
	for step := 0; step < 32; step++ {
		out, err := e.configure(e.ctx, "pico-fido2-enrollment", e.mapper, in)
		if err != nil || (out != nil && out.Error != "") {
			return nil, errEnrollment
		}
		if _, err := e.mapper.snapshot(); err != nil {
			return nil, err
		}
		if out == nil {
			options, err := e.mapper.snapshot()
			if err != nil {
				return nil, err
			}
			e.profile.Provider.Options = options
			if e.profile.validate() != nil {
				return nil, errEnrollment
			}
			if e.validateResult != nil && e.validateResult(e.profile) != nil {
				return nil, errEnrollment
			}
			help := e.reviewText
			if help == "" {
				help = "保存云授权配置？\n服务：" + e.profile.Provider.Provider + "\n目录：" + e.profile.Provider.Root + "\n凭证库编号：" + e.profile.Namespace + "\n保存后再建立、连接或迁移凭证库。"
			}
			e.review = true
			return encodeEnrollmentQuestion(enrollReview, &fs.Option{Name: "save_profile", Required: true, Exclusive: true, Default: "cancel",
				Help:     help,
				Examples: fs.OptionExamples{{Value: "cancel", Help: "取消"}, {Value: "save", Help: "保存此配置"}}})
		}
		e.state = out.State
		if out.OAuth != nil {
			options, ok := out.OAuth.(*oauthutil.Options)
			if !ok {
				return nil, errEnrollment
			}
			config, err := providerOAuthConfig(e.profile.Provider.Provider, e.mapper, options)
			if err != nil {
				return nil, err
			}
			e.grant, err = e.startGrant(e.ctx, config)
			if err != nil {
				return nil, err
			}
			return appendEnrollmentString([]byte{enrollBrowser}, e.grant.URL)
		}
		if out.Option != nil {
			e.question = out.Option.Copy()
			return encodeEnrollmentQuestion(enrollQuestion, e.question)
		}
		in = fs.ConfigIn{State: out.State, Result: out.Result}
	}
	return nil, errEnrollment
}
func (e *enrollment) poll() ([]byte, error) {
	if e.ctx.Err() != nil || e.grant == nil || e.finished {
		return nil, errEnrollment
	}
	select {
	case result := <-e.grant.result:
		e.grant.close()
		e.grant = nil
		if result.err != nil || result.token == nil {
			return nil, errEnrollment
		}
		if err := oauthutil.PutToken("pico-fido2-enrollment", e.mapper, result.token, true); err != nil {
			return nil, errEnrollment
		}
		return e.advance("")
	default:
		return []byte{enrollWaiting}, nil
	}
}
func (e *enrollment) close() {
	if e != nil {
		e.cancel()
		e.grant.close()
		e.profile = CloudProfile{}
		if e.onClose != nil {
			e.onClose()
			e.onClose = nil
		}
	}
}

func ServeEnrollment(parent context.Context, input io.Reader, output io.Writer, path, namespace string) error {
	return serveEnrollment(parent, input, output, path, namespace, PipeEnrollStart, beginEnrollment)
}
func serveEnrollment(parent context.Context, input io.Reader, output io.Writer, path, namespace string, startOperation byte,
	begin func(context.Context, string, string, []byte) (*enrollment, []byte, error)) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	frames := make(chan pipeFrame)
	go func() {
		for sequence := uint64(1); ; sequence++ {
			frame, err := readFrameLimit(input, sequence, profileLimit)
			if err != nil {
				cancel()
				return
			}
			select {
			case frames <- frame:
			case <-ctx.Done():
				clear(frame.data)
				return
			}
		}
	}()
	var session *enrollment
	defer func() { session.close() }()
	for {
		var frame pipeFrame
		select {
		case frame = <-frames:
		case <-ctx.Done():
			return errEnrollment
		}
		var reply []byte
		var err error
		switch {
		case frame.op == startOperation && session == nil:
			session, reply, err = begin(ctx, path, namespace, frame.data)
		case frame.op == PipeEnrollAnswer && session != nil:
			reply, err = session.advance(string(frame.data))
		case frame.op == PipeEnrollPoll && len(frame.data) == 0 && session != nil:
			reply, err = session.poll()
		case frame.op == PipeClose && len(frame.data) == 0:
			session.close()
			clear(frame.data)
			return sendFrame(output, frame, false, nil)
		default:
			err = errEnrollment
		}
		clear(frame.data)
		if err != nil {
			_ = sendFrame(output, frame, true, nil)
			return errEnrollment
		}
		if err := sendFrame(output, frame, false, reply); err != nil {
			return errEnrollment
		}
		if session != nil && session.finished {
			return nil
		}
	}
}
