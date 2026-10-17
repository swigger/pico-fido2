package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/rclone/rclone/fs/config/obscure"
)

// This separate child never opens a credential vault or selects a backend.
// Plain WebDAV passwords cross only private inherited pipes and are immediately
// converted to the upstream representation inside the protected profile.
type ProfileSetup struct {
	Profile        CloudProfile `json:"profile"`
	WebDAVPassword string       `json:"webdav_password,omitempty"`
}

func SaveProfileSetup(ctx context.Context, path, namespace string, data []byte) error {
	if len(data) == 0 || len(data) > profileLimit {
		return errors.New("invalid profile setup size")
	}
	var request ProfileSetup
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return errors.New("invalid profile setup")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || request.Profile.Namespace != namespace || !namespacePattern.MatchString(namespace) || request.Profile.Version != 1 {
		return errors.New("profile setup identity mismatch")
	}
	p := request.Profile
	if err := ctx.Err(); err != nil {
		return err
	}
	if request.WebDAVPassword != "" {
		if p.Provider.Provider != "webdav" || p.Provider.Options["pass"] != "" || p.Provider.Options["bearer_token"] != "" || len(request.WebDAVPassword) > 4096 {
			return errors.New("invalid profile authentication")
		}
		pass, err := obscure.Obscure(request.WebDAVPassword)
		if err != nil {
			return errors.New("cannot protect provider password")
		}
		if p.Provider.Options == nil {
			p.Provider.Options = make(map[string]string)
		}
		p.Provider.Options["pass"] = pass
	}
	if err := ValidateProviderConfig(p.Provider); err != nil {
		return err
	}
	if err := pinCoordinator(ctx, &p); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return CreateProfile(path, p)
}

func pinCoordinator(ctx context.Context, p *CloudProfile) error {
	if p.Coordinator.ClusterID == "" {
		id, err := InspectCoordinator(ctx, p.Coordinator)
		if err != nil {
			return err
		}
		p.Coordinator.ClusterID = id
	} else {
		client, err := OpenCoordinator(ctx, p.Coordinator)
		if err != nil {
			return err
		}
		client.Close()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func ServeProfileSetup(parent context.Context, input io.Reader, output io.Writer, path, namespace string) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	frames := make(chan pipeFrame)
	go func() {
		frame, err := readFrameLimit(input, 1, profileLimit)
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
		var extra [1]byte
		_, _ = input.Read(extra[:])
		cancel() // EOF or unexpected further input cancels setup.
	}()
	var frame pipeFrame
	select {
	case frame = <-frames:
	case <-ctx.Done():
		return errors.New("profile setup canceled")
	}
	defer clear(frame.data)
	var err error
	if frame.op != PipeProfile || len(frame.data) > profileLimit {
		err = errors.New("invalid profile setup command")
	} else {
		err = SaveProfileSetup(ctx, path, namespace, frame.data)
	}
	if err != nil {
		_ = sendFrame(output, frame, true, nil)
		return errors.New("profile validation or save failed")
	}
	return sendFrame(output, frame, false, nil)
}
