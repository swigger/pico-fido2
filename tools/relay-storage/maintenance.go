package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
)

// ProfileMaintenance is a patch, never a replacement profile. Location, namespace,
// cloud-drive identity and enrolled coordinator cluster cannot be supplied here.
type ProfileMaintenance struct {
	Action       string             `json:"action"`
	Secret       *string            `json:"secret,omitempty"`
	ClientID     *string            `json:"client_id,omitempty"`
	ClientSecret *string            `json:"client_secret,omitempty"`
	ProviderCA   *string            `json:"provider_ca_file,omitempty"`
	Coordinator  *CoordinatorConfig `json:"coordinator,omitempty"`
}

func sameCloudBinding(old, next CloudProfile) bool {
	if old.Version != next.Version || old.Namespace != next.Namespace || old.Coordinator.ClusterID != next.Coordinator.ClusterID ||
		old.Provider.Provider != next.Provider.Provider || old.Provider.Root != next.Provider.Root {
		return false
	}
	mutable := func(key string) bool {
		return key == "token" || key == "client_id" || key == "client_secret" || key == "pass" || key == "bearer_token"
	}
	for key, value := range old.Provider.Options {
		if !mutable(key) && next.Provider.Options[key] != value {
			return false
		}
	}
	for key, value := range next.Provider.Options {
		if !mutable(key) && old.Provider.Options[key] != value {
			return false
		}
	}
	return true
}

func maintenancePatch(old CloudProfile, request ProfileMaintenance) (CloudProfile, error) {
	next := old
	next.Provider.Options = maps.Clone(old.Provider.Options)
	for _, value := range []*string{request.Secret, request.ClientID, request.ClientSecret, request.ProviderCA} {
		if value != nil && (len(*value) > 4096 || !utf8.ValidString(*value) || strings.ContainsRune(*value, 0)) {
			return CloudProfile{}, errEnrollment
		}
	}
	switch request.Action {
	case "oauth":
		if (old.Provider.Provider != "drive" && old.Provider.Provider != "onedrive") || request.Secret != nil || request.ProviderCA != nil {
			return CloudProfile{}, errEnrollment
		}
		if request.ClientID != nil {
			if *request.ClientID == "" {
				return CloudProfile{}, errEnrollment
			}
			if *request.ClientID != old.Provider.Options["client_id"] {
				next.Provider.Options["client_secret"] = "" // Never pair a new app with the former app's secret.
			}
			next.Provider.Options["client_id"] = *request.ClientID
		}
		if request.ClientSecret != nil {
			next.Provider.Options["client_secret"] = *request.ClientSecret
		}
		if old.Provider.Provider == "drive" && (next.Provider.Options["client_id"] == "" || next.Provider.Options["client_secret"] == "") {
			return CloudProfile{}, errEnrollment
		}
		if old.Provider.Provider == "onedrive" && next.Provider.Options["client_secret"] != "" && next.Provider.Options["client_id"] == "" {
			return CloudProfile{}, errEnrollment
		}
	case "webdav":
		if old.Provider.Provider != "webdav" || request.Secret == nil || *request.Secret == "" || request.ClientID != nil || request.ClientSecret != nil {
			return CloudProfile{}, errEnrollment
		}
		if old.Provider.Options["bearer_token"] != "" {
			next.Provider.Options["bearer_token"] = *request.Secret
		} else {
			encoded, err := obscure.Obscure(*request.Secret)
			if err != nil {
				return CloudProfile{}, errEnrollment
			}
			next.Provider.Options["pass"] = encoded
		}
		if request.ProviderCA != nil {
			next.Provider.CACertFile = *request.ProviderCA
		}
	case "coordinator":
		if request.Coordinator == nil || request.Secret != nil || request.ClientID != nil || request.ClientSecret != nil || request.ProviderCA != nil {
			return CloudProfile{}, errEnrollment
		}
	default:
		return CloudProfile{}, errEnrollment
	}
	if request.Coordinator != nil {
		if request.Coordinator.ClusterID != "" && request.Coordinator.ClusterID != old.Coordinator.ClusterID {
			return CloudProfile{}, errEnrollment
		}
		next.Coordinator = *request.Coordinator
		next.Coordinator.ClusterID = old.Coordinator.ClusterID
	}
	if !sameCloudBinding(old, next) || next.validate() != nil {
		return CloudProfile{}, errEnrollment
	}
	return next, nil
}

func beginMaintenance(ctx context.Context, path, namespace string, data []byte) (*enrollment, []byte, error) {
	if len(data) == 0 || len(data) > profileLimit {
		return nil, nil, errEnrollment
	}
	var request ProfileMaintenance
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil {
		return nil, nil, errEnrollment
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, nil, errEnrollment
	}
	protected, err := openProfileForMaintenance(path, namespace, true)
	if err != nil {
		return nil, nil, errEnrollment
	}
	retained := false
	defer func() {
		if !retained {
			protected.Close()
		}
	}()
	old, err := protected.Config()
	if err != nil {
		return nil, nil, errEnrollment
	}
	next, err := maintenancePatch(old, request)
	if err != nil || pinCoordinator(ctx, &next) != nil {
		return nil, nil, errEnrollment
	}
	e, err := newEnrollment(ctx, path, next)
	if err != nil {
		return nil, nil, errEnrollment
	}
	e.onClose = protected.Close
	e.validateResult = func(candidate CloudProfile) error {
		if !sameCloudBinding(old, candidate) {
			return errEnrollment
		}
		return nil
	}
	e.save = func(ctx context.Context, candidate CloudProfile) error {
		return verifyAndUpdateProfile(ctx, protected, candidate)
	}
	actionName := map[string]string{"oauth": "重新登录云盘", "webdav": "更新 WebDAV 凭据", "coordinator": "更新协调服务器连接与证书"}[request.Action]
	e.reviewText = "更新现有云配置？\n操作：" + actionName + "\n服务：" + old.Provider.Provider + "\n目录：" + old.Provider.Root +
		"\n凭证库编号：" + old.Namespace + "\n协调集群：" + old.Coordinator.ClusterID +
		"\n协调地址：" + strings.Join(next.Coordinator.Endpoints, ", ") +
		"\n保存前将独占检查现有库及已发布的加密快照。更新不会移动、初始化或选择凭证库。"
	if request.Action == "oauth" {
		// Force a fresh browser grant while retaining the fixed drive/root options.
		delete(e.mapper.values, "token")
	} else {
		e.configure = func(context.Context, string, configmap.Mapper, fs.ConfigIn) (*fs.ConfigOut, error) { return nil, nil }
	}
	reply, err := e.advance("")
	if err != nil {
		e.close()
		return nil, nil, errEnrollment
	}
	retained = true
	return e, reply, nil
}

// Only reads are possible through this late-bound adapter. Provider construction
// (which may itself discover the remote root) happens after distributed locking.
type maintenanceObjects struct{ remote *RcloneObjects }

func (*maintenanceObjects) PutNew(context.Context, string, []byte) error { return errEnrollment }
func (o *maintenanceObjects) Get(ctx context.Context, name string) ([]byte, error) {
	if o.remote == nil {
		return nil, errEnrollment
	}
	return o.remote.Get(ctx, name)
}

func verifyAndUpdateProfile(ctx context.Context, profile *Profile, next CloudProfile) error {
	old, err := profile.Config()
	if err != nil || !sameCloudBinding(old, next) || next.validate() != nil {
		return errEnrollment
	}
	client, err := OpenCoordinator(ctx, next.Coordinator)
	if err != nil {
		return errEnrollment
	}
	defer client.Close()
	objects := &maintenanceObjects{}
	locked, err := acquireForMaintenance(ctx, client, objects, next.Namespace)
	if err != nil {
		return errEnrollment
	}
	defer locked.Close()
	var mutex sync.Mutex
	options := maps.Clone(next.Provider.Options)
	remote, err := NewRcloneObjects(ctx, next.Provider, next.Namespace, func(updated map[string]string) error {
		mutex.Lock()
		defer mutex.Unlock()
		// Stage refreshes in memory. Failed verification must not alter the old profile.
		if len(updated) != len(options) {
			return errEnrollment
		}
		for key, value := range options {
			if key != "token" && updated[key] != value {
				return errEnrollment
			}
		}
		options = maps.Clone(updated)
		return nil
	})
	if err != nil {
		return errEnrollment
	}
	defer remote.Close()
	objects.remote = remote
	if locked.revision != 0 {
		data, _, err := locked.Read(ctx)
		clear(data) // Opaque ciphertext; no vault password or private key is available here.
		if err != nil {
			return errEnrollment
		}
	}
	remote.Close()
	mutex.Lock()
	next.Provider.Options = maps.Clone(options)
	mutex.Unlock()
	profile.mu.Lock()
	defer profile.mu.Unlock()
	if profile.faulted || !sameCloudBinding(profile.value, next) {
		return errEnrollment
	}
	if err := profile.replaceLocked(next, func() error { return locked.Check(ctx) }); err != nil {
		return errEnrollment
	}
	if err := locked.Close(); err != nil {
		return errors.Join(errEnrollment, err)
	}
	return nil
}

func ServeMaintenance(parent context.Context, input io.Reader, output io.Writer, path, namespace string) error {
	return serveEnrollment(parent, input, output, path, namespace, PipeMaintain, beginMaintenance)
}
