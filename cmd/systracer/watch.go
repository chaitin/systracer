package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/aegistudio/shaft"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/chaitin/systracer/rcnotify"
)

var (
	watches []string
)

func initWatchModule() shaft.Option {
	if len(watches) == 0 {
		return shaft.Module()
	}
	return shaft.Module(
		rcnotify.Module,
		shaft.Provide(func(
			ctx context.Context, group *errgroup.Group,
			logger *zap.SugaredLogger, manager *rcnotify.Manager,
		) ([]moduleBarrier, error) {
			// Attempt to parse the watch argumets.
			var options []rcnotify.Option
			for _, watch := range watches {
				pathIndex := strings.Index(watch, "=")
				if pathIndex <= 0 {
					return nil, errors.New(
						`"watch must be of format "<events>=<path>"`)
				}
				events := watch[:pathIndex]
				path := watch[pathIndex+1:]
				var matcher func(rcnotify.Op, string) rcnotify.Option
				matcher = rcnotify.WatchDir
				var flags rcnotify.Op
				for _, event := range strings.Split(events, ",") {
					switch event {
					case "all":
						flags |= rcnotify.OpAll
					case "create":
						flags |= rcnotify.OpCreate
					case "mknod":
						flags |= rcnotify.OpMknod
					case "mkdir":
						flags |= rcnotify.OpMkdir
					case "delete":
						flags |= rcnotify.OpDelete
					case "rmdir":
						flags |= rcnotify.OpRmdir
					case "rename":
						flags |= rcnotify.OpRename
					case "attrib":
						flags |= rcnotify.OpAttrib
					case "link":
						flags |= rcnotify.OpLink
					case "symlink":
						flags |= rcnotify.OpSymlink
					case "dir":
						matcher = rcnotify.WatchDir
					case "file":
						matcher = rcnotify.WatchFile
					default:
						return nil, errors.Errorf(
							"unknown event %q", event)
					}
				}
				options = append(options, matcher(flags, path))
			}
			watcher, err := manager.Watch(options...)
			if err != nil {
				return nil, err
			}
			group.Go(func() error {
				defer watcher.Close()
				for {
					var event rcnotify.Event
					select {
					case <-ctx.Done():
						return nil
					case event = <-watcher.C:
					}
					eventContext := fmt.Sprintf("%s %d",
						event.Timestamp.Format("2006-01-02T15:04:05.999999999"), event.PID)
					sourcePath := "(unknown)"
					if event.Source != nil {
						sourcePath = fmt.Sprintf("%q", *event.Source)
					}
					targetPath := "(unknown)"
					if event.Target != nil {
						targetPath = fmt.Sprintf("%q", *event.Target)
					}
					var fileMode os.FileMode
					if event.Mode != nil {
						fileMode = os.FileMode(*event.Mode & 0777)
						switch *event.Mode & syscall.S_IFMT {
						case syscall.S_IFBLK:
							fileMode |= os.ModeDevice
						case syscall.S_IFCHR:
							fileMode |= os.ModeDevice | os.ModeCharDevice
						case syscall.S_IFDIR:
							fileMode |= os.ModeDir
						case syscall.S_IFIFO:
							fileMode |= os.ModeNamedPipe
						case syscall.S_IFLNK:
							fileMode |= os.ModeSymlink
						case syscall.S_IFREG:
							// nothing to do
						case syscall.S_IFSOCK:
							fileMode |= os.ModeSocket
						}
						if (*event.Mode & syscall.S_ISGID) != 0 {
							fileMode |= os.ModeSetgid
						}
						if (*event.Mode & syscall.S_ISUID) != 0 {
							fileMode |= os.ModeSetuid
						}
						if (*event.Mode & syscall.S_ISVTX) != 0 {
							fileMode |= os.ModeSticky
						}
					}
					switch event.Op {
					case rcnotify.OpCreate:
						logger.Infof("%s - create(%s, %q)",
							eventContext, targetPath, fileMode)
					case rcnotify.OpMkdir:
						logger.Infof("%s - mkdir(%s, %q)",
							eventContext, targetPath, fileMode)
					case rcnotify.OpMknod:
						logger.Infof("%s - mknod(%s, %q, %d)",
							eventContext, targetPath,
							fileMode, *event.Dev)
					case rcnotify.OpDelete:
						logger.Infof("%s - delete(%s)",
							eventContext, targetPath)
					case rcnotify.OpRmdir:
						logger.Infof("%s - rmdir(%s)",
							eventContext, targetPath)
					case rcnotify.OpRename:
						logger.Infof("%s - rename(%s, %s)",
							eventContext, sourcePath, targetPath)
					case rcnotify.OpAttrib:
						if event.Attr&rcnotify.AttrMode != 0 {
							logger.Infof("%s - chmod(%s, %q)",
								eventContext, targetPath, fileMode)
						}
						if event.Attr&rcnotify.AttrUID != 0 {
							logger.Infof("%s - chown_uid(%s, %d)",
								eventContext, targetPath, *event.Uid)
						}
						if event.Attr&rcnotify.AttrGID != 0 {
							logger.Infof("%s - chown_gid(%s, %d)",
								eventContext, targetPath, *event.Gid)
						}
					case rcnotify.OpLink:
						logger.Infof("%s - link(%s, %s)",
							eventContext, sourcePath, targetPath)
					case rcnotify.OpSymlink:
						logger.Infof("%s - symlink(%s, %s)",
							eventContext, sourcePath, targetPath)
					}
				}
				return nil
			})
			return nil, nil
		}),
	)
}

func init() {
	moduleInits = append(moduleInits, initWatchModule)
	rootCmd.PersistentFlags().StringArrayVarP(
		&watches, "watch", "w", watches,
		"specify list of watches for directory events")
}
