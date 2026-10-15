// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/juju/loggo/v2"

	"github.com/hemilabs/heminetwork/v2/config"
	"github.com/hemilabs/heminetwork/v2/version"
)

const (
	daemonName      = "hemictl"
	defaultLogLevel = daemonName + "=INFO;protocol=INFO"

	tbcReadLimit = 16 * (1 << 20) // 16 MiB.
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome string

	logLevel    string
	leveldbHome string
	network     string
	cm          = config.CfgMap{
		"HEMICTL_LEVELDB_HOME": config.Config{
			Value:        &leveldbHome,
			DefaultValue: "~/.tbcd",
			Help:         "leveldb home directory",
			Print:        config.PrintAll,
		},
		"HEMICTL_LOG_LEVEL": config.Config{
			Value:        &logLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for various packages; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
		"HEMICTL_NETWORK": config.Config{
			Value:        &network,
			DefaultValue: "mainnet",
			Help:         "hemictl network",
			Print:        config.PrintAll,
		},
	}

	callTimeout = 100 * time.Second
)

// argument describes a single named argument for a command.
// Arguments with the same (non-zero) order value are mutually exclusive.
type argument struct {
	required     bool
	order        int
	defaultValue string
	help         string
}

// command is a single executable action within a commandGroup.
type command struct {
	help string
	args map[string]argument
	run  func(context.Context, map[string]string) error
}

// commandGroup is a named set of related commands.
type commandGroup struct {
	help     string
	commands map[string]command
}

type topLevelCommand struct {
	help    string
	handler func(context.Context, []string) error
}

var registeredCommands = map[string]topLevelCommand{}

// registerCommand adds a top-level command to the registry.
// Call this from each handler file's init().
func registerCommand(name, help string, handler func(context.Context, []string) error) {
	registeredCommands[name] = topLevelCommand{help: help, handler: handler}
}

// parseArgs splits args into an action name and a key=value map.
func parseArgs(args []string) (string, map[string]string, error) {
	if len(args) < 1 {
		flag.Usage()
		return "", nil, errors.New("action required")
	}

	action := args[0]
	parsed := make(map[string]string, 10)

	for _, v := range args[1:] {
		s := strings.Split(v, "=")
		if len(s) != 2 {
			return "", nil, fmt.Errorf("invalid argument: %v", v)
		}
		if len(s[0]) == 0 || len(s[1]) == 0 {
			return "", nil, fmt.Errorf("expected a=b, got %v", v)
		}
		parsed[s[0]] = s[1]
	}

	return action, parsed, nil
}

func applyDefaults(spec map[string]argument, provided map[string]string) map[string]string {
	effective := make(map[string]string, len(spec))
	maps.Copy(effective, provided)
	for name, arg := range spec {
		if effective[name] == "" && arg.defaultValue != "" {
			effective[name] = arg.defaultValue
		}
	}
	return effective
}

func validateArgs(spec map[string]argument, effective map[string]string) error {
	for name, arg := range spec {
		// exlude 0 from the mutually exclusive logic so that order can
		// be omitted during argument map initilization.
		if arg.order == 0 && arg.required && effective[name] == "" {
			return fmt.Errorf("%v: required", name)
		}
	}

	// identifies an argument group (i.e, an numbered argument set)
	type groupInfo struct {
		names []string // every argument belonging to the group
		found []string // subset of arguments that have a non-empty value
	}
	groups := map[int]*groupInfo{}
	for name, arg := range spec {
		if arg.order == 0 {
			continue
		}
		gi := groups[arg.order]
		if gi == nil {
			gi = &groupInfo{}
			groups[arg.order] = gi
		}
		gi.names = append(gi.names, name)
		if effective[name] != "" {
			gi.found = append(gi.found, name)
		}
	}

	for order, gi := range groups {
		sort.Strings(gi.names)
		sort.Strings(gi.found)

		// Check if any arg in this group is required. If any of the args in
		// this group are required, exactly one has to be set.
		required := false
		for _, name := range gi.names {
			if spec[name].required {
				required = true
				break
			}
		}

		switch len(gi.found) {
		case 0:
			if required {
				return fmt.Errorf("one of [%v] required (group %d)",
					strings.Join(gi.names, "|"), order)
			}
		case 1:
			// exactly one is correct
		default:
			return fmt.Errorf("[%v] are mutually exclusive",
				strings.Join(gi.found, ", "))
		}
	}

	return nil
}

// printGroupHelp prints auto-generated help for a command group.
func printGroupHelp(groupName string, grp commandGroup) {
	fmt.Fprintf(os.Stderr, "%v\n\n", welcome)
	fmt.Fprintf(os.Stderr, "Usage: %v %v [OPTION]... [ACTION] [<key=value>...]\n\n",
		os.Args[0], groupName)
	if grp.help != "" {
		fmt.Fprintf(os.Stderr, "%v\n\n", grp.help)
	}
	fmt.Fprintf(os.Stderr, "OPTIONS:\n")
	fmt.Fprintf(os.Stderr, "\t-h, -help\tDisplay help information\n\n")
	fmt.Fprintf(os.Stderr, "ACTIONS:\n")

	names := make([]string, 0, len(grp.commands))
	for n := range grp.commands {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		cmd := grp.commands[name]
		if cmd.help != "" {
			fmt.Fprintf(os.Stderr, "  %-38v %v\n", name, cmd.help)
		} else {
			fmt.Fprintf(os.Stderr, "  %v\n", name)
		}

		argNames := make([]string, 0, len(cmd.args))
		for a := range cmd.args {
			argNames = append(argNames, a)
		}
		sort.Strings(argNames)

		for _, argName := range argNames {
			spec := cmd.args[argName]
			var qualifier string
			switch {
			case spec.order > 0 && spec.required:
				qualifier = fmt.Sprintf("one-of-group-%d", spec.order)
			case spec.order > 0:
				qualifier = fmt.Sprintf("optional-group-%d", spec.order)
			case spec.required:
				qualifier = "required"
			default:
				qualifier = "optional"
			}
			def := ""
			if spec.defaultValue != "" {
				def = fmt.Sprintf(" (default: %v)", spec.defaultValue)
			}
			fmt.Fprintf(os.Stderr, "    %-40v %v%v [%v]\n", argName, spec.help, def, qualifier)
		}
		fmt.Println("")
	}
	fmt.Fprintf(os.Stderr, "\nARGUMENTS:\n\tPassed as key=value pairs, e.g. '%v %v <action> key=value'\n", os.Args[0], groupName)
}

// dispatchGroup looks up the action in grp, validates args, and runs the command.
// args should be the remaining args after group-level flags have been parsed
// (i.e. the output of flagSet.Args()).
func dispatchGroup(ctx context.Context, grp commandGroup, groupName string, args []string) error {
	if len(args) == 0 {
		printGroupHelp(groupName, grp)
		return nil
	}

	action, rawArgs, err := parseArgs(args)
	if err != nil {
		return err
	}

	cmd, ok := grp.commands[action]
	if !ok {
		return fmt.Errorf("%v: unknown action %q\nRun '%v %v -h' for available actions",
			groupName, action, os.Args[0], groupName)
	}

	effective := applyDefaults(cmd.args, rawArgs)
	if err := validateArgs(cmd.args, effective); err != nil {
		return fmt.Errorf("%v %v: %w", groupName, action, err)
	}

	return cmd.run(ctx, effective)
}

func init() {
	version.Component = "hemictl"
	welcome = "Hemi Network Controller " + version.BuildInfo()
}

func usage() {
	fmt.Fprintf(os.Stderr, "%v\n", welcome)
	fmt.Fprintf(os.Stderr, "Usage: %v [OPTION]... <command> [<args>]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "OPTIONS:\n")
	fmt.Fprintf(os.Stderr, "\t-h, -help\tDisplay help information (this help)\n\n")
	fmt.Fprintf(os.Stderr, "COMMANDS:\n")

	names := make([]string, 0, len(registeredCommands))
	for name := range registeredCommands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(os.Stderr, "\t%-10v\t%v\n", name, registeredCommands[name].help)
	}

	fmt.Fprintf(os.Stderr, "\nENVIRONMENT:\n")
	config.Help(os.Stderr, cm)
	fmt.Fprintf(os.Stderr, "\nuse 'hemictl <command> -h' or 'hemictl <command> -help' to"+
		" display command-specific help information.\n")
}

func _main(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := config.Parse(cm); err != nil {
		return err
	}

	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		return err
	}
	log.Debugf("%v", welcome)

	pc := config.PrintableConfig(cm)
	for k := range pc {
		log.Debugf("%v", pc[k])
	}

	go func() {
		<-ctx.Done()
		cancel()
	}()

	entry, ok := registeredCommands[args[0]]
	if !ok {
		return fmt.Errorf("unknown command: %v", args[0])
	}
	return entry.handler(ctx, args[1:])
}

func main() {
	helpFlag := flag.Bool("h", false, "Display help information")
	helpFlagLong := flag.Bool("help", false, "Display help information")
	flag.Usage = func() {
		usage()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 || *helpFlag || *helpFlagLong {
		usage()
		os.Exit(1)
	}

	if err := _main(args); err != nil {
		fmt.Fprintf(os.Stderr, "\n%v: %v\n", daemonName, err)
		os.Exit(1)
	}
}
