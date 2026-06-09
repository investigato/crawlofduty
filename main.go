package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"

	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/rs/zerolog"
	flag "github.com/spf13/pflag"
)

var (
	version   = "dev"
	codename  = "unknown"
	buildTime = "unknown"
)

type AccessLevel int

const (
	ACCESS_NONE AccessLevel = iota
	ACCESS_READ
	ACCESS_WRITE
)

type Result struct {
	Share       string
	Dir         string
	Files       []string
	accessLevel AccessLevel
}
type LocalOptions struct {
	conn            *smb.Connection
	noInitialCon    bool
	smbOptions      *smb.Options
	excludedFolders map[string]interface{}
}

type workItem struct {
	share string
	dir   string
}

type prettyWriter struct{}

func (w prettyWriter) Write(p []byte) (n int, err error) {
	var event map[string]interface{}
	if err := json.Unmarshal(p, &event); err != nil {

		_, _ = fmt.Print(string(p))
		return len(p), nil
	}

	level, _ := event["level"].(string)
	message, _ := event["message"].(string)

	switch strings.ToUpper(level) {
	case "INFO":
		_, _ = color.New(color.FgCyan).Printf("[INFO]  %s\n", message)
	case "WARN":
		_, _ = color.New(color.FgYellow).Printf("[WARN]  %s\n", message)
	case "ERROR":
		_, _ = color.New(color.FgRed, color.Bold).Printf("[ERR]   %s\n", message)
	case "DEBUG":
		_, _ = color.New(color.Faint).Printf("[DBG]   %s\n", message)
	case "FATAL":
		_, _ = color.New(color.FgRed, color.Bold).Printf("[FATAL] %s\n", message)
	default:
		_, _ = fmt.Printf("[%s] %s\n", strings.ToUpper(level), message)
	}

	return len(p), nil
}

func newLogger() zerolog.Logger {
	return zerolog.New(prettyWriter{}).With().Logger()
}
func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

const (
	KiB = 1024
	MiB = KiB * 1024
	GiB = MiB * 1024
)

func downloadFiles(ctx context.Context, session *smb.Connection, files []string, fileSizeThreshold uint64, fileSizeLimit uint64, downloadDir string) {
	log := zerolog.Ctx(ctx)
	for _, file := range files {
		downloadFile(session, log, file, fileSizeThreshold, fileSizeLimit, downloadDir)
	}
}

func downloadFile(session *smb.Connection, log *zerolog.Logger, file string, fileSizeThreshold uint64, fileSizeLimit uint64, downloadDir string) {
	// Strip filepath of prefix
	tmpPath := strings.TrimPrefix(file, "\\\\")

	parts := strings.Split(tmpPath, "\\")
	if len(parts) == 0 {
		log.Error().Msgf("Invalid path to download (%s)\n", file)
		return
	}
	share := parts[1]
	// When running this tool on linux against a windows SMB share, the path separators will differ
	metafilepath := strings.Join(parts[2:], "\\")

	remotePath := metafilepath
	localPathComponents := strings.Split(metafilepath, "\\")
	// remove all "" path components to avoid issues with path.Join and to prevent creating unintended directories
	cleanedLocalPathComponents := make([]string, 0, len(localPathComponents))
	for _, comp := range localPathComponents {
		if comp != "" {
			cleanedLocalPathComponents = append(cleanedLocalPathComponents, comp)
		}
	}
	localPathComponents = cleanedLocalPathComponents
	localPath := path.Join(downloadDir, share, path.Join(localPathComponents...))
	if err := os.MkdirAll(path.Dir(localPath), 0755); err != nil {
		log.Error().Err(err).Msgf("Failed to create local directory for file %s\n", localPath)
		return
	}
	f, err := os.Create(localPath)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to create local file %s\n", localPath)
		return
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Error().Err(err).Msgf("Failed to close local file %s\n", localPath)
		}
	}()
	// just write the damn file to disk
	err = session.RetrieveFile(share, remotePath, 0, f.Write)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to retrieve file %s\n", file)
		return
	}
	// Clear the progress outprint
	fmt.Printf("\r%s\r", string(make([]byte, 80)))
	log.Info().Msgf("Downloaded (%s)", strings.TrimPrefix(localPath, downloadDir+string(os.PathSeparator)))

}

func main() {

	var host string
	flag.StringVarP(&host, "host", "i", "", "Hostname or IP address of the target")

	var port int
	flag.IntVarP(&port, "port", "P", 445, "Port number to connect to")

	var username string
	flag.StringVarP(&username, "user", "u", "", "Username for authentication")

	var password string
	flag.StringVarP(&password, "pass", "p", "", "Password for authentication")

	var hash string
	flag.StringVarP(&hash, "hash", "H", "", "NTHash for authentication (format: LMHASH:NTHASH)")

	var domain string
	flag.StringVarP(&domain, "domain", "d", "", "Domain for authentication")

	var recurse bool
	flag.BoolVarP(&recurse, "recurse", "r", true, "Recursively list directories")

	var noWrite bool
	flag.BoolVarP(&noWrite, "no-write", "", false, "Disable write checking")

	var shareFlag string
	flag.StringVarP(&shareFlag, "shares", "s", "", "Specify shares")

	var debug bool
	flag.BoolVarP(&debug, "debug", "", false, "Enable debug output")

	var verbose bool
	flag.BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	var yolo bool
	flag.BoolVarP(&yolo, "yolo", "", false, "YOLO mode (disable all filters and limits on file downloads, be careful!)")

	var versionFlag bool
	flag.BoolVarP(&versionFlag, "version", "V", false, "Show version")

	var excludeShareFlag string
	flag.StringVarP(&excludeShareFlag, "exclude-shares", "e", "", "Comma separated list of shares to exclude from enumeration")

	var excludeFolder string
	flag.StringVarP(&excludeFolder, "exclude-folders", "F", "", "Exclude folders")

	var kerberos bool
	flag.BoolVarP(&kerberos, "kerberos", "k", false, "Use Kerberos")

	var targetIP string
	flag.StringVarP(&targetIP, "target-ip", "", "", "Target IP address")

	var dcIP string
	flag.StringVarP(&dcIP, "dc-ip", "", "", "Domain Controller IP address")

	var ccachePath string
	flag.StringVarP(&ccachePath, "ccache", "", "", "use this ccache file")

	var aesKey string
	flag.StringVarP(&aesKey, "aes-key", "", "", "AES key for Kerberos authentication (format: hex string)")

	var spn string
	flag.StringVarP(&spn, "spn", "", "", "SPN for Kerberos authentication (format: service/hostname)")

	var noPass bool
	flag.BoolVarP(&noPass, "no-pass", "", false, "Do not use password")

	var dnsHost string
	flag.StringVarP(&dnsHost, "dns-host", "", "", "DNS host")

	var dnsTCP bool
	flag.BoolVarP(&dnsTCP, "dns-tcp", "", false, "Use DNS over TCP")

	var noEnc bool
	flag.BoolVarP(&noEnc, "no-enc", "", false, "Disable encryption")

	var forceSMB2 bool
	flag.BoolVarP(&forceSMB2, "smb2", "", false, "Force SMB2")

	var nullSession bool
	flag.BoolVarP(&nullSession, "null", "Z", false, "Use null session")

	var interactive bool
	flag.BoolVarP(&interactive, "interactive", "", false, "Interactive mode")

	var localUser bool
	flag.BoolVarP(&localUser, "local", "", false, "")

	var dialTimeout time.Duration
	flag.DurationVarP(&dialTimeout, "timeout", "", 5*time.Second, "Timeout")
	// var includeExt string
	// var excludeExt string
	// flag.StringVar(&includeExt, "include-exts", "", "")
	// flag.StringVar(&excludeExt, "exclude-exts", "", "")

	// var includedExts map[string]interface{}
	// var excludedExts map[string]interface{}

	var err error
	var excludedFolders map[string]interface{}

	flag.CommandLine.SortFlags = false
	flag.Parse()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	logger := newLogger()
	ctx := context.Background()
	ctx = logger.WithContext(ctx)
	if versionFlag {
		_, _ = fmt.Printf("App Version: %s\nCodename: %s\nBuild Time: %s\n", version, codename, buildTime)
		os.Exit(0)
	}
	// if includeExt != "" && excludeExt != "" {
	// 	if isFlagSet("include-exts") {
	// 		logger.Error().Msg("--include-ext and --exclude-ext are mutually exclusive, so don't supply both!")
	// 		flag.Usage()
	// 		return
	// 	}
	// 	logger.Warn().Msg("Clearing default --include-exts settings as --exclude-exts was specified")
	// 	includeExt = ""

	// }

	// if includeExt != "" {
	// 	includedExts = make(map[string]interface{})
	// 	exts := strings.Split(includeExt, ",")
	// 	for _, e := range exts {
	// 		includedExts["."+strings.ToUpper(strings.TrimPrefix(e, "."))] = nil
	// 	}
	// }

	// if excludeExt != "" {
	// 	excludedExts = make(map[string]interface{})
	// 	exts := strings.Split(excludeExt, ",")
	// 	for _, e := range exts {
	// 		excludedExts["."+strings.ToUpper(strings.TrimPrefix(e, "."))] = nil
	// 	}
	// }
	// validate host and/or targetIP
	if host == "" && targetIP == "" {
		logger.Error().Msg("Error: Hostname or Target IP must be specified")
		return
	}

	// if both host and targetIP are provided, we can use host for SMB connection and targetIP for Kerberos or other operations
	// if only one is provided, we can use it for both purposes
	if host == "" && targetIP != "" {
		host = targetIP
	} else if targetIP == "" && host != "" {
		targetIP = host
	}
	// Validate format
	if isFlagSet("dns-host") {
		parts := strings.Split(dnsHost, ":")
		if len(parts) < 2 {
			if dnsHost != "" {
				dnsHost += ":53"
				parts = append(parts, "53")
				logger.Info().Msgf("No port number specified for --dns-host so assuming port 53")
			} else {
				fmt.Println("Invalid --dns-host")
				flag.Usage()
				return
			}
		}
		ip := net.ParseIP(parts[0])
		if ip == nil {
			fmt.Println("Invalid --dns-host. Not a valid ip host address")
			flag.Usage()
			return
		}
		p, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			fmt.Printf("Invalid --dns-host. Failed to parse port: %s\n", err)
			return
		}
		if p < 1 {
			fmt.Println("Invalid --dns-host port number")
			flag.Usage()
			return
		}
	}
	smbOptions := smb.Options{
		Host:                  targetIP,
		Domain:                domain,
		Port:                  port,
		DisableEncryption:     noEnc,
		ForceSMB2:             forceSMB2,
		RequireMessageSigning: false,
		DisableSigning:        true,
	}
	var hashBytes []byte
	if hash != "" {
		var hashBytesErr error
		hashBytes, hashBytesErr = hex.DecodeString(hash)
		if hashBytesErr != nil {
			fmt.Println("Failed to decode hash")

			os.Exit(1)
		}
	}
	if kerberos {
		if ccachePath != "" {
			err := os.Setenv("KRB5CCNAME", ccachePath)
			if err != nil {
				return
			}
		}
		var aesKeyBytes []byte
		if aesKey != "" {
			aesKeyBytes, err = hex.DecodeString(aesKey)
			if err != nil {
				fmt.Println("Failed to decode AES key")
				os.Exit(1)
			}
		}
		if spn == "" {
			spn = fmt.Sprintf("cifs/%s", host)
		}

		// if the username has @domain.com format, split it and use the part before @ as username and the part after @ as domain, unless domain is explicitly specified with -d/--domain flag
		if strings.Contains(username, "@") && domain == "" {
			parts := strings.SplitN(username, "@", 2)
			username = parts[0]
			domain = parts[1]
		} else if strings.Contains(username, "@") && domain != "" {
			parts := strings.SplitN(username, "@", 2)
			username = parts[0]
		}
		smbOptions.Initiator = &spnego.KRB5Initiator{
			User:     username,
			Password: password,
			Hash:     hashBytes,
			AESKey:   aesKeyBytes,
			Domain:   domain,
			DCIP:     dcIP,
			SPN:      spn,
		}
	} else {
		smbOptions.Initiator = &spnego.NTLMInitiator{
			User:        username,
			Password:    password,
			Hash:        hashBytes,
			Domain:      domain,
			NullSession: nullSession,
		}
	}
	smbOptions.DialTimeout = dialTimeout

	// can't touch this ...dah na na na na na na na na
	if excludeFolder != "" {
		excludedFolders = make(map[string]interface{})
		folders := strings.Split(excludeFolder, ",")
		for _, f := range folders {
			excludedFolders[strings.TrimSpace(f)] = nil
		}
	}
	parts := strings.Split(excludeShareFlag, ",")
	excludedShares := make(map[string]bool)
	for _, p := range parts {
		excludedShares[strings.TrimSpace(p)] = true
	}

	if dnsHost != "" {
		protocol := "udp"
		if dnsTCP {
			protocol = "tcp"
		}
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: dialTimeout,
				}
				return d.DialContext(ctx, protocol, dnsHost)
			},
		}
	}
	var opts LocalOptions
	opts.smbOptions = &smbOptions
	opts.conn, err = smb.NewConnection(smbOptions)
	if err != nil {
		logger.Fatal().Err(err).Msg("Critical error")
		opts.noInitialCon = true
	}

	defer func() {
		if opts.conn != nil {
			opts.conn.Close()
		}
	}()

	if interactive {
		fmt.Print("Shits not ready yet for interactive mode, sorry :(\n")
		// if opts.conn != nil && !opts.conn.IsAuthenticated() {
		// 	opts.smbOptions.ManualLogin = true
		// }
		// shell := newShell(&opts)
		// if shell == nil {
		// 	logger.Error().Msg("Failed to start an interactive shell")
		// 	return
		// }
		// shell.cmdloop()
		// return
	}
	if opts.conn == nil {
		logger.Info().Msg("That didn't work, maybe the target is down or not responding on that port?")
		return
	}

	if opts.conn.IsAuthenticated() {
		// logger.Info().Msgf("Logged in as %s", opts.conn.GetAuthUsername())
	} else {
		logger.Info().Msg("So sad, authentication failed :(")
		return
	}
	var shares []string
	share := "IPC$"
	disconnectShare := func(share string) {
		if err := opts.conn.TreeDisconnect(share); err != nil {
			logger.Error().Err(err).Msgf("Failed to disconnect tree %s", share)
		}
	}
	err = opts.conn.TreeConnect(share)
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	f, err := opts.conn.OpenFile(share, "srvsvc")
	if err != nil {
		logger.Error().Msg(err.Error())
		disconnectShare(share)
		return
	}

	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	bind, err := dcerpc.Bind(transport, mssrvs.MSRPCUuidSrvSvc, 3, 0, dcerpc.MSRPCUuidNdr)
	if err != nil {
		logger.Error().Msg("Failed to bind to service")
		logger.Error().Msg(err.Error())
		if err := f.CloseFile(); err != nil {
			logger.Error().Err(err).Msg("Failed to close srvsvc file")
		}
		disconnectShare(share)
		return
	}
	rpccon := mssrvs.NewRPCCon(bind)

	result, err := rpccon.NetShareEnumAll(host)
	if err != nil {
		logger.Error().Msg(err.Error())
		if err := f.CloseFile(); err != nil {
			logger.Error().Err(err).Msg("Failed to close srvsvc file")
		}
		disconnectShare(share)
		return
	}

	// anything we don't want?
	for _, netshare := range result {
		name := netshare.Name
		if _, ok := excludedShares[name]; ok {
			// Exclude share
			continue
		}

		if netshare.TypeId == mssrvs.StypeDisktree {
			shares = append(shares, name)
		}
	}
	if err := f.CloseFile(); err != nil {
		logger.Error().Err(err).Msg("Failed to close srvsvc file")
	}
	//

	var excludeThese = []string{"ADMIN$", "C$", "IPC$"}
	sharesToScan := []string{}
	for _, share := range shares {
		if slices.Contains(excludeThese, share) {
			continue
		}
		if (len(shareFlag) > 0) && !strings.Contains(shareFlag, share) {
			continue
		}
		sharesToScan = append(sharesToScan, share)
	}
	tryWrite := !noWrite
	var results []Result
	var allFiles []string
	results, err = lukeTreeWalker(ctx, opts.conn, sharesToScan, excludedFolders, recurse, tryWrite, false, "")
	if err != nil {
		logger.Error().Err(err).Msg("Failed to list directories recursively")
		return
	}

	// if we got here, we have a list of files that we can potentially download, so let's do it!
	for _, r := range results {
		for _, file := range r.Files {
			var resultFilepath = fmt.Sprintf("\\\\%s\\%s\\%s", host, r.Share, file)
			allFiles = append(allFiles, resultFilepath)
		}
	}

	if yolo && len(allFiles) > 0 {
		// downloadFiles(ctx, opts.conn, allFiles, includedExts, excludedExts, nil, 0, 0, "downloads")
		downloadFiles(ctx, opts.conn, allFiles, 0, 0, "downloads")
	}
}

// now with file listing return!
func lukeTreeWalker(ctx context.Context, session *smb.Connection, shares []string, excludedFolders map[string]interface{}, recurse, tryWrite, followJunctions bool, startDir string) (allResults []Result, err error) {

	logger := zerolog.Ctx(ctx)
	dir := strings.ReplaceAll(startDir, "/", `\`)
	dir = strings.Trim(dir, `\`)

	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	workChan := make(chan workItem, 100)

	// 4 worker bees buzzing
	for i := 0; i < 4; i++ {
		go workerBee(ctx, session, excludedFolders, recurse, tryWrite, followJunctions, &results, &mu, &wg, workChan)
	}

	for _, share := range shares {
		err := session.TreeConnect(share)
		if err != nil {
			if errors.Is(err, smb.StatusMap[smb.StatusBadNetworkName]) {
				fmt.Printf("Share %s can not be found!\n", share)
				continue
			}
			logger.Error().Err(err).Msg("tree connect")
			continue
		}
		wg.Add(1)
		workChan <- workItem{share: share, dir: dir}
	}

	// clean up after yourself pleaseee
	go func() {
		wg.Wait()
		close(workChan)
	}()

	wg.Wait()
	printResults(results, tryWrite)
	return results, nil
}

func canWeWriteHere(ctx context.Context, session *smb.Connection, share, dir string) bool {
	testFile := dir + `\.wrtest`
	if dir == "" {
		testFile = `.wrtest`
	}

	err := uploadFile(ctx, session, share, os.DevNull, testFile, true)
	if err != nil {
		return false
	}

	_ = session.DeleteFile(share, testFile)
	return true
}

func uploadFile(ctx context.Context, conn *smb.Connection, share, localFile, remotePath string, replaceFile bool) (err error) {
	logger := zerolog.Ctx(ctx)
	var f *os.File
	filename := filepath.Base(localFile)
	if filename == "." || filename == string(os.PathSeparator) {
		err = fmt.Errorf("could not determine filename for local file")
		return
	}

	// Remote paths should use Windows path separators
	remotePath = strings.ReplaceAll(remotePath, "/", "\\")

	if remotePath == "" {
		err = fmt.Errorf("remote path must not be empty")
		return
	}

	// Check if remotePath specifies filename
	if remotePath[len(remotePath)-1] == '\\' {
		remotePath += "\\" + filename
	}
	var modifiedRemoteFile string
	modifiedRemoteFile = remotePath

	if remotePath[0] == '\\' {
		modifiedRemoteFile = remotePath[1:] // Skip initial slash
	}

	// Check that local file exists
	f, err = os.Open(localFile)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Error().Msgf("The local filename(%s) does not exist\n", localFile)
			return
		}
		logger.Error().Err(err).Msg("Failed to open local file")
		return
	}
	defer func() {
		closeErr := f.Close()
		if closeErr == nil {
			return
		}
		if err == nil {
			err = closeErr
			return
		}
		logger.Error().Err(closeErr).Msg("Failed to close local file")
	}()

	// Check if remote file exists
	createOpts := smb.NewCreateReqOpts()
	createOpts.CreateDisp = smb.FileCreate
	f2, err := conn.OpenFileExt(share, modifiedRemoteFile, createOpts)
	if err != nil {
		// Check if file exists and we want to replace it
		if errors.Is(err, smb.StatusMap[smb.StatusObjectNameCollision]) {
			if !replaceFile {
				logger.Error().Msgf("The remote file %q already exists. Run with --replace to overwrite it\n", modifiedRemoteFile)
				return
			}
		} else {
			return
		}
	} else {
		if closeErr := f2.CloseFile(); closeErr != nil {
			logger.Error().Err(closeErr).Msg("Failed to close remote file handle")
			return closeErr
		}
	}

	err = conn.PutFile(share, modifiedRemoteFile, 0, f.Read)
	if err != nil {

		return err
	}
	return nil
}

func workerBee(ctx context.Context, session *smb.Connection, excludedFolders map[string]interface{}, recurse, tryWrite, followJunctions bool, results *[]Result, mu *sync.Mutex, wg *sync.WaitGroup, workChan chan workItem) {
	logger := zerolog.Ctx(ctx)

	for item := range workChan {
		contents, err := session.ListDirectory(item.share, item.dir, "")
		if err != nil {
			if !errors.Is(err, smb.StatusMap[smb.StatusAccessDenied]) {
				logger.Error().Err(err).Msg("listing directory")
			}
			// Collect the filenames before you enter the mutex block, then include them in the struct literal when you do the append.
			fileNames := make([]string, 0, len(contents))
			for _, content := range contents {
				if !content.IsDir {
					fileNames = append(fileNames, content.Name)
				}
			}
			mu.Lock()
			*results = append(*results, Result{
				Share:       item.share,
				Dir:         item.dir,
				Files:       fileNames,
				accessLevel: ACCESS_NONE,
			})
			mu.Unlock()
			wg.Done()
			continue
		}
		if tryWrite {
			writable := canWeWriteHere(ctx, session, item.share, item.dir)

			mu.Lock()
			*results = append(*results, Result{
				Share: item.share,
				Dir:   item.dir,
				accessLevel: func() AccessLevel {
					if writable {
						return ACCESS_WRITE
					}
					return ACCESS_READ
				}(),
			})
			mu.Unlock()
		} else {
			mu.Lock()
			*results = append(*results, Result{
				Share:       item.share,
				Dir:         item.dir,
				accessLevel: ACCESS_READ,
			})
			mu.Unlock()
		}
		for _, content := range contents {
			// collecting directories for recursion, but also files for downloading later
			if content.IsDir {
				if _, ok := excludedFolders[content.Name]; ok {
					continue
				}
				var entryPath string
				if item.dir == "" {
					entryPath = content.Name
				} else {
					entryPath = item.dir + `\` + content.Name
				}
				wg.Add(1)
				workChan <- workItem{share: item.share, dir: entryPath}
			}
			// if it's a file, we add it to the list of files in the current directory result
			if !content.IsDir {
				mu.Lock()
				for i := range *results {
					if (*results)[i].Share == item.share && (*results)[i].Dir == item.dir {
						var entryPath string
						if item.dir == "" {
							entryPath = content.Name
						} else {
							entryPath = item.dir + `\` + content.Name
						}
						(*results)[i].Files = append((*results)[i].Files, entryPath)
						break
					}
				}
				mu.Unlock()
			}
			// if it's a junction and we want to follow junctions, we also add it to the list of directories to recurse into
			if content.IsJunction && followJunctions {
				var entryPath string
				if item.dir == "" {
					entryPath = content.Name
				} else {
					entryPath = item.dir + `\` + content.Name
				}
				wg.Add(1)
				workChan <- workItem{share: item.share, dir: entryPath}
			}
		}
		wg.Done()
	}
}
func getParent(dir string) string {
	idx := strings.LastIndex(dir, `\`)
	if idx == -1 {
		return dir
	}
	return dir[:idx]
}
func printResults(results []Result, tryWrite bool) {
	rw := color.New(color.FgGreen, color.Bold)
	ro := color.New(color.FgWhite, color.Bold)
	na := color.New(color.FgRed, color.Bold)
	warn := color.New(color.FgYellow, color.Bold)

	fmt.Println()
	// sort writable paths to the top of the list, then no access, then readable but not writable at the bottom, while maintaining the original order within those groups...
	sort.Slice(results, func(i, j int) bool {
		order := map[AccessLevel]int{
			ACCESS_WRITE: 0,
			ACCESS_NONE:  1,
			ACCESS_READ:  2,
		}
		return order[results[i].accessLevel] < order[results[j].accessLevel]
	})

	printSection := func(items []Result, limit int, printer *color.Color) {
		if len(items) == 0 {
			return
		}

		// if there's too many kids, just hide them under their parent folder
		parentCount := make(map[string]int)
		for _, r := range items {
			parentCount[getParent(r.Dir)]++
		}

		printed := make(map[string]bool)
		count := 0

		for _, r := range items {
			if count >= limit {
				_, _ = printer.Printf("    ... aaaaaand %d more\n", len(items)-count)
				break
			}

			parent := getParent(r.Dir)
			siblings := parentCount[parent]

			if siblings > 1 && !printed[parent] {
				_, _ = printer.Printf("%s\\%s\\*\n", r.Share, parent)
				printed[parent] = true
				count++
			} else if siblings == 1 {
				_, _ = printer.Printf("%s\\%s\n", r.Share, r.Dir)
				count++
			}
		}
		fmt.Println()
	}

	var writable, noAccess, readable []Result
	for _, r := range results {
		switch r.accessLevel {
		case ACCESS_WRITE:
			writable = append(writable, r)
		case ACCESS_NONE:
			noAccess = append(noAccess, r)
		case ACCESS_READ:
			readable = append(readable, r)
		}
	}
	if !tryWrite {
		_, _ = warn.Println("We didn't even try to write anywhere, so who knows ¯\\_(ツ)_/¯")
	} else if len(writable) == 0 {
		_, _ = warn.Println("no writable paths found")
	} else if len(writable) == 1 {
		_, _ = rw.Printf("%d writable path found\n", len(writable))
	} else {
		_, _ = rw.Printf("%d writable paths found\n", len(writable))
	}
	fmt.Println()
	if tryWrite && len(writable) > 0 {
		_, _ = rw.Println("YOU CAN WRITE STUFF HERE!!")
		printSection(writable, 5, rw)
	}
	if len(noAccess) > 0 {
		_, _ = na.Println("YOU CAN'T EVEN SEE THESE FOLDERS :(")
		printSection(noAccess, 5, na)
	}
	if len(readable) > 0 {
		_, _ = ro.Println("MAYBE SOMETHING INTERESTING TO READ HERE?")
		printSection(readable, 5, ro)
	}

}
