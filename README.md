# crawlofduty

<img height="150" alt="crawlofduty-logo" src="https://github.com/investigato/crawlofduty/blob/main/assets/crawlofduty.png" />

it recursively checks if you can write to shares. that's it.

## why

because smbmap and netexec lied to me recently. they check ACLs. ACLs are suggestions. `crawlofduty` actually tries to create a file. if it works, the share is writable. if it doesn't, it isn't. no assumptions, no inference, no bullshit.

this tool exists because on one recent Saturday afternoon HTB release, SYSVOL showed up READ-ONLY in every tool in the bag. it wasn't.

## usage

```bash
crawlofduty [flags]

flags:
    -i, --host string              Hostname or IP address of the target
    -P, --port int                 Port number to connect to (default 445)
    -u, --user string              Username for authentication
    -p, --pass string              Password for authentication
    -H, --hash string              NTHash for authentication (format: LMHASH:NTHASH)
    -d, --domain string            Domain for authentication
    -r, --recurse                  Recursively list directories (default true)
        --no-write                 Disable write checking (default false)
    -s, --shares string            Specify shares
        --debug                    Enable debug output
    -v, --verbose                  Verbose output
    -V, --version                  Show version
        --yolo                     Check for writable shares & Download every file you can read!
    -e, --exclude-shares string    Comma separated list of shares to exclude from enumeration
    -F, --exclude-folders string   Exclude folders
    -k, --kerberos                 Use Kerberos
        --target-ip string         Target IP address
        --dc-ip string             Domain Controller IP address
        --aes-key string           AES key for Kerberos authentication (format: hex string)
        --no-pass                  Do not use password
        --dns-host string          DNS host
        --dns-tcp                  Use DNS over TCP
        --no-enc                   Disable encryption
        --smb2                     Force SMB2
    -Z, --null                     Use null session
        --interactive              Interactive mode
        --local                    
        --timeout duration         Timeout (default 5s)
```

### examples

```bash
crawlofduty --host dc01.corp.local -u f.fakerson -p 'ThisIsNotReal'
```

## output

```bash
1 writable path found

YOU CAN WRITE STUFF HERE!!
SYSVOL\corp.local\scripts

YOU CAN'T EVEN SEE THESE FOLDERS :(
SYSVOL\corp.local\DfsrPrivate

MAYBE SOMETHING INTERESTING TO READ HERE?
SYSVOL\corp.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\*
SYSVOL\corp.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\*
SYSVOL\corp.local\*
SYSVOL\corp.local\Policies\*
SYSVOL\\*
    ... aaaaaand 15 more
```

writable paths first. no access second. readable last, collapsed where possible, capped at 5 entries per section. the thing you care about is always at the top.

## what it does not do

- check ACLs
- assume anything about your permissions based on group membership
- report a share as writable without actually writing to it
- require a domain-joined machine
- support kerberos yet (coming eventually, probably)

## authorized use only

this tool is for authorized penetration testing and red team engagements. don't be weird about it. as always, I am not responsible for your poor decisions.
