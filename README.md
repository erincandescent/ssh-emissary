# `ssh-emissary` - A better SSH agent

> **emissary**
> ˈɛmɪs(ə)ri/Submit
> *noun*
> a person sent as a diplomatic representative on a special mission.

There are several commonly used SSH Agent implementations: 
 * `ssh-agent`
 * `gpg-agent`
 * Gnome Keyring

Theyre all fine, but you might want more:
 * None support use of ECDSA keys from a smart card
 * You might like using `pam_u2f` for `sudo`, but it only 
   supports locally connected devices

`ssh-emissary` gives you these features - and, in addition, it lets 
you forward requests to another agent if you need features it lacks

# Installation
The simplest option is to build from source:
```
go get github.com/erincandescent/ssh-emissary
go install github.com/erincandescent/ssh-emissary
```

# Configuration
`ssh-emissary` is configured by a the file `~/.config/ssh-emissary/config.json`. 
The strutcure of this should be 

```
{
	"backends": [
		{"type": "type_name", "params": {...}},
		{"type": "type_name", "params": {...}},
		...
	]
}
```

The ordering of backends expresses a preference order - earlier backends
will have their keys listed first, and hence ssh will list them first. In
addition, add key requests (`ssh-add <file>`) will be forwarded to each backend
in turn until one reports success.

## Backends
### proxy
Proxy requests to another SSH Agent implementation
```
  {"type": "proxy", "params": {"socket": "~/.gnupg/S.gpg-agent.ssh"}}
```
Options:
 * **socket**: Path to socket to connect to agent on

### piv 
Source keys from a PIV smartcard
```
  {"type": "piv", "params": {"transport": "scdaemon"}}
```

Options:
 * **transport**: Formatted as "`<name>`" or "`<name>:<params>`", 
 	where the structure of `<params>` is transport dependent.

### u2f
Expose u2f devices as SSH keys
```
  {"type": "u2f"}
```

This plugin has no options. **Caution**: The protocol used by
this mode is subject to change.

This protocol is custom to ssh-emissary. See 
[the documentation](docs/protocol.md).