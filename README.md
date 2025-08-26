# go-sneck

This program is deliberately quite primitive.

It's not an authentication system to keep people from accessing your self-hosted service(s). It's an authentication system to keep people from knowing you have a self-hosted service in the first place. This is a latch in front of the real lock, made to prevent people from casually deciding to pick it. It is *not* very secure by itself and isn't supposed to be. If you can use a central authentication system of some sort, it will be a better solution, but I couldn't, so I had to make this.

It is useful in a narrow set of circumstances which I suspect is more common than it appears:

+ You have a system where `nginx` serves as a reverse proxy for one or multiple self-hosted services that already have authentication systems of their own -- like, say, [Jellyfin](https://jellyfin.org/).
+ You want to prevent random visitors -- marauding LLMs -- from knowing the service even exists.
+ The service requires purpose-built clients which can't handle a central authentication solution or something more robust, and these clients run in constrained environments -- like Jellyfin clients on Android TV devices.

You can see Jellyfin is the use case this was devised for, but it is by far not the only case where such a thing could be useful.

`go-sneck` uses nginx's `auth_request` mechanism to sit in front of a service, and vets client IPs, rather than anything else. When you need to access the service from a new location, you open a browser to the login URL, which can be hidden entirely, and enter a [TOTP code](https://en.wikipedia.org/wiki/Time-based_one-time_password). Your IP is memorized and requests from this IP begin to pass to the actual service.

Once no more requests are coming in, IPs will eventually time out and be forgotten. Autentications are only stored in memory, so a quick way to kick everyone off is to restart `go-sneck`.

If you have shell access to the client machine, but no browser, you can use `curl` or equivalent, since there is actually no CORS check -- just POST a form with `otp` field in it. This is obviously not very secure, which is why POST requests to the login page are rate-limited to one per 5 seconds *globally*, that is, ignoring the source IP address of the request. This ensures that determined attackers will take at least some time to bruteforce the TOTP.

But if they succeed, they still have the service's native login page to deal with.

## Configuration file

By default, `go-sneck` tries to read the configuration file from `/etc/nginx/go-sneck.yaml`, but you can supply one on command line:

```text
go-sneck -c config-file-elsewhere.yaml
```

The config file is a yaml file:

```yaml
# You need to supply the starting slash on urls, which indicates server root.
# This example contains default values.

# The URL that auth_request will be pointed at.
auth_url: /@authorize

# URL of the login page. Pick something random.
login_url: /@login

# URL that the user will be redirected to upon logging in. 
# Presumably your service's actual login page.
success_url: /

# Time for an authorization to time out, in minutes.
# This time is measured since the last successfull 
# request that was verified against auth_request,
# so if your service's clients keepalive at least
# this often, they will never time out.
timeout: 1440

# Host to listen at.
host: "127.0.0.1"
# Port to listen at
port: 4302

# List of explicitly allowed IP addresses. Optional.
allow:
- "192.168.1.1"
# CIDR networks are also supported in allow/deny lists.
- "192.168.100.0/24"

# List of explicitly denied IP addresses.
# The order they're checked in is deny/allow/authorized.
deny:
- "8.8.8.8"

# List of authorized users. See below for details:
users:
- ...
- ...
```

All of the configuration options can actually be supplied on the command line or through environment variables, see `go-sneck --help`.

## Adding users

`go-sneck` supports multiple users, that are written into the configuration file as `otpauth://` urls:

```yaml
users:
- otpauth://totp/sneck:USERNAME?algorithm=SHA1&digits=6&issuer=go-sneck&period=30&secret=SECRET
```

`go-sneck` only relies on the presence of `USERNAME` and `SECRET` in this url, though your typical TOTP program, like Google Authenticator, needs the rest of this data. You can feed such an URL into a QR code generator and most every TOTP program will scan the result normally. The only use of a username is to see it in the logs and make it easier for you to revoke authorization.

To generate a new user record, as well as see the QR code in your console, you can use `go-sneck` itself:

```text
$ go-sneck adduser foo | tee -a /etc/nginx/go-sneck.yaml
....
users:
- otpauth://totp/sneck:.....?algorithm=SHA1&digits=6&issuer=sneck&period=30&secret=....
```

You then scan the barcode with your authenticator app. The `tee -a` will append only the `users:` part of the output to the configuration file, so you can put it where it belongs.

## Setting up Nginx

I refer you to the various literature on setting up `auth_request` properly.

`go-sneck` relies on the presence of `X-Real-IP` header to permit or refuse access, and errors out if it doesn't see one, but even with that, the configuration is relatively trivial. This snippet, that goes into `server {}`, sets nginx up to request go/no-go decisions from `go-sneck`:

```nginx
# Which URL to go check
auth_request /@authorize;

# If the URL is exactly equal to that, pass it to go-sneck,
# limiting data conferred thereby to headers only and supplying the real IP.
location = /@authorize {
        proxy_pass http://localhost:4302;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Real-IP $remote_addr;
}
```

The login page can be more or less anywhere else:

```nginx
location /@login {
        proxy_pass http://localhost:4302;
        proxy_set_header X-Real-IP $remote_addr;
        # To disable checking authentication on the login page itself:
        auth_request off;
}
```

## Starting up

You can restrict a service pretty hard just with systemd alone, so I don't see why people insist on containers for a single-executable service.

```systemd
[Unit]
Description=go-sneck authenticator
StartLimitIntervalSec=5
After=syslog.target network.target

[Service]
ExecStart=/usr/local/bin/go-sneck
Restart=always

# Start as a dummy user belonging to www-data group
# (which owns the config file).
DynamicUser=yes
SupplementaryGroups=www-data
ReadOnlyPaths=/etc/nginx/go-sneck.yaml

# Log as usual for a systemd service.
SyslogIdentifier=sneck
StandardOutput=journal
StandardError=journal

# Harden things by revoking privileges we don't need.
NoNewPrivileges=yes
PrivateTmp=yes

PrivateDevices=yes
PrivateUsers=yes
IPAddressDeny=any
IPAddressAllow=127.0.0.1

[Install]
WantedBy=default.target
```

## Building

This is a Go program. A recent installation of Go and `go build -ldflags='-s -w'` is all you really need. Or pick a file from the Releases.

## Potential questions

### Why TOTP?

Because it is easier to type in constrained conditions, like on a screen keyboard on an Android TV. The security of a TOTP alone without even a username isn't very good, but with the other protections it should be enough.

Tuning [fail2ban](https://github.com/fail2ban/fail2ban) to block visitors that get rate limited on the login is left as an exercise for the reader.

### The name is kinda weird

["sneck" is a Scottish word for "latch"](https://en.wikipedia.org/wiki/Latch), and I liked the sound of it quite a bit when I found out.

## License

This program is licensed under the terms of MIT license.
