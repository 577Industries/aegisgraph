# REG-URL-OkHttp-userinfo-1: userinfo-host-confusion (validator vs fetcher)

## Class
userinfo-host-confusion

## Bug
Some URL parsers (notably `okhttp3.HttpUrl` historically and many
OAuth/redirect validators) parse `https://trusted.example@evil.example/`
as host=`trusted.example`, while strict RFC 3986 parsers parse it as
host=`evil.example` with `userinfo=trusted.example`. When a validator
trusts the first interpretation and a fetcher acts on the second, you
get an SSRF / origin-confusion bug.

## Why it matters
This is the canonical case from Snyk's 2022 "How URL parsers can become
weapons" study, also extensively covered by Bishop Fox and PortSwigger.
Reachable from any link-preview pipeline that accepts user-submitted
URLs.

## Reference
- https://snyk.io/blog/url-confusion-vulnerabilities/
- https://blog.doyensec.com/2022/01/12/url-validation-bypass.html

## Public-info-only
This case is constructed from public references; it is NOT a live
target probe. The "evil.example" / "trusted.example" hosts are RFC 2606
example domains.
