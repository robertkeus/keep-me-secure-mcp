module example.com/app

go 1.22

require (
	golang.org/x/text v0.3.0
	github.com/old/lib v2.0.0+incompatible // indirect
	github.com/acme/local v1.0.0
	github.com/orig/moved v1.0.0
)

require github.com/one/line v1.0.0

replace github.com/acme/local => ../local

replace (
	github.com/orig/moved => github.com/fork/moved v1.5.0
)
