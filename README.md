# gin-csrf [![Build Status](https://travis-ci.org/srbry/gin-csrf.svg?branch=main)](https://travis-ci.org/srbry/gin-csrf)

CSRF protection middleware for [Gin]. This middleware has to be used with [gin-contrib/sessions](https://github.com/gin-contrib/sessions).

Original credit to [tommy351](https://github.com/tommy351/gin-csrf).
Also based on the work from [utrack](https://github.com/utrack/gin-csrf) that made it work with gin-gonic contrib sessions.

This fork adds on both of those to allow the optional use of named sessions when used with gin-contrib [multiple sessions](https://github.com/gin-contrib/sessions#multiple-sessions).

Additionaly aims at making changes easier by introducing a `CSRFManager` interface.

## Installation

``` bash
$ go get github.com/srbry/gin-csrf
```

## Usage

```go
package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/srbry/gin-csrf"
)

func main() {
	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))

	csrfManager := &csrf.DefaultCSRFManager{
		Secret: "secret123",
		ErrorFunc: func(c *gin.Context) {
			c.String(400, "CSRF token mismatch")
			c.Abort()
		},
	}

	r.Use(sessions.Sessions("mysession", store))
	r.Use(csrfManager.Middleware())


	r.GET("/protected", func(c *gin.Context) {
		c.String(200, csrfManager.GetToken(c))
	})

	r.POST("/protected", func(c *gin.Context) {
		c.String(200, "CSRF token is valid")
	})

	r.Run(":8080")
}
```

[Gin]: http://gin-gonic.github.io/gin/
[gin-sessions]: https://github.com/utrack/gin-sessions
