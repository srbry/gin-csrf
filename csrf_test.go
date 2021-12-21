package csrf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions/cookie"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newServer(csrfManager CSRFManager) *gin.Engine {
	g := gin.New()

	store := cookie.NewStore([]byte("secret123"))

	g.Use(sessions.Sessions("my_session", store))
	g.Use(csrfManager.Middleware())

	return g
}

func newServerWithNamedSession(csrfManager CSRFManager) *gin.Engine {
	g := gin.New()

	store := cookie.NewStore([]byte("secret123"))

	g.Use(sessions.SessionsMany([]string{"my_session", "my-test-session"}, store))
	g.Use(csrfManager.Middleware())

	return g
}

type requestOptions struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    io.Reader
}

func request(server *gin.Engine, options requestOptions) *httptest.ResponseRecorder {
	if options.Method == "" {
		options.Method = "GET"
	}

	w := httptest.NewRecorder()
	req, err := http.NewRequest(options.Method, options.URL, options.Body)

	if options.Headers != nil {
		for key, value := range options.Headers {
			req.Header.Set(key, value)
		}
	}

	server.ServeHTTP(w, req)

	if err != nil {
		panic(err)
	}

	return w
}

func TestForm(t *testing.T) {
	var token string
	csrfManager := &DefaultCSRFManager{
		Secret: "secret123",
	}
	g := newServer(csrfManager)

	g.GET("/login", func(c *gin.Context) {
		token = csrfManager.GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login",
		Headers: map[string]string{
			"Cookie":       r1.Header().Get("Set-Cookie"),
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: strings.NewReader("_csrf=" + token),
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}

func TestQueryString(t *testing.T) {
	var token string
	csrfManager := &DefaultCSRFManager{
		Secret: "secret123",
	}
	g := newServer(csrfManager)

	g.GET("/login", func(c *gin.Context) {
		token = csrfManager.GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login?_csrf=" + token,
		Headers: map[string]string{
			"Cookie": r1.Header().Get("Set-Cookie"),
		},
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}

func TestQueryStringWithNamedSession(t *testing.T) {
	var token string
	csrfManager := &DefaultCSRFManager{
		Secret:      "secret123",
		SessionName: "my-test-session",
	}
	g := newServerWithNamedSession(csrfManager)

	g.GET("/login", func(c *gin.Context) {
		token = csrfManager.GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login?_csrf=" + token,
		Headers: map[string]string{
			"Cookie": r1.Header().Get("Set-Cookie"),
		},
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}

func TestQueryHeader1(t *testing.T) {
	var token string
	csrfManager := &DefaultCSRFManager{
		Secret: "secret123",
	}
	g := newServer(csrfManager)

	g.GET("/login", func(c *gin.Context) {
		token = csrfManager.GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login",
		Headers: map[string]string{
			"Cookie":       r1.Header().Get("Set-Cookie"),
			"X-CSRF-Token": token,
		},
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}

func TestQueryHeader2(t *testing.T) {
	var token string
	csrfManager := &DefaultCSRFManager{
		Secret: "secret123",
	}
	g := newServer(csrfManager)

	g.GET("/login", func(c *gin.Context) {
		token = csrfManager.GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login",
		Headers: map[string]string{
			"Cookie":       r1.Header().Get("Set-Cookie"),
			"X-XSRF-Token": token,
		},
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}

func TestErrorFunc(t *testing.T) {
	result := ""
	csrfManager := &DefaultCSRFManager{
		Secret: "secret123",
		ErrorFunc: func(c *gin.Context) {
			result = "something wrong"
		},
	}
	g := newServer(csrfManager)

	g.GET("/login", func(c *gin.Context) {
		csrfManager.GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	request(g, requestOptions{
		Method: "POST",
		URL:    "/login",
		Headers: map[string]string{
			"Cookie": r1.Header().Get("Set-Cookie"),
		},
	})

	if result != "something wrong" {
		t.Error("Error function was not called")
	}
}

func TestIgnoreMethods(t *testing.T) {
	csrfManager := &DefaultCSRFManager{
		Secret:        "secret123",
		IgnoreMethods: []string{"GET", "POST"},
	}
	g := newServer(csrfManager)

	g.GET("/login", func(c *gin.Context) {
		csrfManager.GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login",
		Headers: map[string]string{
			"Cookie": r1.Header().Get("Set-Cookie"),
		},
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}

func TestTokenGetter(t *testing.T) {
	var token string
	csrfManager := &DefaultCSRFManager{
		Secret: "secret123",
		TokenGetter: func(c *gin.Context) string {
			return c.Request.FormValue("wtf")
		},
	}
	g := newServer(csrfManager)

	g.GET("/login", func(c *gin.Context) {
		token = csrfManager.GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login",
		Headers: map[string]string{
			"Cookie":       r1.Header().Get("Set-Cookie"),
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: strings.NewReader("wtf=" + token),
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}
