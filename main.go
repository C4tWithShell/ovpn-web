package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gavintan/gopkg/tools"
	"github.com/gin-contrib/sessions"
	gormsessions "github.com/gin-contrib/sessions/gorm"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
	gLogger "gorm.io/gorm/logger"
)

const (
	DefaultWebPort    = "8833"
	DefaultManagement = "127.0.0.1:7505"
	DefaultDataDir    = "/app"
	DefaultSecretKey  = "ovpn-web"
	ConnectionTimeout = 10 * time.Second
	BufferSize        = 1024
	MaxFileSize       = 10 * 1024 * 1024 // 10MB
	SessionMaxAge     = 3600
	Remember7dMaxAge  = 3600 * 24 * 7

	// Command patterns for validation
	ValidCommandPattern = `^[a-zA-Z0-9\-_\s]+$`
	ValidFilePattern    = `^[a-zA-Z0-9\-_\.\/]+$`
	ValidNamePattern    = `^[a-zA-Z0-9\-_]+$`
)

type ClientData struct {
	ID         string `json:"id"`
	Rip        string `json:"rip"`
	Vip        string `json:"vip"`
	Vip6       string `json:"vip6"`
	RecvBytes  string `json:"recvBytes"`
	SendBytes  string `json:"sendBytes"`
	ConnDate   string `json:"connDate"`
	OnlineTime string `json:"onlineTime"`
	UserName   string `json:"username"`
}

type ServerData struct {
	RunDate    string
	Status     string
	StatusDesc string
	Address    string
	Nclients   string
	BytesIn    string
	BytesOut   string
	Mode       string
	Version    string
}

type ClientConfigData struct {
	Name     string `json:"name"`
	FullName string `json:"fullName"`
	File     string `json:"file"`
	Date     string `json:"date"`
}

type Params struct {
	Draw        int    `json:"draw" form:"draw"`
	Offset      int    `json:"offset" form:"offset"`
	Limit       int    `json:"limit" form:"limit"`
	OrderColumn string `json:"orderColumn" form:"orderColumn"`
	Order       string `json:"order" form:"order"`
	Search      string `json:"search" form:"search"`
	Qt          string `json:"qt" form:"qt"`
}

type ovpn struct {
	address string
}

type Config struct {
	OvData    string
	OvManage  string
	WebPort   string
	SecretKey string
}

var (
	FS embed.FS

	db           *gorm.DB
	config       *Config
	validCommand = regexp.MustCompile(ValidCommandPattern)
	validFile    = regexp.MustCompile(ValidFilePattern)
	validName    = regexp.MustCompile(ValidNamePattern)

	logger = gLogger.New(
		log.New(os.Stdout, "[OPENVPN-WEB] "+time.Now().Format("2025-07-18 02:37:05.000")+" MAIN ", 0),
		gLogger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  gLogger.Error,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)
)

// Input validation functions
func validateInput(input, pattern string) bool {
	if len(input) == 0 || len(input) > 255 {
		return false
	}
	matched, err := regexp.MatchString(pattern, input)
	if err != nil {
		logger.Error(context.Background(), "Regex validation error: "+err.Error())
		return false
	}
	return matched
}

func sanitizeFilePath(filePath string) (string, error) {
	if !validateInput(filePath, ValidFilePattern) {
		return "", fmt.Errorf("invalid file path")
	}

	cleanPath := filepath.Clean(filePath)
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("path traversal detected")
	}

	return cleanPath, nil
}

func generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (ov *ovpn) sendCommand(command string) (string, error) {
	if !validateInput(command, ValidCommandPattern) {
		return "", fmt.Errorf("invalid command format")
	}

	ctx, cancel := context.WithTimeout(context.Background(), ConnectionTimeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", ov.address)
	if err != nil {
		logger.Error(context.Background(), "Connection error: "+err.Error())
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Set connection deadline
	if err := conn.SetDeadline(time.Now().Add(ConnectionTimeout)); err != nil {
		return "", fmt.Errorf("failed to set deadline: %w", err)
	}

	// Send command
	if _, err := conn.Write([]byte(fmt.Sprintf("%s\n", command))); err != nil {
		return "", fmt.Errorf("failed to write command: %w", err)
	}

	// Read response with size limit
	var sb strings.Builder
	sb.Grow(BufferSize * 4) // Pre-allocate space

	totalRead := 0
	re := regexp.MustCompile(`>INFO(.)*\r\n`)

	for {
		if totalRead > MaxFileSize {
			return "", fmt.Errorf("response too large")
		}

		buf := make([]byte, BufferSize)
		n, err := conn.Read(buf)
		if n > 0 {
			totalRead += n
			cleanStr := re.ReplaceAllString(string(buf[:n]), "")
			if cleanStr != "" {
				sb.WriteString(cleanStr)
			}
		}

		if err != nil || strings.HasSuffix(sb.String(), "\r\nEND\r\n") || strings.HasPrefix(sb.String(), "SUCCESS:") {
			break
		}
	}

	data := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(sb.String(), "\r\nEND\r\n"), "\r\n"), "SUCCESS: ")
	return data, nil
}

// Enhanced getClient with proper error handling and bounds checking
func (ov *ovpn) getClient() ([]ClientData, error) {
	clients := make([]ClientData, 0)

	data, err := ov.sendCommand("status 3")
	if err != nil {
		return clients, fmt.Errorf("Failed to get status: %w", err)
	}

	lines := strings.Split(data, "\r\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		cdSlice := strings.Split(line, "\t")

		// Proper bounds checking
		if len(cdSlice) < 11 || cdSlice[0] != "CLIENT_LIST" {
			continue
		}

		// Validate and parse numeric fields with error handling
		recv, err := strconv.ParseFloat(cdSlice[5], 64)
		if err != nil {
			logger.Error(context.Background(), "Failed to parse recv bytes: "+err.Error())
			continue
		}

		send, err := strconv.ParseFloat(cdSlice[6], 64)
		if err != nil {
			logger.Error(context.Background(), "Failed to parse send bytes: "+err.Error())
			continue
		}

		connDate, err := time.ParseInLocation("2025-07-18 02:42:05", cdSlice[7], time.Local)
		if err != nil {
			logger.Error(context.Background(), "Failed to parse connection date: "+err.Error())
			continue
		}

		// Safe string operations
		rip := cdSlice[2]
		if strings.Contains(cdSlice[2], ":") {
			if colonIndex := strings.IndexByte(cdSlice[2], ':'); colonIndex != -1 {
				rip = cdSlice[2][:colonIndex]
			}
		}

		username := cdSlice[9]
		if username == "UNDEF" {
			username = cdSlice[1]
		}

		// Validate extracted data
		if !validateInput(rip, `^[0-9a-fA-F\.:]+$`) {
			continue
		}

		cd := ClientData{
			Rip:        rip,
			Vip:        cdSlice[3],
			Vip6:       cdSlice[4],
			RecvBytes:  tools.FormatBytes(recv),
			SendBytes:  tools.FormatBytes(send),
			ConnDate:   cdSlice[7],
			UserName:   username,
			ID:         cdSlice[10],
			OnlineTime: (time.Duration(time.Now().Unix()-connDate.Unix()) * time.Second).String(),
		}

		clients = append(clients, cd)
	}

	return clients, nil
}

// Enhanced getServer with better error handling
func (ov *ovpn) getServer() (ServerData, error) {
	var sd ServerData

	// Get state
	data, err := ov.sendCommand("state")
	if err != nil {
		return sd, fmt.Errorf("Failed to get state: %w", err)
	}

	stateSlice := strings.Split(data, ",")
	if len(stateSlice) >= 3 {
		if runDate, err := strconv.ParseInt(stateSlice[0], 10, 64); err == nil {
			sd.RunDate = time.Unix(runDate, 0).Format("2006-01-02 15:04:05")
		}
		sd.Status = stateSlice[1]
		sd.StatusDesc = stateSlice[2]
		sd.Address = stateSlice[3]
	}

	// Get load stats
	data, err = ov.sendCommand("load-stats")
	if err != nil {
		return sd, fmt.Errorf("Failed to get load stats: %w", err)
	}

	statsSlice := strings.Split(data, ",")
	for _, v := range statsSlice {
		statsKeySlice := strings.Split(v, "=")
		if len(statsKeySlice) != 2 {
			continue
		}

		switch statsKeySlice[0] {
		case "nclients":
			sd.Nclients = statsKeySlice[1]
		case "bytesin":
			if in, err := strconv.ParseFloat(statsKeySlice[1], 64); err == nil {
				sd.BytesIn = tools.FormatBytes(in)
			}
		case "bytesout":
			if out, err := strconv.ParseFloat(statsKeySlice[1], 64); err == nil {
				sd.BytesOut = tools.FormatBytes(out)
			}
		}
	}

	// Get version
	data, err = ov.sendCommand("version")
	if err != nil {
		return sd, fmt.Errorf("Failed to get version: %w", err)
	}

	for _, v := range strings.Split(data, "\n") {
		if strings.HasPrefix(v, "OpenVPN Version: ") {
			sd.Version = strings.TrimPrefix(v, "OpenVPN Version: ")
			break
		}
	}

	return sd, nil
}

func (ov *ovpn) killClient(cid string) error {
	if !validateInput(cid, `^[a-zA-Z0-9\-_]+$`) {
		return fmt.Errorf("Invalid client ID")
	}

	_, err := ov.sendCommand(fmt.Sprintf("client-kill %s HALT", cid))
	return err
}

func AuthMiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")

		if user == nil {
			if c.Request.Method == "GET" && c.Request.URL.Path == "/login" {
				c.Next()
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authentication required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func ValidationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validate Content-Length
		if c.Request.ContentLength > MaxFileSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"message": "Request too large"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func secureFileRead(basePath, relativePath string) ([]byte, error) {
	cleanPath, err := sanitizeFilePath(relativePath)
	if err != nil {
		return nil, err
	}

	fullPath := filepath.Join(basePath, cleanPath)

	// Ensure the file is within the base directory
	if !strings.HasPrefix(fullPath, filepath.Clean(basePath)) {
		return nil, fmt.Errorf("path outside base directory")
	}

	return os.ReadFile(fullPath)
}

func secureFileWrite(basePath, relativePath, content string) error {
	cleanPath, err := sanitizeFilePath(relativePath)
	if err != nil {
		return err
	}

	fullPath := filepath.Join(basePath, cleanPath)

	// Ensure the file is within the base directory
	if !strings.HasPrefix(fullPath, filepath.Clean(basePath)) {
		return fmt.Errorf("path outside base directory")
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(fullPath, []byte(content), 0644)
}

func secureExecCommand(command string, args ...string) ([]byte, error) {
	// Validate command and arguments
	if !validateInput(command, ValidCommandPattern) {
		return nil, fmt.Errorf("invalid command")
	}

	for _, arg := range args {
		if !validateInput(arg, ValidCommandPattern) {
			return nil, fmt.Errorf("invalid argument")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	return cmd.CombinedOutput()
}

func loadConfig() (*Config, error) {
	config := &Config{
		OvData:    DefaultDataDir,
		OvManage:  DefaultManagement,
		WebPort:   DefaultWebPort,
		SecretKey: DefaultSecretKey,
	}

	if val, ok := os.LookupEnv("OVPN_DATA"); ok {
		if validateInput(val, ValidFilePattern) {
			config.OvData = val
		}
	}

	if val, ok := os.LookupEnv("OVPN_MANAGEMENT"); ok {
		if validateInput(val, `^[0-9a-zA-Z\.\:]+$`) {
			config.OvManage = val
		}
	}

	if val, ok := os.LookupEnv("WEB_PORT"); ok {
		if validateInput(val, `^[0-9]+$`) {
			config.WebPort = val
		}
	}

	if val, ok := os.LookupEnv("SECRET_KEY"); ok {
		if len(val) >= 8 {
			config.SecretKey = val
		}
	}

	return config, nil
}

func initDB(config *Config) (*gorm.DB, error) {
	dbPath := filepath.Join(config.OvData, "ovpn.db")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to connect database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("Failed to get database instance: %w", err)
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

func init() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		logger.Error(context.Background(), "Failed to load .env file: "+err.Error())
	}
}

func main() {
	// Load configuration
	var err error
	config, err = loadConfig()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// Initialize database
	db, err = initDB(config)
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	// Auto-migrate database
	if err := db.AutoMigrate(&User{}, &History{}, &SysUser{}); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Initialize OpenVPN client
	ov := &ovpn{
		address: config.OvManage,
	}

	// Create session store
	store := gormsessions.NewStore(db, true, []byte(config.SecretKey))

	// Initialize Gin with security headers
	r := gin.New()

	// Add security middleware
	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Next()
	})

	r.Use(ValidationMiddleware())
	r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		var statusColor, methodColor, resetColor string
		if param.IsOutputColor() {
			statusColor = param.StatusCodeColor()
			methodColor = param.MethodColor()
			resetColor = param.ResetColor()
		}

		if param.Latency > time.Minute {
			param.Latency = param.Latency.Truncate(time.Second)
		}
		return fmt.Sprintf("[OPENVPN-WEB] %v GIN |%s %3d %s| %13v | %15s |%s %-7s %s %#v\n%s",
			param.TimeStamp.Format("2006-01-02 15:04:05.000"),
			statusColor, param.StatusCode, resetColor,
			param.Latency,
			param.ClientIP,
			methodColor, param.Method, resetColor,
			param.Path,
			param.ErrorMessage,
		)
	}))

	r.Use(sessions.Sessions("user_session", store))
	r.Use(gin.Recovery())

	// Setup templates
	templ := template.Must(template.New("").ParseFS(FS, "templates/*.tmpl"))
	r.SetHTMLTemplate(templ)
	f, _ := fs.Sub(FS, "templates/static")
	r.StaticFS("/static", http.FS(f))

	// Public routes
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.tmpl", gin.H{})
	})

	r.POST("/login", func(c *gin.Context) {
		var u SysUser
		if err := c.ShouldBind(&u); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
			return
		}

		// Validate input
		if !validateInput(u.Username, `^[a-zA-Z0-9_]+$`) || !validateInput(u.Password, `.+`) {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid username or password format"})
			return
		}

		remember7d := c.PostForm("remember7d")

		if err := u.Login(); err == nil {
			session := sessions.Default(c)
			session.Set("user", u.Username)

			maxAge := SessionMaxAge
			if remember7d == "on" {
				maxAge = Remember7dMaxAge
			}

			session.Options(sessions.Options{
				MaxAge:   maxAge,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})

			if err := session.Save(); err != nil {
				logger.Error(context.Background(), "Failed to save session: "+err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Session error"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{"message": "Incorrect username or password"})
	})

	r.GET("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Clear()
		session.Options(sessions.Options{MaxAge: -1})
		session.Save()
		c.Redirect(http.StatusFound, "/login")
	})

	// Protected routes
	r.Use(AuthMiddleWare())

	r.GET("/", func(c *gin.Context) {
		serverData, err := ov.getServer()
		if err != nil {
			logger.Error(context.Background(), "Failed to get server data: "+err.Error())
			c.HTML(http.StatusInternalServerError, "error.tmpl", gin.H{"error": "Server error"})
			return
		}

		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"server":  serverData,
			"sysUser": os.Getenv("ADMIN_USERNAME"),
		})
	})

	r.POST("/user", func(c *gin.Context) {
		var u SysUser
		if err := c.ShouldBind(&u); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
			return
		}

		if err := u.Create(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "User added successfully"})
		}
	})

	// OpenVPN routes
	ovpn := r.Group("/ovpn")
	{
		ovpn.StaticFS("/download", http.Dir("clients"))

		ovpn.POST("/server", func(c *gin.Context) {
			action := c.PostForm("action")
			if !validateInput(action, `^[a-zA-Z]+$`) {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid action"})
				return
			}

			switch action {
			case "settings":
				key := c.PostForm("key")
				value := c.PostForm("value")

				if !validateInput(key, `^[a-zA-Z\-]+$`) || !validateInput(value, `^[a-zA-Z0-9]+$`) {
					c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid parameters"})
					return
				}

				if key == "auth-user" {
					msg := "Disable"
					if value == "true" {
						msg = "Enable"
					}

					out, err := secureExecCommand("sh", "-c", fmt.Sprintf("/usr/bin/docker-entrypoint.sh auth %s", value))
					if err != nil {
						logger.Error(context.Background(), string(out))
						c.JSON(http.StatusInternalServerError, gin.H{"message": fmt.Sprintf("%s user authentication failed", msg)})
						return
					}

					if _, err := ov.sendCommand("signal SIGHUP"); err != nil {
						logger.Error(context.Background(), "Failed to send SIGHUP: "+err.Error())
					}

					c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("%s user authentication successful", msg)})
				}

			case "renewcert":
				out, err := secureExecCommand("sh", "-c", "/usr/bin/docker-entrypoint.sh renewcert")
				if err != nil {
					logger.Error(context.Background(), string(out))
					c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update certificate"})
					return
				}

				if _, err := ov.sendCommand("signal SIGHUP"); err != nil {
					logger.Error(context.Background(), "Failed to send SIGHUP: "+err.Error())
				}

				c.JSON(http.StatusOK, gin.H{"message": "Certificate updated successfully"})

			case "restartSrv":
				if _, err := ov.sendCommand("signal SIGHUP"); err != nil {
					logger.Error(context.Background(), err.Error())
					c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to restart service"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"message": "Service restarted successfully"})

			case "getConfig":
				data, err := secureFileRead(config.OvData, "server.conf")
				if err != nil {
					logger.Error(context.Background(), err.Error())
					c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to read configuration"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"content": string(data)})

			case "updateConfig":
				content := c.PostForm("content")
				if len(content) > MaxFileSize {
					c.JSON(http.StatusBadRequest, gin.H{"message": "Content too large"})
					return
				}

				if err := secureFileWrite(config.OvData, "server.conf", content); err != nil {
					logger.Error(context.Background(), err.Error())
					c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update configuration"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"message": "Configuration updated successfully"})

			default:
				c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "Unknown operation"})
			}
		})

		ovpn.POST("/kill", func(c *gin.Context) {
			cid := c.PostForm("cid")
			if err := ov.killClient(cid); err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to kill client"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"code": http.StatusOK})
		})

		ovpn.POST("/login", func(c *gin.Context) {
			var u User
			if err := c.ShouldBind(&u); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
				return
			}

			if err := u.Login(); err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
			}
		})

		ovpn.GET("/online-client", func(c *gin.Context) {
			clients, err := ov.getClient()
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to get clients"})
				return
			}
			c.JSON(http.StatusOK, clients)
		})

		ovpn.GET("/user", func(c *gin.Context) {
			var u User
			auth := false

			out, err := secureExecCommand("egrep", "^auth-user-pass-verify", filepath.Join(config.OvData, "server.conf"))
			if err == nil && len(out) > 0 {
				auth = true
			}

			c.JSON(http.StatusOK, gin.H{"users": u.All(), "authUser": auth})
		})

		ovpn.POST("/user", func(c *gin.Context) {
			var u User
			if err := c.ShouldBind(&u); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
				return
			}

			if err := u.Create(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "User added successfully"})
			}
		})

		ovpn.PATCH("/user", func(c *gin.Context) {
			var u User
			if err := c.ShouldBind(&u); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
				return
			}

			if ipAddr, ok := c.Request.PostForm["ipAddr"]; ok {
				if ipAddr[0] == "" {
					db.Model(&u).Update("ip_addr", nil)
				}
			}
			if err := u.Update(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
			}
		})

		ovpn.DELETE("/user/:id", func(c *gin.Context) {
			var u User
			id := c.Param("id")

			if !validateInput(id, `^[a-zA-Z0-9\-_]+$`) {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid user ID"})
				return
			}

			if err := u.Delete(id); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
			}
		})

		ovpn.GET("/client", func(c *gin.Context) {
			action := c.Query("a")
			if !validateInput(action, `^[a-zA-Z]+$`) {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid action"})
				return
			}

			if action == "getConfig" {
				file := c.Query("file")
				if !validateInput(file, ValidFilePattern) {
					c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid file path"})
					return
				}

				data, err := secureFileRead(config.OvData, file)
				if err != nil {
					if strings.Contains(file, "ccd") && os.IsNotExist(err) {
						c.JSON(http.StatusOK, gin.H{"content": ""})
					} else {
						logger.Error(context.Background(), err.Error())
						c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to read file"})
					}
					return
				}

				c.JSON(http.StatusOK, gin.H{"content": string(data)})
			} else {
				// List client configs
				ccd := make([]ClientConfigData, 0)
				clientsDir := filepath.Join(config.OvData, "clients")

				files, err := os.ReadDir(clientsDir)
				if err != nil {
					logger.Error(context.Background(), "Failed to read clients directory: "+err.Error())
					c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to read client directory"})
					return
				}

				for _, file := range files {
					if file.IsDir() {
						continue
					}

					finfo, err := file.Info()
					if err != nil {
						continue
					}

					// Validate file name
					if !validateInput(file.Name(), `^[a-zA-Z0-9\-_\.]+$`) {
						continue
					}

					f := ClientConfigData{
						Name:     strings.TrimSuffix(file.Name(), filepath.Ext(file.Name())),
						FullName: file.Name(),
						File:     fmt.Sprintf("/ovpn/download/%s", file.Name()),
						Date:     finfo.ModTime().Local().Format("2006-01-02 15:04:05"),
					}
					ccd = append(ccd, f)
				}

				c.JSON(http.StatusOK, ccd)
			}
		})

		ovpn.PUT("/client", func(c *gin.Context) {
			file := c.Query("file")
			content := c.PostForm("content")

			if !validateInput(file, ValidFilePattern) {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid file path"})
				return
			}

			if len(content) > MaxFileSize {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Content too large"})
				return
			}

			msg := "Client configuration updated successfully"

			if strings.Contains(file, "ccd") {
				// Check if client-config-dir is enabled
				serverConfPath := filepath.Join(config.OvData, "server.conf")
				out, err := secureExecCommand("grep", "-q", "^client-config-dir", serverConfPath)
				if out == nil {
					out = []byte(err.Error())
				}
				if err != nil {
					// Add client-config-dir to server.conf
					ccdCmd := fmt.Sprintf("echo 'client-config-dir %s/ccd' >> %s/server.conf", config.OvData, config.OvData)
					if _, err := secureExecCommand("sh", "-c", ccdCmd); err != nil {
						logger.Error(context.Background(), "Failed to add client-config-dir: "+err.Error())
					}
					msg += " (CCD not enabled, restart service required)"
				}
			}

			if err := secureFileWrite(config.OvData, file, content); err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update client configuration"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": msg})
		})

		ovpn.POST("/client", func(c *gin.Context) {
			name := c.PostForm("name")
			serverAddr := c.PostForm("serverAddr")
			clientConfig := c.PostForm("config")
			ccdConfig := c.PostForm("ccdConfig")

			// Validate inputs
			if !validateInput(name, ValidNamePattern) {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid client name"})
				return
			}

			if !validateInput(serverAddr, `^[a-zA-Z0-9\.\-:]+$`) {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid server address"})
				return
			}

			if len(clientConfig) > MaxFileSize || len(ccdConfig) > MaxFileSize {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Configuration too large"})
				return
			}

			// Check if client already exists
			clientPath := filepath.Join(config.OvData, "clients", fmt.Sprintf("%s.ovpn", name))
			if _, err := os.Stat(clientPath); err == nil {
				c.JSON(http.StatusConflict, gin.H{"message": "Client already exists"})
				return
			}

			// Generate client
			cmd := fmt.Sprintf("/usr/bin/docker-entrypoint.sh genclient %s %s %s %s",
				name, serverAddr, clientConfig, ccdConfig)

			out, err := secureExecCommand("sh", "-c", cmd)
			if err != nil {
				logger.Error(context.Background(), string(out))
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create client"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Client created successfully"})
		})

		ovpn.DELETE("/client/:name", func(c *gin.Context) {
			name := c.Param("name")

			if !validateInput(name, ValidNamePattern) {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid client name"})
				return
			}

			// Revoke certificate
			revokeCmd := fmt.Sprintf("easyrsa --batch revoke %s && easyrsa gen-crl", name)
			out, err := secureExecCommand("sh", "-c", revokeCmd)
			if err != nil {
				logger.Error(context.Background(), string(out))
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to revoke client certificate"})
				return
			}

			// Remove client files
			clientPath := filepath.Join(config.OvData, "clients", fmt.Sprintf("%s.ovpn", name))
			ccdPath := filepath.Join(config.OvData, "ccd", name)

			if err := os.Remove(clientPath); err != nil && !os.IsNotExist(err) {
				logger.Error(context.Background(), "Failed to remove client file: "+err.Error())
			}

			if err := os.Remove(ccdPath); err != nil && !os.IsNotExist(err) {
				logger.Error(context.Background(), "Failed to remove CCD file: "+err.Error())
			}

			c.JSON(http.StatusOK, gin.H{"message": "Client deleted successfully"})
		})

		ovpn.GET("/history", func(c *gin.Context) {
			var h History
			var p Params

			if err := c.ShouldBindQuery(&p); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid query parameters"})
				return
			}

			// Validate and sanitize parameters
			if p.Limit <= 0 || p.Limit > 1000 {
				p.Limit = 100
			}
			if p.Offset < 0 {
				p.Offset = 0
			}

			c.JSON(http.StatusOK, h.Query(p))
		})

		ovpn.POST("/history", func(c *gin.Context) {
			var h History
			if err := c.ShouldBind(&h); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
				return
			}

			if err := h.Create(); err != nil {
				logger.Error(context.Background(), "Failed to create history record: "+err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create history record"})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "History record created successfully"})
			}
		})
	}

	// Graceful shutdown
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", config.WebPort),
		Handler:           r,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	log.Printf("OpenVPN Web Interface starting on port %s", config.WebPort)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("Failed to start server:", err)
	}
}
