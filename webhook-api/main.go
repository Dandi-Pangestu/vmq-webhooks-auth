package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// JWT Secret Key - In production, this should be from environment variables
var jwtSecretKey = []byte("your_super_secret_key")

// CustomClaims struct with publish and subscribe ACLs
type CustomClaims struct {
	Subject string   `json:"subject"`
	PubACL  []string `json:"pub,omitempty"`
	SubACL  []string `json:"sub,omitempty"`
	jwt.RegisteredClaims
}

// Request/Response structures for VerneMQ webhooks

// Auth on Register Request
type AuthOnRegisterRequest struct {
	PeerAddr     string `json:"peer_addr"`
	PeerPort     int    `json:"peer_port"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Mountpoint   string `json:"mountpoint"`
	ClientID     string `json:"client_id"`
	CleanSession bool   `json:"clean_session"`
}

// Auth on Subscribe Request
type AuthOnSubscribeRequest struct {
	Username   string                 `json:"username"`
	ClientID   string                 `json:"client_id"`
	Mountpoint string                 `json:"mountpoint"`
	Topics     []AuthOnSubscribeTopic `json:"topics"`
}

type AuthOnSubscribeTopic struct {
	Topic string `json:"topic"`
	QOS   int    `json:"qos"`
}

// Auth on Publish Request
type AuthOnPublishRequest struct {
	Username   string `json:"username"`
	ClientID   string `json:"client_id"`
	Mountpoint string `json:"mountpoint"`
	QOS        int    `json:"qos"`
	Topic      string `json:"topic"`
	Payload    string `json:"payload"`
	Retain     bool   `json:"retain"`
}

// Generate JWT Request
type GenerateJWTRequest struct {
	Subject       string   `json:"subject"`
	PublishACL    []string `json:"pub_acl"`
	SubscribeACL  []string `json:"sub_acl"`
	ExpirySeconds int      `json:"expiry_seconds,omitempty"`
}

// Standard VerneMQ webhook responses
type WebhookResponse struct {
	Result interface{} `json:"result"`
}

type WebhookErrorResponse struct {
	Result map[string]string `json:"result"`
}

type WebhookModifiersResponse struct {
	Result    string      `json:"result"`
	Modifiers interface{} `json:"modifiers,omitempty"`
}

// Generate JWT Token endpoint
func generateJWT(c *gin.Context) {
	var req GenerateJWTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Generate JWT - Invalid request format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid request format: %v", err),
		})
		return
	}

	// Validate required fields
	if req.Subject == "" {
		log.Printf("Generate JWT - Missing subject field")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Subject field is required and cannot be empty",
		})
		return
	}

	// Default expiry to 3600 seconds (1 hour) if not specified
	if req.ExpirySeconds == 0 {
		req.ExpirySeconds = 3600
	}

	// Validate expiry range (minimum 10 seconds, maximum 30 days)
	if req.ExpirySeconds < 10 {
		log.Printf("Generate JWT - Expiry too short: %d seconds", req.ExpirySeconds)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Expiry seconds must be at least 10 seconds",
		})
		return
	}
	if req.ExpirySeconds > 2592000 { // 30 days
		log.Printf("Generate JWT - Expiry too long: %d seconds", req.ExpirySeconds)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Expiry seconds cannot exceed 2592000 seconds (30 days)",
		})
		return
	}

	// Log token generation attempt
	log.Printf("Generate JWT - Subject: %s, PubACL: %v, SubACL: %v, Expiry: %d seconds",
		req.Subject, req.PublishACL, req.SubscribeACL, req.ExpirySeconds)

	// Create claims
	claims := CustomClaims{
		Subject: req.Subject,
		PubACL:  req.PublishACL,
		SubACL:  req.SubscribeACL,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(req.ExpirySeconds) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "vmq-webhook-api",
			Subject:   req.Subject,
		},
	}

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(jwtSecretKey)
	if err != nil {
		log.Printf("Generate JWT - Token signing failed for subject %s: %v", req.Subject, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to generate token: %v", err),
		})
		return
	}

	log.Printf("Generate JWT - Successfully generated token for subject: %s, expires at: %v",
		req.Subject, claims.ExpiresAt.Time)

	c.JSON(http.StatusOK, gin.H{
		"jwt":        signedToken,
		"expires_at": claims.ExpiresAt.Time,
		"subject":    req.Subject,
		"issued_at":  claims.IssuedAt.Time,
	})
}

// Validate JWT and extract claims
func validateJWT(tokenString string) (*CustomClaims, error) {
	// Check if token string is empty
	if tokenString == "" {
		return nil, fmt.Errorf("empty token provided")
	}

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v, expected HMAC", token.Header["alg"])
		}
		return jwtSecretKey, nil
	})

	if err != nil {
		// Check for specific error types based on error message
		errMsg := err.Error()
		switch {
		case strings.Contains(errMsg, "token is malformed"):
			return nil, fmt.Errorf("token is malformed or not a valid JWT token")
		case strings.Contains(errMsg, "token has invalid claims: token is expired"):
			return nil, fmt.Errorf("token has expired")
		case strings.Contains(errMsg, "token is not valid yet"):
			return nil, fmt.Errorf("token is not valid yet")
		case strings.Contains(errMsg, "signature is invalid"):
			return nil, fmt.Errorf("token signature is invalid")
		case strings.Contains(errMsg, "token has invalid audience"):
			return nil, fmt.Errorf("token audience is invalid")
		case strings.Contains(errMsg, "token has invalid issuer"):
			return nil, fmt.Errorf("token issuer is invalid")
		case strings.Contains(errMsg, "token has invalid subject"):
			return nil, fmt.Errorf("token subject is invalid")
		case strings.Contains(errMsg, "token used before valid"):
			return nil, fmt.Errorf("token is not valid yet")
		default:
			return nil, fmt.Errorf("token validation failed: %v", err)
		}
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		// Additional validation for custom claims
		if claims.Subject == "" {
			return nil, fmt.Errorf("token subject cannot be empty")
		}
		return claims, nil
	}

	return nil, fmt.Errorf("token claims are invalid or token is not valid")
}

// Check if topic matches any pattern in ACL using wildcard matching
func matchesACL(topic string, acl []string) bool {
	for _, pattern := range acl {
		if matchTopic(topic, pattern) {
			return true
		}
	}
	return false
}

// Simple wildcard matching for MQTT topics
func matchTopic(topic, pattern string) bool {
	// Handle exact match
	if topic == pattern {
		return true
	}

	// Handle + wildcard (single level)
	// Handle # wildcard (multi level)
	topicParts := strings.Split(topic, "/")
	patternParts := strings.Split(pattern, "/")

	return matchTopicParts(topicParts, patternParts)
}

func matchTopicParts(topicParts, patternParts []string) bool {
	i, j := 0, 0

	for i < len(topicParts) && j < len(patternParts) {
		if patternParts[j] == "#" {
			// # matches everything from this point
			return true
		} else if patternParts[j] == "+" {
			// + matches exactly one level
			i++
			j++
		} else if topicParts[i] == patternParts[j] {
			i++
			j++
		} else {
			return false
		}
	}

	// Check if we've consumed all parts
	if i == len(topicParts) && j == len(patternParts) {
		return true
	}

	// Check if pattern ends with # and we've consumed all topic parts
	if i == len(topicParts) && j == len(patternParts)-1 && patternParts[j] == "#" {
		return true
	}

	return false
}

// Auth on Register webhook endpoint
func authOnRegister(c *gin.Context) {
	var req AuthOnRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Auth on register - Invalid request format from %s:%d, client_id: %s, error: %v",
			req.PeerAddr, req.PeerPort, req.ClientID, err)
		c.JSON(http.StatusBadRequest, WebhookErrorResponse{
			Result: map[string]string{"error": fmt.Sprintf("Invalid request format: %v", err)},
		})
		return
	}

	// Log the authentication attempt
	log.Printf("Auth on register attempt - Client ID: %s, Peer: %s:%d, Mountpoint: %s",
		req.ClientID, req.PeerAddr, req.PeerPort, req.Mountpoint)

	// Validate JWT token (username should be the JWT token)
	claims, err := validateJWT(req.Username)
	if err != nil {
		log.Printf("Auth on register failed - Client ID: %s, Peer: %s:%d, JWT Error: %v",
			req.ClientID, req.PeerAddr, req.PeerPort, err)
		c.JSON(http.StatusOK, WebhookErrorResponse{
			Result: map[string]string{"error": fmt.Sprintf("Authentication failed: %v", err)},
		})
		return
	}

	log.Printf("Auth on register successful - Client ID: %s authenticated as subject: %s, Peer: %s:%d",
		req.ClientID, claims.Subject, req.PeerAddr, req.PeerPort)

	c.JSON(http.StatusOK, WebhookResponse{
		Result: "ok",
	})
}

// Auth on Subscribe webhook endpoint
func authOnSubscribe(c *gin.Context) {
	var req AuthOnSubscribeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Auth on subscribe - Invalid request format from client_id: %s, error: %v",
			req.ClientID, err)
		c.JSON(http.StatusBadRequest, WebhookErrorResponse{
			Result: map[string]string{"error": fmt.Sprintf("Invalid request format: %v", err)},
		})
		return
	}

	// Log the subscription attempt
	log.Printf("Auth on subscribe attempt - Client ID: %s, Mountpoint: %s, Topics count: %d",
		req.ClientID, req.Mountpoint, len(req.Topics))

	// Validate JWT token
	claims, err := validateJWT(req.Username)
	if err != nil {
		log.Printf("Auth on subscribe failed - Client ID: %s, JWT Error: %v", req.ClientID, err)
		c.JSON(http.StatusOK, WebhookErrorResponse{
			Result: map[string]string{"error": fmt.Sprintf("Authentication failed: %v", err)},
		})
		return
	}

	// Log available ACLs for debugging
	log.Printf("Auth on subscribe - Subject: %s, Subscribe ACL: %v", claims.Subject, claims.SubACL)

	// Check if subscribe ACL is empty
	if len(claims.SubACL) == 0 {
		log.Printf("Subscribe denied: no subscribe ACL defined for subject %s", claims.Subject)
		c.JSON(http.StatusOK, WebhookErrorResponse{
			Result: map[string]string{"error": fmt.Sprintf("Subscription not allowed: no subscribe ACL defined for subject %s", claims.Subject)},
		})
		return
	}

	// Check subscription permissions - reject if any topic doesn't match ACL
	var allowedTopics []AuthOnSubscribeTopic
	var deniedTopics []string
	for _, topic := range req.Topics {
		if matchesACL(topic.Topic, claims.SubACL) {
			allowedTopics = append(allowedTopics, topic)
			log.Printf("Subscribe allowed: %s (QoS %d) for subject %s", topic.Topic, topic.QOS, claims.Subject)
		} else {
			deniedTopics = append(deniedTopics, topic.Topic)
			log.Printf("Subscribe denied: %s for subject %s (topic not in ACL: %v)", topic.Topic, claims.Subject, claims.SubACL)
		}
	}

	// If any topics were denied, return error
	if len(deniedTopics) > 0 {
		log.Printf("Auth on subscribe result - Subject: %s, Total topics: %d, Denied: %d, Allowed: %d",
			claims.Subject, len(req.Topics), len(deniedTopics), len(allowedTopics))
		c.JSON(http.StatusOK, WebhookErrorResponse{
			Result: map[string]string{"error": fmt.Sprintf("Subscription not allowed: topics %v not permitted for subject '%s'", deniedTopics, claims.Subject)},
		})
		return
	}

	// All topics are allowed
	log.Printf("Auth on subscribe result - Subject: %s, All %d topics allowed",
		claims.Subject, len(req.Topics))

	c.JSON(http.StatusOK, WebhookModifiersResponse{
		Result: "ok",
		Modifiers: map[string]interface{}{
			"topics": allowedTopics,
		},
	})
}

// Auth on Publish webhook endpoint
func authOnPublish(c *gin.Context) {
	var req AuthOnPublishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Auth on publish - Invalid request format from client_id: %s, error: %v",
			req.ClientID, err)
		c.JSON(http.StatusBadRequest, WebhookErrorResponse{
			Result: map[string]string{"error": fmt.Sprintf("Invalid request format: %v", err)},
		})
		return
	}

	// Log the publish attempt
	log.Printf("Auth on publish attempt - Client ID: %s, Topic: %s, QoS: %d, Retain: %t, Payload length: %d",
		req.ClientID, req.Topic, req.QOS, req.Retain, len(req.Payload))

	// Validate JWT token
	claims, err := validateJWT(req.Username)
	if err != nil {
		log.Printf("Auth on publish failed - Client ID: %s, Topic: %s, JWT Error: %v",
			req.ClientID, req.Topic, err)
		c.JSON(http.StatusOK, WebhookErrorResponse{
			Result: map[string]string{"error": fmt.Sprintf("Authentication failed: %v", err)},
		})
		return
	}

	// Log available ACLs for debugging
	log.Printf("Auth on publish - Subject: %s, Publish ACL: %v", claims.Subject, claims.PubACL)

	// Check publish permissions
	if len(claims.PubACL) == 0 {
		log.Printf("Publish denied: %s for subject %s (no publish ACL defined)", req.Topic, claims.Subject)
		c.JSON(http.StatusOK, WebhookErrorResponse{
			Result: map[string]string{"error": fmt.Sprintf("Publishing not allowed: no publish ACL defined for subject %s", claims.Subject)},
		})
	} else if matchesACL(req.Topic, claims.PubACL) {
		log.Printf("Publish allowed: %s (QoS %d) for subject %s", req.Topic, req.QOS, claims.Subject)
		c.JSON(http.StatusOK, WebhookResponse{
			Result: "ok",
		})
	} else {
		log.Printf("Publish denied: %s for subject %s (topic not in ACL: %v)", req.Topic, claims.Subject, claims.PubACL)
		c.JSON(http.StatusOK, WebhookErrorResponse{
			Result: map[string]string{"error": fmt.Sprintf("Publishing not allowed: topic '%s' not permitted for subject '%s')", req.Topic, claims.Subject)},
		})
	}
}

func main() {
	// Set Gin to release mode in production
	// gin.SetMode(gin.ReleaseMode)

	r := gin.Default()

	// Add logging middleware
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// CORS middleware for development
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// API endpoints
	api := r.Group("/api/v1")
	{
		// Endpoint 1: Generate JWT token
		api.POST("/generate-token", generateJWT)

		// Endpoint 2: VerneMQ auth_on_register webhook
		api.POST("/auth/register", authOnRegister)

		// Endpoint 3: VerneMQ auth_on_subscribe webhook
		api.POST("/auth/subscribe", authOnSubscribe)

		// Endpoint 4: VerneMQ auth_on_publish webhook
		api.POST("/auth/publish", authOnPublish)
	}

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now(),
		})
	})

	// Start server
	port := ":8181"
	log.Printf("Starting VerneMQ Webhook API server on port %s", port)
	log.Fatal(r.Run(port))
}
