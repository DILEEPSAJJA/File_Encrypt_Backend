package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/DILEEPSAJJA/File_Encrypt/filecrypt"
	"github.com/gin-gonic/gin"
)

func ginadapter(f func(*gin.Context)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := gin.CreateTestContext(w)
		c.Request = r
		f(c)
	})
}

var Handler = ginadapter(func(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if c.Request.Method == http.MethodOptions {
		c.AbortWithStatus(204)
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, "File is required")
		return
	}

	password := c.PostForm("password")
	if len(password) < 4 {
		c.String(http.StatusBadRequest, "Password must be at least 4 characters")
		return
	}

	tempPath := filepath.Join(os.TempDir(), file.Filename)
	if err := c.SaveUploadedFile(file, tempPath); err != nil {
		c.String(http.StatusInternalServerError, "Failed to save uploaded file")
		return
	}
	defer os.Remove(tempPath)

	encPath, err := filecrypt.EncryptFile(tempPath, []byte(password))
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("Encryption failed: %v", err))
		return
	}
	defer os.Remove(encPath)

	c.FileAttachment(encPath, file.Filename+".enc")
})
