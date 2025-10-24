package api

import "github.com/gin-gonic/gin"

func GetLogs(c *gin.Context) {
	c.JSON(200, gin.H{"logs": []map[string]string{}})
}