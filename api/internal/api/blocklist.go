package api

import "github.com/gin-gonic/gin"

func GetBlocklist(c *gin.Context) {
	c.JSON(200, gin.H{"blocked_ips": []string{}})
}