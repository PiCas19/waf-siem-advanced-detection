package api

import "github.com/gin-gonic/gin"

func GetRules(c *gin.Context) {
	c.JSON(200, gin.H{"rules": []map[string]string{}})
}

func CreateRule(c *gin.Context) {
	c.JSON(201, gin.H{"message": "Rule created"})
}