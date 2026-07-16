package phase5

import (
    "os/exec"
    "github.com/gin-gonic/gin"
)

func safeRoutes(router *gin.Engine) {
    router.POST("/safe", safeCommand)
}

func safeCommand(context *gin.Context) {
    if !authorized(context) {
        return
    }
    input := context.Query("tool")
    safe := allowlist(input)
    exec.Command("tool", safe).Run()
}
