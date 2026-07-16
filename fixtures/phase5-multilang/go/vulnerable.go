package phase5

import (
    "net/http"
    "os"
    "os/exec"
    "github.com/gin-gonic/gin"
)

func routes(router *gin.Engine) {
    router.GET("/run", runCommand)
}

func runCommand(context *gin.Context) {
    input := context.Query("command")
    exec.Command("sh", "-c", input).Run()
    db.Query(input)
    os.ReadFile(input)
    http.Get(input)
    http.Redirect(context.Writer, context.Request, input, http.StatusFound)
}
