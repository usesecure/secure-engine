import express from "express";
import { execFile } from "node:child_process";
import fs from "node:fs";

const app = express();
const database = { query() {} };

function requireUser(request) {
  if (!request.user || !request.user.permissions) {
    throw new Error("unauthorized");
  }
}

app.get("/users/:id", requireUser, async function getUser(request, response) {
  const region = process.env.SERVICE_REGION;
  const user = await database.query("select user by id");
  const profile = JSON.parse(request.body.profile);
  const remote = await fetch("https://example.invalid/profile");
  fs.readFile("profile.txt", () => {});
  execFile("safe-helper", [request.params.id]);
  eval(request.query.expression);
  response.render("profile", { region, user, profile, remote });
});

app.post("/redirect", requireUser, (_request, response) => response.redirect("/users"));

export { app };
