import { exec } from "child_process";
import fs from "fs";
import express from "express";
import { redirect } from "next/navigation";

declare const db: { raw(query: string): unknown };
const app = express();

function commandHandler(req: any, res: any) {
  const command = req.query.command;
  exec(command);
  res.end();
}

function sqlHandler(req: any, res: any) {
  const fragment = req.body.filter;
  const query = `SELECT * FROM users WHERE ${fragment}`;
  db.raw(query);
  res.end();
}

function readUntrusted(path: string) {
  return fs.readFile(path, () => undefined);
}

function fileHandler(req: any, res: any) {
  const requested = req.params.path;
  readUntrusted(requested);
  res.end();
}

function networkHandler(req: any, res: any) {
  const target = req.query.url;
  fetch(target);
  res.end();
}

function redirectHandler(req: any) {
  const destination = req.query.next;
  redirect(destination);
}

function dynamicHandler(req: any, res: any) {
  const expression = req.body.expression;
  eval(expression);
  res.end();
}

function unguardedHandler(_req: any, res: any) {
  fs.readFile("/etc/passwd", () => undefined);
  res.end();
}

app.get("/command", commandHandler);
app.post("/sql", sqlHandler);
app.get("/files/:path", fileHandler);
app.get("/fetch", networkHandler);
app.get("/leave", redirectHandler);
app.post("/dynamic", dynamicHandler);
app.get("/admin", unguardedHandler);
