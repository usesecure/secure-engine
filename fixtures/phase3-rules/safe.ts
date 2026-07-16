import { execFile } from "child_process";
import fs from "fs";
import express from "express";

declare const db: { query(text: string, values: unknown[]): unknown };
declare function requireAuthorization(): void;
declare function sanitizeCommand(value: unknown): string;
declare function normalizeSafePath(value: unknown): string;
declare function safeUrl(value: unknown): string;
const app = express();

function safeCommand(req: any, res: any) {
  requireAuthorization();
  const command = sanitizeCommand(req.query.command);
  execFile("/usr/bin/printf", [command]);
  res.end();
}

function safeSql(req: any, res: any) {
  requireAuthorization();
  db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
  res.end();
}

function safeFile(req: any, res: any) {
  requireAuthorization();
  const path = normalizeSafePath(req.params.path);
  fs.readFile(path, () => undefined);
  res.end();
}

function safeNetwork(req: any, res: any) {
  requireAuthorization();
  const target = safeUrl(req.query.url);
  fetch(target);
  res.end();
}

function guardedAdmin(_req: any, res: any) {
  requireAuthorization();
  fs.readFile("/srv/app/status.txt", () => undefined);
  res.end();
}

app.get("/safe-command", safeCommand);
app.get("/safe-sql", safeSql);
app.get("/safe-file", safeFile);
app.get("/safe-network", safeNetwork);
app.get("/guarded", guardedAdmin);
