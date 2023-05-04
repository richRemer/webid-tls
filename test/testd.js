import http from "http";
import https from "https";
import {dirname, join} from "path";
import {readFileSync} from "fs";
import {fileURLToPath} from "url";
import {X509Certificate} from "crypto";
import express from "express";
import morgan from "morgan";
import {verify} from "../webid-tls.js";

const app = express();
const dir = dirname(fileURLToPath(import.meta.url));
const tls = getTLSOptions(dir);
const authServer = https.createServer(tls, app);
const identServer = http.createServer(sendProfile);

app.use(morgan("tiny"));

app.get("/", (req, res) => {
  const cert = req.connection.getPeerCertificate();
  console.log(cert);
  res.sendStatus(200);
});

app.get("/login", async (req, res) => {
  const certInfo = req.connection.getPeerCertificate();
  const cert = new X509Certificate(certInfo.raw);
  const webid = await verify(cert);
  res.send(`logged in as ${webid}`);
});

identServer.listen(80, () => {
  authServer.listen(443, () => {
    console.log("waiting for connections");
  });
});

function getTLSOptions(dir) {
  const cert = readFileSync(join(dir, "config/server.crt"));
  const key = readFileSync(join(dir, "config/server.key"));
  const ca = readFileSync(join(dir, "config/ca.crt"));
  const requestCert = true;
  const rejectUnauthorized = false;

  return {cert, key, ca, requestCert, rejectUnauthorized};
}

function sendProfile(req, res) {
  const profile = readFileSync(join(dir, "config/profile.ttl"));
  res.setHeader("Content-Type", "text/turtle");
  res.end(profile);
}