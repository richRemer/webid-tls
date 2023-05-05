import http from "http";
import {X509Certificate} from "crypto";
import forge from "node-forge";

export function HttpServer() {
  return http.createServer().listen();
}

export function WebID(httpServer) {
  return `http://localhost:${httpServer.address().port}/me#id`;
}

export function PEMCert(...alts) {
  const {pki, rsa} = forge;
  const keys = rsa.generateKeyPair();
  const cert = pki.createCertificate();
  const attrs = [];
  const exts = [];

  if (alts.length) {
    alts = alts.map(alt => {
      const [name, ...rest] = alt.split(":");
      const type = altType(name);
      const value = rest.join(":");
      return {type, value};
    });

    exts.push({name: "subjectAltName", altNames: alts});
  }

  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 100000);
  cert.publicKey = keys.publicKey;
  cert.setExtensions(exts);
  cert.sign(keys.privateKey);

  return pki.certificateToPem(cert);
}

export function X509Cert(...alts) {
  return new X509Certificate(PEMCert(...alts));
}

export function Profile(webid, exp, mod) {
  exp = Number(exp);
  mod = mod.toString(16);

  return `
    @prefix cert: <http://www.w3.org/ns/auth/cert#>.
    @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
    <${webid}> cert:key [
      a cert:RSAPublicKey;
      cert:exponent ${exp};
      cert:modulus "${mod}"^^xsd:hexBinary].
  `;
}

export function Listener(profile) {
  return function listener(req, res) {
    res.setHeader("Content-Type", "text/turtle");
    res.end(profile);
  }
}

function altType(type) {
  switch (type) {
    case "DNS": return 2;
    case "URI": return 6;
    case "IP": return 7;
  }
}
