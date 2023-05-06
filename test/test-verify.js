import expect from "expect.js";
import {X509Certificate} from "crypto";
import {exportRSAPublicKey} from "../src/x509.js";
import verify from "../src/verify.js";
import {
  HttpServer, WebID, PEMCert, X509Cert, Profile, Listener
} from "./lib/mock.js";

describe("verify(X509Certificate)", () => {
  let httpServer;
  let webid;

  beforeEach(() => {
    httpServer = HttpServer();
    webid = WebID(httpServer);
  });

  afterEach(() => {
    httpServer.close();
  });

  it("should return WebID from certificate", async () => {
    const cert = setupTest(httpServer, webid, [`URI:${webid}`]);
    expect(await verify(cert)).to.be(webid);
  });

  it("should return first matching WebID", async () => {
    const id = new URL("foo#id", webid).toString();
    const cert = setupTest(httpServer, webid, [`URI:${id}`, `URI:${webid}`]);
    expect(await verify(cert)).to.be(webid);
  });

  it("should work with getPeerCertificate PEM-encoded cert", async () => {
    const raw = PEMCert(`URI:${webid}`);
    const cert = new X509Certificate(raw);
    const {exponent, modulus} = exportRSAPublicKey(cert);
    const profile = Profile(webid, exponent, modulus);

    httpServer.on("request", Listener(profile));

    expect(await verify({raw})).to.be(webid);
  });

  it("should filter profile for WebID subject", async () => {
    const id = new URL("foo#id", webid).toString();
    const cert = setupTest(httpServer, id, [`URI:${webid}`]);
    expect(await verify(cert)).to.be(false);
  });

  it("should filter SAN for URI name", async () => {
    const cert = setupTest(httpServer, webid, [`DNS:${webid}`]);
    expect(await verify(cert)).to.be(false);
  });

  it("should filter cert:key for exponent", async () => {
    const exp = BigInt(23);
    const cert = setupTest(httpServer, webid, [`URI:${webid}`], {exp});
    expect(await verify(cert)).to.be(false);
  });

  it("should filter cert:key for modulus", async () => {
    const mod = BigInt(42232112);
    const cert = setupTest(httpServer, webid, [`URI:${webid}`], {mod});
    expect(await verify(cert)).to.be(false);
  });
});

function setupTest(httpServer, webid, alts, {exp, mod}={}) {
  const cert = X509Cert(...alts);
  const {exponent, modulus} = exportRSAPublicKey(cert);
  const profile = Profile(webid, exp ?? exponent, mod ?? modulus);

  httpServer.on("request", Listener(profile));

  return cert;
}
