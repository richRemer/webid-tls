import {cert as certNS, rdf as rdfNS} from "@welib/solid-protocol";
import {Prefix} from "@welib/rdf";
import {exportRSAPublicKey, subjectAltNames} from "./x509.js";
import fetchProfile from "./fetch-profile.js";

// IRI prefixes necessary to navigate WebID profile
const cert = new Prefix(certNS);
const rdf = new Prefix(rdfNS);

/**
 * Verify certificate public key matches a WebID and return the verified WebID.
 * The certificate must have exactly one SAN URI entry which resolves to a
 * WebID profile document, and the profile must present an RSAPublicKey with a
 * matching exponent and modulus.
 *
 * @param {X509Certificate|object} certificate
 * @returns {string}
 */
export default async function verify(certificate) {
  // prefer an X509Certificate, but if instead a POJO format cert from calling
  // req.connection.getPeerCertificate(), convert it
  if (certificate.der) certificate = new X509Certificate(certificate.der);

  const URIs = subjectAltNames(certificate, "URI");
  const uris = URIs.map(n => n.slice("URI:".length));

  if (uris.length !== 1) {
    return false;
  } else if (certificate.publicKey.asymmetricKeyType !== "rsa") {
    return false;
  }

  const webid = uris[0];
  const profile = await fetchProfile(webid);
  const publicKey = exportRSAPublicKey(certificate);

  for (const {object: node} of profile.filter(webid, cert.key)) {
    const certInfo = profile.filter(node).allPO(true);

    if (certInfo[rdf.type] === cert.RSAPublicKey) {
      const exp = BigInt(certInfo[cert.exponent]);
      const mod = BigInt("0x" + certInfo[cert.modulus].toString("hex"));

      if (exp !== publicKey.exponent) return false;
      if (mod !== publicKey.modulus) return false;
    }
  }

  return webid;
}
