import {cert, xsd} from "@welib/solid-protocol";
import {Graph} from "@welib/rdf";
import {exportRSAPublicKey, subjectAltNames} from "./x509.js";

// IRIs needed to navigate WebID profile graph
const key = `${cert}key`;
const RSAPublicKey = `${cert}RSAPublicKey`;
const exponent = `${cert}exponent`;
const modulus = `${cert}modulus`;
const integer = `${xsd}integer`;
const hexBinary = `${xsd}hexBinary`;

/**
 * Verify certificate public key matches a WebID and return the verified WebID.
 * The certificate must have exactly one SAN URI entry which resolves to a
 * WebID profile document, and the profile must present an RSAPublicKey with a
 * matching exponent and modulus.
 *
 * @param {X509Certificate} cert
 * @returns {string}
 */
export default async function verify(cert) {
  const uris = subjectAltNames(cert, "URI").map(n => n.slice("URI:".length));

  if (uris.length !== 1) {
    return false;
  } else if (cert.publicKey.asymmetricKeyType !== "rsa") {
    return false;
  }

  const webid = uris[0];
  const graph = await Graph.fetch(webid);
  const keys = graph.findObjects(webid, key);
  const isRSAPublicKey = graph.typeFilter(RSAPublicKey);
  const publicKey = exportRSAPublicKey(cert);

  for (const subject of keys.filter(isRSAPublicKey)) {
    const exp = graph.readLiteral(subject, exponent, integer);
    const mod = BigInt("0x" + graph.readLiteral(subject, modulus, hexBinary));

    if (exp != publicKey.exponent) return false;
    if (mod != publicKey.modulus) return false;
  }

  return webid;
}
