import {X509Certificate} from "crypto";
import {cert as certNS, rdf as rdfNS} from "@welib/solid-protocol";
import {Prefix} from "@welib/rdf";
import {exportRSAPublicKey, subjectAltNames} from "./x509.js";
import fetchProfile from "./fetch-profile.js";

// IRI prefixes necessary to navigate WebID profile
const cert = new Prefix(certNS);
const rdf = new Prefix(rdfNS);

/**
 * Verify certificate public key matches a WebID and return the verified WebID.
 * The certificate must have at least one SAN URI entry which resolves to a
 * WebID profile document presenting an RSAPublicKey with a matching exponent
 * and modulus.
 *
 * @param {X509Certificate|object} certificate
 * @returns {string}
 */
export default async function verify(certificate) {
  if (certificate.raw) {
    certificate = new X509Certificate(certificate.raw);
  }

  if (certificate.publicKey?.asymmetricKeyType !== "rsa") {
    return false;
  }

  const {exponent, modulus} = exportRSAPublicKey(certificate);
  const URIs = subjectAltNames(certificate, "URI");
  const uris = URIs.map(n => n.slice("URI:".length));

  for (const webid of uris) {
    try {
      const profile = await fetchProfile(webid);

      for (const {object: node} of profile.filter(webid, cert.key)) {
        const certInfo = profile.filter(node).allPO(true);

        if (certInfo[rdf.type] === cert.RSAPublicKey) {
          const exp = BigInt(certInfo[cert.exponent]);
          const mod = BigInt("0x" + certInfo[cert.modulus].toString("hex"));

          if (exp === exponent && mod === modulus) {
            return webid;
          }
        }
      }
    } catch (err) {
      // ignore error and move on to the next URI
    }
  }

  return false;
}
