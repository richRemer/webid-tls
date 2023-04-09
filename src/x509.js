/**
 * Extract subject alternative names from X509 certificate, with optional
 * filter on which types of names to return (e.g. "DNS" or "URI").
 *
 * @param {X509Certificate} cert
 * @param {string} [type]
 * @returns {string[]}
 */
export function subjectAltNames(cert, type=undefined) {
  const {subjectAltName} = cert;
  const names = subjectAltName.split(",").map(s => s.trim());
  const prefix = type ? `${type}:` : "";

  return names.filter(n => n.startsWith(prefix));
}

/**
 * Export public key details of an RSA X509Certificate.
 * @param {X509Certificate} cert
 * @returns {object}
 */
export function exportRSAPublicKey(cert) {
  if (cert.publicKey.asymmetricKeyType !== "rsa") {
    throw new TypeError("certificate does not have an RSA public key");
  }

  const type = "spki";
  const format = "jwk";
  const {n: mod, e: exp} = cert.publicKey.export({type, format});
  const modulus = BigInt("0x" + Buffer.from(mod, "base64").toString("hex"));
  const exponent = BigInt("0x" + Buffer.from(exp, "base64").toString("hex"));

  return {modulus, exponent};
}
