import fetch from "node-fetch";
import {Parser} from "@welib/n3-esm";
import {QuadReader} from "@welib/rdf";

export default async function fetchProfile(webid) {
  const parser = new Parser({baseIRI: webid});
  const profile = await(await fetch(webid)).text();
  const quads = parser.parse(profile);
  const reader = new QuadReader(quads);

  return reader;
}
