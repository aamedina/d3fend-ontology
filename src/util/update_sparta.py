from stix2 import MemoryStore, Filter
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, RDFS, OWL

import sys


def get_sparta_graph(sparta_path):
    D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")

    src = MemoryStore()
    src.load_from_file(sparta_path)

    techniques = src.query(
        [
            Filter("type", "=", "attack-pattern"),
            Filter("external_references.source_name", "=", "sparta"),
        ]
    )

    # Create a new graph
    g = Graph()

    # Add SPARTA Techniques to the graph
    for tech in techniques:
        sparta_id = next(
            (
                ref.get("external_id")
                for ref in tech["external_references"]
                if ref.get("source_name") == "sparta"
            ),
            None,
        )
        # If the technique has a SPARTA ID, add it to the graph
        if sparta_id is not None:
            # Create a URI for the SPARTA Technique
            sparta_uri = D3F[f"SPARTA-{sparta_id}"]
            g.add((sparta_uri, RDF.type, D3F.SPARTATechnique))
            g.add((sparta_uri, RDF.type, OWL.Class))
            g.add((sparta_uri, RDF.type, OWL.NamedIndividual))
            g.add((sparta_uri, RDFS.label, Literal(tech["name"].strip() + " - SPARTA")))
            sparta_url = next(
                (
                    ref.get("url")
                    for ref in tech["external_references"]
                    if ref.get("source_name") == "sparta"
                ),
                None,
            )
            g.add((sparta_uri, RDFS.seeAlso, URIRef(sparta_url)))
            g.add((sparta_uri, D3F.definition, Literal(tech["description"])))
            g.add((sparta_uri, D3F["sparta-id"], Literal(sparta_id)))
            # NOTE: as of v1.6, SPARTA STIX data has "x_sparta_is_subtechnique" set to False for everything, so this is a workaround
            # If the SPARTA ID has a period, it is a sub-technique
            if "." in sparta_id:
                g.add(
                    (
                        sparta_uri,
                        RDFS.subClassOf,
                        D3F[f"SPARTA-{sparta_id.split('.')[0]}"],
                    )
                )
            else:
                # Interpret the kill chain phase name as the parent technique classified by tactic
                for obj in tech.get("kill_chain_phases", []):
                    name = str("SPARTA" + obj["phase_name"] + " Technique").replace(
                        " ", ""
                    )
                    g.add((sparta_uri, RDFS.subClassOf, D3F[name]))

    return g


def main(SPARTA_VERSION="1.6"):

    d3fend_graph = Graph()
    d3fend_graph.parse("src/ontology/d3fend-protege.sparta.ttl")

    sparta_graph = get_sparta_graph(f"data/sparta_data_v{SPARTA_VERSION}.json")

    d3fend_graph += sparta_graph

    d3fend_graph.serialize(
        destination="src/ontology/d3fend-protege.sparta.ttl", format="turtle"
    )


if __name__ == "__main__":
    version = sys.argv[1]
    main(SPARTA_VERSION=version)
